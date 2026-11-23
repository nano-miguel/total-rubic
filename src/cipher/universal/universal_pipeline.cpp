/* cipher/universal/universal_pipeline.cpp
Orquestador del pipeline AES-256-GCM.
Responsabilidades:
  - I/O con reintentos (write/read_full_with_retry)
  - Validacion de cabecera
  - Cifrado/descifrado con I/O tradicional
  - Enrutamiento (mmap vs tradicional) y reintentos
  - Workers y ciclo de vida
NO contiene la implementacion de mmap. Eso vive en universal_mmap.cpp.
El RateLimiter vive en universal_rate_limit.cpp. */
#include "../universal_cipher.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

/* ============================================
   I/O con reintentos
   ============================================ */

bool AES256GCM::write_full_with_retry(
    int fd, const void* data, size_t size, int max_retries) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    int retries = 0;

    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written <= 0) {
            if (written == -1 && (errno == EINTR || errno == EAGAIN)) {
                if (retries++ < max_retries) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
            }
            return false;
        }
        ptr += written;
        remaining -= written;
        retries = 0;
    }
    return true;
}

bool AES256GCM::read_full_with_retry(
    int fd, void* data, size_t size, int max_retries) {
    uint8_t* ptr = static_cast<uint8_t*>(data);
    size_t remaining = size;
    int retries = 0;

    while (remaining > 0) {
        ssize_t read_bytes = read(fd, ptr, remaining);
        if (read_bytes <= 0) {
            if (read_bytes == -1 && (errno == EINTR || errno == EAGAIN)) {
                if (retries++ < max_retries) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
            }
            return false;
        }
        ptr += read_bytes;
        remaining -= read_bytes;
        retries = 0;
    }
    return true;
}

/* ============================================
   Validacion de cabecera
   ============================================ */

/* Solo acepta los dos valores exactos de flags que este
formato define: 0x01 solo GCM, 0x03 GCM mas MAC. */
bool AES256GCM::validate_header_integrity(
    const uint8_t* data, size_t size) {
    if (size < config.nonce_size + 1 + 8)
        return false;
    uint8_t flags = data[config.nonce_size];
    return (flags == 0x01 || flags == 0x03);
}

/* ============================================
   Construccion de cabecera (copia local)
   Duplicada en universal_mmap.cpp como static.
   Linkage interno, sin conflicto en el linker. */
/* ============================================ */

static Botan::secure_vector<uint8_t> buildHeaderData(
    const Botan::secure_vector<uint8_t>& nonce,
    uint8_t flags,
    uint64_t original_size) {
    Botan::secure_vector<uint8_t> header;
    header.insert(header.end(), nonce.begin(), nonce.end());
    header.push_back(flags);
    uint8_t size_bytes[8];
    std::memcpy(size_bytes, &original_size, 8);
    header.insert(header.end(), size_bytes, size_bytes + 8);
    return header;
}

/* ============================================
   Cifrado con I/O tradicional
   ============================================ */

bool AES256GCM::encrypt_with_traditional_io(
    const std::string& inputPath, const std::string& outputPath) {

    FileRAII in_file(inputPath, O_RDONLY);
    if (!in_file.valid()) return false;

    struct stat st;
    if (fstat(in_file.get(), &st) != 0) return false;
    size_t file_size = st.st_size;

    FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!out_file.valid()) return false;

    Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
    SecureRandom::generate_bytes(file_nonce.data(), file_nonce.size());

    if (!write_full_with_retry(out_file.get(), file_nonce.data(), file_nonce.size()))
        return false;

    uint8_t flags = 0x01 | (config.use_header_mac ? 0x02 : 0);
    if (!write_full_with_retry(out_file.get(), &flags, 1))
        return false;

    uint64_t original_size = file_size;
    if (!write_full_with_retry(out_file.get(), &original_size, 8))
        return false;

    auto header_data = buildHeaderData(file_nonce, flags, original_size);

    if (config.use_header_mac) {
        auto mac = header_mac.calculate(header_data.data(), header_data.size());
        if (!write_full_with_retry(out_file.get(), mac.data(), mac.size()))
            return false;
    }

    auto cipher = Botan::AEAD_Mode::create_or_throw(
        "AES-256/GCM", Botan::Cipher_Dir::Encryption);
    cipher->set_key(key);
    cipher->set_associated_data(header_data.data(), header_data.size());
    cipher->start(file_nonce);

    size_t buffer_size = config.optimal_buffer_size;
    std::vector<uint8_t> buffer(buffer_size);
    size_t total_read = 0;

    if (file_size == 0) {
        Botan::secure_vector<uint8_t> empty_buf;
        cipher->finish(empty_buf);
        if (!write_full_with_retry(out_file.get(), empty_buf.data(), empty_buf.size()))
            return false;
    } else {
        while (total_read < file_size) {
            size_t to_read = std::min(buffer_size, file_size - total_read);
            if (!read_full_with_retry(in_file.get(), buffer.data(), to_read))
                return false;

            Botan::secure_vector<uint8_t> secure_buf(
                buffer.data(), buffer.data() + to_read);

            if (total_read + to_read >= file_size) cipher->finish(secure_buf);
            else cipher->update(secure_buf);

            if (!write_full_with_retry(out_file.get(), secure_buf.data(), secure_buf.size()))
                return false;

            total_read += to_read;
            rate_limiter->wait_if_needed(to_read);
        }
    }

    total_files_processed++;
    total_bytes_processed += file_size;
    return true;
}

/* ============================================
   Descifrado con I/O tradicional
   ============================================ */

bool AES256GCM::decrypt_with_traditional_io(
    const std::string& inputPath, const std::string& outputPath) {

    FileRAII in_file(inputPath, O_RDONLY);
    if (!in_file.valid()) return false;

    struct stat st;
    if (fstat(in_file.get(), &st) != 0) return false;
    off_t file_end = st.st_size;

    FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!out_file.valid()) return false;

    Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
    if (!read_full_with_retry(in_file.get(), file_nonce.data(), file_nonce.size()))
        return false;

    uint8_t flags;
    if (!read_full_with_retry(in_file.get(), &flags, 1))
        return false;
    bool has_mac = (flags & 0x02) != 0;

    uint64_t original_size;
    if (!read_full_with_retry(in_file.get(), &original_size, 8))
        return false;

    auto header_data = buildHeaderData(file_nonce, flags, original_size);

    if (has_mac) {
        Botan::secure_vector<uint8_t> file_mac(32);
        if (!read_full_with_retry(in_file.get(), file_mac.data(), 32))
            return false;
        if (!header_mac.verify(header_data.data(), header_data.size(),
                               file_mac.data(), file_mac.size()))
            return false;
    }

    auto cipher = Botan::AEAD_Mode::create_or_throw(
        "AES-256/GCM", Botan::Cipher_Dir::Decryption);
    cipher->set_key(key);
    cipher->set_associated_data(header_data.data(), header_data.size());
    cipher->start(file_nonce);

    off_t current_pos = lseek(in_file.get(), 0, SEEK_CUR);
    if (current_pos < 0 || (size_t)(file_end - current_pos) < SystemConfig::GCM_TAG_SIZE)
        return false;

    size_t ciphertext_size = file_end - current_pos - SystemConfig::GCM_TAG_SIZE;
    size_t buffer_size = config.optimal_buffer_size;
    std::vector<uint8_t> buffer(buffer_size);
    size_t total_read = 0;

    if (ciphertext_size == 0) {
        Botan::secure_vector<uint8_t> tag(SystemConfig::GCM_TAG_SIZE);
        if (!read_full_with_retry(in_file.get(), tag.data(), tag.size()))
            return false;
        cipher->finish(tag);
    } else {
        while (total_read < ciphertext_size) {
            size_t to_read = std::min(buffer_size, ciphertext_size - total_read);
            if (!read_full_with_retry(in_file.get(), buffer.data(), to_read))
                return false;

            Botan::secure_vector<uint8_t> secure_buf(
                buffer.data(), buffer.data() + to_read);

            if (total_read + to_read >= ciphertext_size) {
                Botan::secure_vector<uint8_t> tag(SystemConfig::GCM_TAG_SIZE);
                if (!read_full_with_retry(in_file.get(), tag.data(), tag.size()))
                    return false;
                secure_buf.insert(secure_buf.end(), tag.begin(), tag.end());
                cipher->finish(secure_buf);
            } else {
                cipher->update(secure_buf);
            }

            if (!write_full_with_retry(out_file.get(), secure_buf.data(), secure_buf.size()))
                return false;

            total_read += to_read;
            rate_limiter->wait_if_needed(to_read);
        }
    }

    total_files_processed++;
    total_bytes_processed += original_size;
    return true;
}

/* ============================================
   Enrutamiento tradicional
   ============================================ */

bool AES256GCM::process_with_traditional_io(
    const std::string& inputPath,
    const std::string& outputPath,
    bool encryptMode) {
    if (encryptMode)
        return encrypt_with_traditional_io(inputPath, outputPath);
    return decrypt_with_traditional_io(inputPath, outputPath);
}

/* ============================================
   Reintentos (bifurca mmap vs tradicional)
   mmap se implementa en universal_mmap.cpp.
   ============================================ */

bool AES256GCM::process_single_file_with_retry(
    const std::string& inputPath,
    const std::string& outputPath,
    bool encryptMode) {

    int retries = 0;
    bool success = false;

    while (retries <= static_cast<int>(config.max_retries) && !success) {
        if (retries > 0) {
            total_retries++;
            std::this_thread::sleep_for(
                std::chrono::milliseconds(config.retry_delay_ms));
            std::remove(outputPath.c_str());
        }
        try {
            struct stat st;
            if (stat(inputPath.c_str(), &st) != 0)
                return false;

            rate_limiter->wait_if_needed();

            if (config.should_use_mmap(st.st_size))
                success = process_with_mmap_wrapper(inputPath, outputPath, encryptMode);
            else
                success = process_with_traditional_io(inputPath, outputPath, encryptMode);
        } catch (const std::exception&) {
            success = false;
        }
        retries++;
    }

    if (!success) total_errors++;
    return success;
}

/* ============================================
   Workers
   ============================================ */

void AES256GCM::file_worker_function() {
    while (workers_running.load()) {
        FileWork work;
        if (!work_queue.pop(work)) break;

        bool result = false;
        try {
            result = process_single_file_with_retry(
                work.input_path, work.output_path, work.is_encrypt);
        } catch (...) {
            result = false;
        }
        try {
            work.result_promise.set_value(result);
        } catch (const std::future_error&) {
            /* Ya resuelta por el destructor al drenar */
        }
    }
}

/* ============================================
   Ciclo de vida
   ============================================ */

AES256GCM::AES256GCM(
    const uint8_t* key_data, size_t key_len,
    size_t num_threads, size_t queue_sz,
    const SystemConfig& cfg)
    : work_queue(queue_sz)
    , workers_running(true)
    , config(cfg) {
    key.assign(key_data, key_data + key_len);
    header_mac.set_key(key);
    rate_limiter = std::make_unique<RateLimiter>();
    for (size_t i = 0; i < num_threads; i++)
        file_workers.emplace_back(&AES256GCM::file_worker_function, this);
}

AES256GCM::~AES256GCM() {
    workers_running = false;
    work_queue.stop();

    FileWork pending;
    while (work_queue.pop(pending)) {
        try {
            pending.result_promise.set_value(false);
        } catch (const std::future_error&) {
            /* Ya resuelta, ignorar */
        }
    }

    for (auto& thread : file_workers)
        if (thread.joinable()) thread.join();
}

/* ============================================
   API publica
   ============================================ */

void AES256GCM::setRateLimits(size_t max_files, size_t max_bytes) {
    rate_limiter->setLimits(max_files, max_bytes);
}

bool AES256GCM::encrypt_file(
    const std::string& inputPath, const std::string& outputPath) {
    return process_single_file_with_retry(inputPath, outputPath, true);
}

bool AES256GCM::decrypt_file(
    const std::string& inputPath, const std::string& outputPath) {
    return process_single_file_with_retry(inputPath, outputPath, false);
}

std::vector<bool> AES256GCM::process_files_parallel(
    const std::vector<std::pair<std::string, std::string>>& files,
    bool encryptMode) {

    std::vector<std::future<bool>> futures;
    futures.reserve(files.size());
    std::vector<bool> results;
    results.reserve(files.size());

    for (const auto& [input, output] : files) {
        std::promise<bool> promise;
        futures.push_back(promise.get_future());

        FileWork work;
        work.input_path = input;
        work.output_path = output;
        work.is_encrypt = encryptMode;
        work.result_promise = std::move(promise);
        work_queue.push(std::move(work));
    }

    for (auto& future : futures) {
        try {
            results.push_back(future.get());
        } catch (const std::future_error&) {
            results.push_back(false);
        }
    }

    return results;
}

std::string AES256GCM::provider() const {
    static const std::string cached = [] {
        auto test = Botan::AEAD_Mode::create_or_throw(
            "AES-256/GCM", Botan::Cipher_Dir::Encryption);
        return test->provider();
    }();
    return cached;
}

bool AES256GCM::has_aes_ni() const {
    std::string prov = provider();
    return prov.find("aes-ni") != std::string::npos ||
           prov.find("clmul") != std::string::npos;
}