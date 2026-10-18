// cipher/universal_cipher.cpp - 0.1 alpha
// Implementación de la lógica pura del cifrador universal.
// NOTA: NameKeyMgr, PersistCounter y NameObfus viven en universal/name_obfus.cpp

#include "universal_cipher.h"
#include "../keygest/key_manager.h"
#include "../rubic_core.h"
#include <botan/kdf.h>
#include <span>

//***************************************
// HeaderKMAC

void HeaderKMAC::set_key(const Botan::secure_vector<uint8_t>& master_key) {
    try {
        auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");

        std::string info_str = "HEADER_KMAC"; 
        std::string salt_str = "RUBIC_SALT";

        Botan::secure_vector<uint8_t> derived_key(32);

        kdf->derive_key(std::span<uint8_t>(derived_key.data(), derived_key.size()),
                        std::span<const uint8_t>(master_key.data(), master_key.size()),
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(salt_str.data()), salt_str.size()),
                        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()));

        mac_key = derived_key;
    } catch (...) {
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(master_key);
        hash->update("HEADER_KMAC_SECURE_V2");
        mac_key = hash->final();
    }
}

Botan::secure_vector<uint8_t> HeaderKMAC::calculate(const uint8_t* data, size_t len) {
    std::unique_ptr<Botan::MessageAuthenticationCode> mac;
    try {
        mac = Botan::MessageAuthenticationCode::create_or_throw("KMAC-128(256)");
    } catch (...) {
        mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-3(256))");
    }
    mac->set_key(mac_key);
    mac->update(data, len);
    return mac->final();
}

bool HeaderKMAC::verify(const uint8_t* data, size_t len, const uint8_t* mac_tag, size_t mac_len) {
    auto calculated = calculate(data, len);
    if (calculated.size() != mac_len)
        return false;
    return ConstantTime::compare(calculated.data(), mac_tag, mac_len);
}

// ============================================
// RateLimiter
// ============================================

RateLimiter::RateLimiter(size_t max_files, size_t max_bytes)
    : max_files_per_second(max_files), max_bytes_per_second(max_bytes) {
    reset();
}

void RateLimiter::reset() {
    window_start = std::chrono::steady_clock::now();
    files_processed = 0;
    bytes_processed = 0;
}

void RateLimiter::wait_if_needed(size_t bytes) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - window_start).count();

    if (elapsed >= 1000) {
        window_start = now;
        files_processed = 0;
        bytes_processed = 0;
    }

    files_processed++;
    bytes_processed += bytes;

    if (files_processed > max_files_per_second || bytes_processed > max_bytes_per_second) {
        size_t wait_ms = 1000 - elapsed;
        if (wait_ms > 0 && wait_ms < 1000) {
            std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
        }
    }
}

void RateLimiter::setLimits(size_t max_files, size_t max_bytes) {
    max_files_per_second = max_files;
    max_bytes_per_second = max_bytes;
}

// ============================================
// AES256GCM
// ============================================

bool AES256GCM::write_full_with_retry(int fd, const void* data, size_t size, int max_retries) {
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
                return false;
            }
            return false;
        }
        ptr += written;
        remaining -= written;
        retries = 0;
    }
    return true;
}

bool AES256GCM::read_full_with_retry(int fd, void* data, size_t size, int max_retries) {
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
                return false;
            }
            return false;
        }
        ptr += read_bytes;
        remaining -= read_bytes;
        retries = 0;
    }
    return true;
}

bool AES256GCM::validate_header_integrity(const uint8_t* data, size_t size) {
    if (size < config.nonce_size + 1 + 8)
        return false;
    uint8_t flags = data[config.nonce_size];
    if (flags != 0x01 && flags != 0x03)
        return false;
    return true;
}

bool AES256GCM::encrypt_with_mmap(const MMapRAII& mapped, const std::string& outputPath) {
    Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
    SecureRandom::generate_bytes(file_nonce.data(), file_nonce.size());

    FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!out_file.valid())
        return false;

    if (!write_full_with_retry(out_file.get(), file_nonce.data(), file_nonce.size()))
        return false;

    uint8_t flags = 0x01 | (config.use_header_mac ? 0x02 : 0);
    if (!write_full_with_retry(out_file.get(), &flags, 1))
        return false;

    uint64_t original_size = mapped.get_size();
    if (!write_full_with_retry(out_file.get(), &original_size, 8))
        return false;

    Botan::secure_vector<uint8_t> header_data;
    header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
    header_data.push_back(flags);
    header_data.insert(header_data.end(),
                       reinterpret_cast<uint8_t*>(&original_size),
                       reinterpret_cast<uint8_t*>(&original_size) + 8);

    if (config.use_header_mac) {
        auto mac = header_mac.calculate(header_data.data(), header_data.size());
        if (!write_full_with_retry(out_file.get(), mac.data(), mac.size()))
            return false;
    }

    auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    cipher->set_key(key);
    cipher->set_associated_data(header_data.data(), header_data.size());
    cipher->start(file_nonce);

    size_t buffer_size = config.optimal_buffer_size;
    Botan::secure_vector<uint8_t> buffer;

    const uint8_t* data_ptr = static_cast<const uint8_t*>(mapped.get());
    size_t remaining = mapped.get_size();

    while (remaining > 0) {
        size_t chunk = std::min(buffer_size, remaining);
        buffer.assign(data_ptr, data_ptr + chunk);

        if (remaining <= chunk)
            cipher->finish(buffer);
        else
            cipher->update(buffer);

        if (!write_full_with_retry(out_file.get(), buffer.data(), buffer.size()))
            return false;

        data_ptr += chunk;
        remaining -= chunk;
        rate_limiter->wait_if_needed(chunk);
    }

    total_bytes_processed += mapped.get_size();
    return true;
}

bool AES256GCM::decrypt_with_mmap(const MMapRAII& mapped, const std::string& outputPath) {
    const uint8_t* data = static_cast<const uint8_t*>(mapped.get());
    size_t total_size = mapped.get_size();

    if (!validate_header_integrity(data, total_size))
        return false;

    size_t pos = 0;

    Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
    std::memcpy(file_nonce.data(), data + pos, config.nonce_size);
    pos += config.nonce_size;

    uint8_t flags = data[pos++];
    bool has_mac = (flags & 0x02) != 0;

    uint64_t original_size;
    std::memcpy(&original_size, data + pos, 8);
    pos += 8;

    Botan::secure_vector<uint8_t> header_data;
    header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
    header_data.push_back(flags);
    header_data.insert(header_data.end(),
                       reinterpret_cast<uint8_t*>(&original_size),
                       reinterpret_cast<uint8_t*>(&original_size) + 8);

    if (has_mac) {
        if (pos + 32 > total_size)
            return false;
        Botan::secure_vector<uint8_t> file_mac(32);
        std::memcpy(file_mac.data(), data + pos, 32);
        pos += 32;

        if (!header_mac.verify(header_data.data(), header_data.size(), file_mac.data(), file_mac.size())) {
            return false;
        }
    }

    auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    cipher->set_key(key);
    cipher->set_associated_data(header_data.data(), header_data.size());
    cipher->start(file_nonce);

    FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!out_file.valid())
        return false;

    if (total_size < pos + SystemConfig::GCM_TAG_SIZE)
        return false;

    size_t ciphertext_size = total_size - pos - SystemConfig::GCM_TAG_SIZE;
    size_t buffer_size = config.optimal_buffer_size;
    Botan::secure_vector<uint8_t> buffer;

    while (ciphertext_size > 0) {
        size_t chunk = std::min(buffer_size, ciphertext_size);
        buffer.assign(data + pos, data + pos + chunk);
        pos += chunk;

        if (chunk >= ciphertext_size) {
            if (pos + SystemConfig::GCM_TAG_SIZE > total_size)
                return false;
            buffer.insert(buffer.end(), data + pos, data + pos + SystemConfig::GCM_TAG_SIZE);
            cipher->finish(buffer);
        } else {
            cipher->update(buffer);
        }

        if (!write_full_with_retry(out_file.get(), buffer.data(), buffer.size()))
            return false;

        ciphertext_size -= chunk;
        rate_limiter->wait_if_needed(chunk);
    }

    total_bytes_processed += original_size;
    return true;
}

bool AES256GCM::process_with_traditional_io(const std::string& inputPath,
                                            const std::string& outputPath,
                                            bool encryptMode) {
    FileRAII in_file(inputPath, O_RDONLY);
    if (!in_file.valid())
        return false;

    struct stat st;
    if (fstat(in_file.get(), &st) != 0)
        return false;
    size_t file_size = st.st_size;

    if (encryptMode) {
        FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!out_file.valid())
            return false;

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

        Botan::secure_vector<uint8_t> header_data;
        header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
        header_data.push_back(flags);
        header_data.insert(header_data.end(),
                           reinterpret_cast<uint8_t*>(&original_size),
                           reinterpret_cast<uint8_t*>(&original_size) + 8);

        if (config.use_header_mac) {
            auto mac = header_mac.calculate(header_data.data(), header_data.size());
            if (!write_full_with_retry(out_file.get(), mac.data(), mac.size()))
                return false;
        }

        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        cipher->set_key(key);
        cipher->set_associated_data(header_data.data(), header_data.size());
        cipher->start(file_nonce);

        size_t buffer_size = config.optimal_buffer_size;
        std::vector<uint8_t> buffer(buffer_size);
        size_t total_read = 0;

        while (total_read < file_size) {
            size_t to_read = std::min(buffer_size, file_size - total_read);
            if (!read_full_with_retry(in_file.get(), buffer.data(), to_read))
                return false;

            Botan::secure_vector<uint8_t> secure_buf(buffer.data(), buffer.data() + to_read);

            if (total_read + to_read >= file_size)
                cipher->finish(secure_buf);
            else
                cipher->update(secure_buf);

            if (!write_full_with_retry(out_file.get(), secure_buf.data(), secure_buf.size()))
                return false;

            total_read += to_read;
            rate_limiter->wait_if_needed(to_read);
        }
    } else {
        FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!out_file.valid())
            return false;

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

        Botan::secure_vector<uint8_t> header_data;
        header_data.insert(header_data.end(), file_nonce.begin(), file_nonce.end());
        header_data.push_back(flags);
        header_data.insert(header_data.end(),
                           reinterpret_cast<uint8_t*>(&original_size),
                           reinterpret_cast<uint8_t*>(&original_size) + 8);

        if (has_mac) {
            Botan::secure_vector<uint8_t> file_mac(32);
            if (!read_full_with_retry(in_file.get(), file_mac.data(), 32))
                return false;
            if (!header_mac.verify(header_data.data(), header_data.size(), file_mac.data(), file_mac.size()))
                return false;
        }

        auto cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        cipher->set_key(key);
        cipher->set_associated_data(header_data.data(), header_data.size());
        cipher->start(file_nonce);

        off_t current_pos = lseek(in_file.get(), 0, SEEK_CUR);
        off_t file_end = lseek(in_file.get(), 0, SEEK_END);
        lseek(in_file.get(), current_pos, SEEK_SET);

        size_t ciphertext_size = file_end - current_pos - SystemConfig::GCM_TAG_SIZE;
        size_t buffer_size = config.optimal_buffer_size;
        std::vector<uint8_t> buffer(buffer_size);
        size_t total_read = 0;

        while (total_read < ciphertext_size) {
            size_t to_read = std::min(buffer_size, ciphertext_size - total_read);
            if (!read_full_with_retry(in_file.get(), buffer.data(), to_read))
                return false;

            Botan::secure_vector<uint8_t> secure_buf(buffer.data(), buffer.data() + to_read);

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
    total_bytes_processed += file_size;
    return true;
}

bool AES256GCM::process_with_mmap_wrapper(const std::string& inputPath,
                                          const std::string& outputPath,
                                          bool encryptMode) {
    FileRAII in_file(inputPath, O_RDONLY);
    if (!in_file.valid())
        return false;

    struct stat st;
    if (fstat(in_file.get(), &st) != 0)
        return false;

    MMapRAII mmap;
    if (!mmap.map(in_file.get(), st.st_size))
        return false;

    mmap_used++;

    try {
        if (encryptMode)
            return encrypt_with_mmap(mmap, outputPath);
        else
            return decrypt_with_mmap(mmap, outputPath);
    } catch (const std::exception& e) {
        return false;
    }
}

bool AES256GCM::process_single_file_with_retry(const std::string& inputPath,
                                               const std::string& outputPath,
                                               bool encryptMode) {
    int retries = 0;
    bool success = false;

    while (retries <= static_cast<int>(config.max_retries) && !success) {
        if (retries > 0) {
            total_retries++;
            std::this_thread::sleep_for(std::chrono::milliseconds(config.retry_delay_ms));
            std::remove(outputPath.c_str());
        }

        try {
            rate_limiter->wait_if_needed();

            struct stat st;
            if (stat(inputPath.c_str(), &st) != 0)
                return false;

            if (config.should_use_mmap(st.st_size)) {
                success = process_with_mmap_wrapper(inputPath, outputPath, encryptMode);
            } else {
                success = process_with_traditional_io(inputPath, outputPath, encryptMode);
            }
        } catch (const std::exception& e) {
            success = false;
        }

        retries++;
    }

    if (!success)
        total_errors++;
    return success;
}

void AES256GCM::file_worker_function() {
    while (workers_running.load()) {
        FileWork work;
        if (work_queue.pop(work)) {
            bool result = process_single_file_with_retry(work.input_path, work.output_path, work.is_encrypt);
            work.result_promise.set_value(result);
        }
    }
}

AES256GCM::AES256GCM(const uint8_t* key_data,
                     size_t key_len,
                     size_t num_threads,
                     size_t queue_sz,
                     const SystemConfig& cfg)
    : work_queue(queue_sz), workers_running(true), config(cfg) {

    key.assign(key_data, key_data + key_len);
    header_mac.set_key(key);
    rate_limiter = std::make_unique<RateLimiter>();

    for (size_t i = 0; i < num_threads; i++) {
        file_workers.emplace_back(&AES256GCM::file_worker_function, this);
    }
}

AES256GCM::~AES256GCM() {
    workers_running = false;
    work_queue.stop();
    for (auto& thread : file_workers) {
        if (thread.joinable())
            thread.join();
    }
    if (!key.empty()) {
        SecMemGuard::secure_memset(key.data(), 0, key.size());
    }
}

void AES256GCM::setRateLimits(size_t max_files, size_t max_bytes) {
    rate_limiter->setLimits(max_files, max_bytes);
}

bool AES256GCM::encrypt_file(const std::string& inputPath, const std::string& outputPath) {
    return process_single_file_with_retry(inputPath, outputPath, true);
}

bool AES256GCM::decrypt_file(const std::string& inputPath, const std::string& outputPath) {
    return process_single_file_with_retry(inputPath, outputPath, false);
}

std::vector<bool> AES256GCM::process_files_parallel(const std::vector<std::pair<std::string, std::string>>& files,
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
        results.push_back(future.get());
    }

    return results;
}

std::string AES256GCM::provider() const {
    auto test = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    return test->provider();
}

bool AES256GCM::has_aes_ni() const {
    std::string prov = provider();
    return prov.find("aes-ni") != std::string::npos || prov.find("clmul") != std::string::npos;
}

// ============================================
// UniversalCipher
// ============================================

Botan::secure_vector<uint8_t> UniversalCipher::hexToSecureBytes(const std::string& hex) {
    Botan::secure_vector<uint8_t> result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        char hex_byte[3] = {hex[i], hex[i + 1], '\0'};
        char* endptr = nullptr;
        long val = strtol(hex_byte, &endptr, 16);
        if (endptr == hex_byte + 2) {
            result.push_back(static_cast<uint8_t>(val));
        }
    }
    return result;
}

std::string UniversalCipher::secureVectorToHex(const Botan::secure_vector<uint8_t>& data) {
    std::string result;
    result.reserve(data.size() * 2);
    for (size_t i = 0; i < data.size(); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        result += buf;
    }
    return result;
}

bool UniversalCipher::fileExists(const std::string& path) {
    struct stat buffer;
    return stat(path.c_str(), &buffer) == 0;
}

bool UniversalCipher::isDirectory(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 && (st.st_mode & S_IFDIR);
}

uint64_t UniversalCipher::getFileSize(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0 ? st.st_size : 0;
}

bool UniversalCipher::should_ignore_file(const std::string& filename) {
    std::string name = std::filesystem::path(filename).filename().string();
    static const std::vector<std::string> ignored = {".cipher_counters.dat",
                                                     ".cipher_namekey.dat",
                                                     ".DS_Store",
                                                     "Thumbs.db"};
    for (const auto& ign : ignored) {
        if (name == ign)
            return true;
    }
    return false;
}

bool UniversalCipher::is_already_encrypted(const std::string& filename) {
    if (filename.length() < 4)
        return false;
    std::string ext = filename.substr(filename.length() - 4);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext == ".enc";
}

std::vector<std::string> UniversalCipher::getAllFiles(const std::string& path, bool recursive) {
    std::vector<std::string> files;
    try {
        if (recursive) {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                if (entry.is_regular_file() && !should_ignore_file(entry.path().string())) {
                    files.push_back(entry.path().string());
                }
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(path)) {
                if (entry.is_regular_file() && !should_ignore_file(entry.path().string())) {
                    files.push_back(entry.path().string());
                }
            }
        }
    } catch (const std::exception& e) {
        log(univ_log::LogLevel::Error, univ_log::LogEvent::ScanError, path + ": " + e.what());
    }
    return files;
}

bool UniversalCipher::processDirectory(const std::string& path, bool encryptMode) {
    std::vector<std::string> files = getAllFiles(path, true);
    if (files.empty()) {
        log(univ_log::LogLevel::Warning, univ_log::LogEvent::NoFilesFound, path);
        return false;
    }

    std::vector<std::pair<std::string, std::string>> toProcess;

    for (const auto& file : files) {
        std::string name = std::filesystem::path(file).filename().string();
        std::string dir = std::filesystem::path(file).parent_path().string();

        if (encryptMode && !is_already_encrypted(name)) {
            std::string obfuscated = name_obfuscator->obfuscate_name(name);
            std::string temp_path = dir;
            temp_path += "/";
            temp_path += obfuscated;
            temp_path += ".tmp";
            toProcess.push_back({file, temp_path});
        } else if (!encryptMode && is_already_encrypted(file)) {
            std::string original = name_obfuscator->deobfuscate_name(name);
            std::string temp_path = dir;
            temp_path += "/";
            temp_path += original;
            temp_path += ".tmp";
            toProcess.push_back({file, temp_path});
        }
    }

    if (toProcess.empty()) {
        log(univ_log::LogLevel::Warning, univ_log::LogEvent::NoFilesToProcess, path);
        return false;
    }

    processing_active = true;
    auto start_time = std::chrono::high_resolution_clock::now();

    std::vector<bool> results;
    results.reserve(toProcess.size());
    size_t processed = 0;

    while (processed < toProcess.size() && !stop_requested) {
        size_t batch_size = std::min(config.max_parallel_files, toProcess.size() - processed);
        std::vector<std::pair<std::string, std::string>> batch;

        for (size_t i = 0; i < batch_size; i++) {
            batch.push_back(toProcess[processed + i]);
        }

        auto batch_results = cipher->process_files_parallel(batch, encryptMode);

        for (size_t i = 0; i < batch_results.size(); i++) {
            size_t index = processed + i;

            progress(index + 1, toProcess.size(), toProcess[index].first);

            if (batch_results[i]) {
                std::string final_path = toProcess[index].second;
                final_path.resize(final_path.length() - 4);

                if (std::rename(toProcess[index].second.c_str(), final_path.c_str()) == 0) {
                    if (final_path != toProcess[index].first) {
                        std::remove(toProcess[index].first.c_str());
                    }
                    if (!encryptMode) {
                        UserPermissions::fixFilePermissions(final_path);
                    }
                    log(univ_log::LogLevel::Success, univ_log::LogEvent::FileDone, final_path);
                } else {
                    log(univ_log::LogLevel::Error, univ_log::LogEvent::FileMoveError, toProcess[index].first);
                    batch_results[i] = false;
                }
            } else {
                log(univ_log::LogLevel::Error, univ_log::LogEvent::FileError, toProcess[index].first);
            }
        }

        results.insert(results.end(), batch_results.begin(), batch_results.end());
        processed += batch_size;
    }

    name_obfuscator->force_save_counters();

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    size_t success = 0, fail = 0;
    for (bool r : results) {
        if (r)
            success++;
        else
            fail++;
    }

    last_stats.total_files = toProcess.size();
    last_stats.success = success;
    last_stats.fail = fail;
    last_stats.total_time_ms = static_cast<uint64_t>(duration.count());

    processing_active = false;
    return success > 0;
}

bool UniversalCipher::encryptFileInPlace(const std::string& inputPath) {
    if (!cipher)
        return false;

    std::string dir = std::filesystem::path(inputPath).parent_path().string();
    std::string filename = std::filesystem::path(inputPath).filename().string();

    if (should_ignore_file(filename))
        return true;

    std::string obfuscated = name_obfuscator->obfuscate_name(filename);
    std::string outputPath = dir + "/" + obfuscated;
    std::string tempPath = outputPath + ".tmp";

    bool success = cipher->encrypt_file(inputPath, tempPath);

    if (!success) {
        std::remove(tempPath.c_str());
        return false;
    }

    if (std::rename(tempPath.c_str(), outputPath.c_str()) != 0) {
        std::remove(tempPath.c_str());
        return false;
    }

    if (outputPath != inputPath) {
        std::remove(inputPath.c_str());
    }

    return true;
}

bool UniversalCipher::decryptFileInPlace(const std::string& inputPath) {
    if (!cipher)
        return false;

    std::string dir = std::filesystem::path(inputPath).parent_path().string();
    std::string filename = std::filesystem::path(inputPath).filename().string();
    std::string outputFilename = name_obfuscator->deobfuscate_name(filename);
    std::string outputPath = dir + "/" + outputFilename;
    std::string tempPath = outputPath + ".tmp";

    bool success = cipher->decrypt_file(inputPath, tempPath);

    if (!success) {
        std::remove(tempPath.c_str());
        return false;
    }

    if (std::rename(tempPath.c_str(), outputPath.c_str()) != 0) {
        std::remove(tempPath.c_str());
        return false;
    }

    if (outputPath != inputPath) {
        std::remove(inputPath.c_str());
    }
    UserPermissions::fixFilePermissions(outputPath);

    return true;
}

bool UniversalCipher::processPath(const std::string& path, bool encryptMode) {
    if (isDirectory(path)) {
        return processDirectory(path, encryptMode);
    } else if (fileExists(path)) {
        log(univ_log::LogLevel::Info, univ_log::LogEvent::ProcessingSingle, path);
        return encryptMode ? encryptFileInPlace(path) : decryptFileInPlace(path);
    }
    log(univ_log::LogLevel::Error, univ_log::LogEvent::PathInvalid, path);
    return false;
}

UniversalCipher::UniversalCipher() : keyManager(nullptr) {
    unsigned int system_threads = std::thread::hardware_concurrency();
    if (system_threads == 0)
        system_threads = 4;

    config.autoConfigure(system_threads);

    std::string data_dir = XDG::get_rubic_data_dir();
    config.counter_file_path = data_dir + "/.cipher_counters.dat";
    config.name_key_file_path = data_dir + "/.cipher_namekey.dat";

    name_obfuscator =
        std::make_unique<NameObfus>(config.name_cache_size, config.counter_file_path, config.name_key_file_path);
    SecureRandom::setUseHardware(config.use_hardware_rng);
}

UniversalCipher::~UniversalCipher() {
    if (name_obfuscator) {
        name_obfuscator->force_save_counters();
    }
}

bool UniversalCipher::encryptPath(const std::string& path) {
    return processPath(path, true);
}

bool UniversalCipher::decryptPath(const std::string& path) {
    return processPath(path, false);
}

bool UniversalCipher::setCipherKey(const std::string& keyName) {
    if (!keyManager) {
        log(univ_log::LogLevel::Error, univ_log::LogEvent::NoKeyManager, "");
        return false;
    }

    if (!keyManager->hasKey(keyName)) {
        log(univ_log::LogLevel::Error, univ_log::LogEvent::KeyNotFound, keyName);
        return false;
    }

    if (!keyManager->isKeyActive(keyName)) {
        log(univ_log::LogLevel::Error, univ_log::LogEvent::KeyNotActive, keyName);
        return false;
    }

    Botan::secure_vector<uint8_t> keyBytes = keyManager->getKeyValue(keyName);
    if (keyBytes.empty()) {
        log(univ_log::LogLevel::Error, univ_log::LogEvent::KeyValueError, keyName);
        return false;
    }

    if (keyBytes.size() != 32) {
        log(univ_log::LogLevel::Error, univ_log::LogEvent::KeyLengthError, keyName);
        return false;
    }

    cipher = std::make_unique<AES256GCM>(keyBytes.data(),
                                         keyBytes.size(),
                                         config.thread_config.crypto_threads,
                                         config.queue_size,
                                         config);

    cipher->setRateLimits(config.max_files_per_second, config.max_bytes_per_second);
    currentKeyName = keyName;

    return true;
}

uint64_t UniversalCipher::getFilesProcessed() const {
    return cipher ? cipher->get_files_processed() : 0;
}

uint64_t UniversalCipher::getBytesProcessed() const {
    return cipher ? cipher->get_bytes_processed() : 0;
}

uint64_t UniversalCipher::getErrors() const {
    return cipher ? cipher->get_errors() : 0;
}

uint64_t UniversalCipher::getRetries() const {
    return cipher ? cipher->get_retries() : 0;
}

uint64_t UniversalCipher::getMmapUsed() const {
    return cipher ? cipher->get_mmap_used() : 0;
}