/* cipher/universal/universal_mmap.cpp
Implementacion de la estrategia mmap para AES-256-GCM.
Produce exactamente el mismo formato de archivo que
la estrategia tradicional (nonce | flags | size | [mac] | ct | tag),
asi que ambos caminos son intercambiables.
La cabecera (buildHeaderData) se duplica como static con
linkage interno, por eso no colisiona con la de universal_pipeline.cpp. */
#include "../universal_cipher.h"
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

/* ============================================
   Construccion de cabecera (copia local)
   Identica a la de universal_pipeline.cpp.
   ============================================ */

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
   Cifrado con mmap
   ============================================ */

bool AES256GCM::encrypt_with_mmap(
    const MMapRAII& mapped, const std::string& outputPath) {

    Botan::secure_vector<uint8_t> file_nonce(config.nonce_size);
    SecureRandom::generate_bytes(file_nonce.data(), file_nonce.size());

    FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!out_file.valid()) return false;

    if (!write_full_with_retry(out_file.get(), file_nonce.data(), file_nonce.size()))
        return false;

    uint8_t flags = 0x01 | (config.use_header_mac ? 0x02 : 0);
    if (!write_full_with_retry(out_file.get(), &flags, 1))
        return false;

    uint64_t original_size = mapped.get_size();
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
    const uint8_t* data_ptr = static_cast<const uint8_t*>(mapped.get());
    size_t remaining = mapped.get_size();

    if (remaining == 0) {
        Botan::secure_vector<uint8_t> empty_buf;
        cipher->finish(empty_buf);
        if (!write_full_with_retry(out_file.get(), empty_buf.data(), empty_buf.size()))
            return false;
    } else {
        Botan::secure_vector<uint8_t> buffer;
        while (remaining > 0) {
            size_t chunk = std::min(buffer_size, remaining);
            buffer.assign(data_ptr, data_ptr + chunk);

            if (remaining <= chunk) cipher->finish(buffer);
            else cipher->update(buffer);

            if (!write_full_with_retry(out_file.get(), buffer.data(), buffer.size()))
                return false;

            data_ptr += chunk;
            remaining -= chunk;
            rate_limiter->wait_if_needed(chunk);
        }
    }

    total_files_processed++;
    total_bytes_processed += mapped.get_size();
    return true;
}

/* ============================================
   Descifrado con mmap
   ============================================ */

bool AES256GCM::decrypt_with_mmap(
    const MMapRAII& mapped, const std::string& outputPath) {

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

    auto header_data = buildHeaderData(file_nonce, flags, original_size);

    if (has_mac) {
        if (pos + 32 > total_size) return false;
        Botan::secure_vector<uint8_t> file_mac(32);
        std::memcpy(file_mac.data(), data + pos, 32);
        pos += 32;
        if (!header_mac.verify(header_data.data(), header_data.size(),
                               file_mac.data(), file_mac.size()))
            return false;
    }

    auto cipher = Botan::AEAD_Mode::create_or_throw(
        "AES-256/GCM", Botan::Cipher_Dir::Decryption);
    cipher->set_key(key);
    cipher->set_associated_data(header_data.data(), header_data.size());
    cipher->start(file_nonce);

    FileRAII out_file(outputPath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!out_file.valid()) return false;

    if (total_size < pos + SystemConfig::GCM_TAG_SIZE)
        return false;

    size_t ciphertext_size = total_size - pos - SystemConfig::GCM_TAG_SIZE;
    size_t buffer_size = config.optimal_buffer_size;
    Botan::secure_vector<uint8_t> buffer;

    if (ciphertext_size == 0) {
        Botan::secure_vector<uint8_t> tag(
            data + pos, data + pos + SystemConfig::GCM_TAG_SIZE);
        cipher->finish(tag);
    } else {
        while (ciphertext_size > 0) {
            size_t chunk = std::min(buffer_size, ciphertext_size);
            buffer.assign(data + pos, data + pos + chunk);
            pos += chunk;

            if (chunk >= ciphertext_size) {
                if (pos + SystemConfig::GCM_TAG_SIZE > total_size)
                    return false;
                buffer.insert(buffer.end(),
                    data + pos, data + pos + SystemConfig::GCM_TAG_SIZE);
                cipher->finish(buffer);
            } else {
                cipher->update(buffer);
            }

            if (!write_full_with_retry(out_file.get(), buffer.data(), buffer.size()))
                return false;

            ciphertext_size -= chunk;
            rate_limiter->wait_if_needed(chunk);
        }
    }

    total_files_processed++;
    total_bytes_processed += original_size;
    return true;
}

/* ============================================
   Wrapper: decide mmap vs tradicional
   Si mmap falla (archivo vacio, mapeo fallido),
   cae al path tradicional.
   ============================================ */

bool AES256GCM::process_with_mmap_wrapper(
    const std::string& inputPath,
    const std::string& outputPath,
    bool encryptMode) {

    FileRAII in_file(inputPath, O_RDONLY);
    if (!in_file.valid()) return false;

    struct stat st;
    if (fstat(in_file.get(), &st) != 0) return false;

    MMapRAII mmap;
    if (st.st_size == 0 || !mmap.map(in_file.get(), st.st_size))
        return process_with_traditional_io(inputPath, outputPath, encryptMode);

    mmap_used++;
    try {
        if (encryptMode) return encrypt_with_mmap(mmap, outputPath);
        return decrypt_with_mmap(mmap, outputPath);
    } catch (const std::exception&) {
        return false;
    }
}
