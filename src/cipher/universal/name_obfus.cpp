// src/cipher/universal/name_obfus.cpp
// Lógica de ofuscación de nombres, contadores y gestión de la clave de nombres.

#include "../universal_cipher.h"
#include <botan/stream_cipher.h>
#include <botan/pwdhash.h>
#include <botan/hex.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <iostream>

// NameKeyMgr
Botan::secure_vector<uint8_t> NameKeyMgr::derive_name_key(const Botan::secure_vector<uint8_t>& master) {
    auto hash = Botan::HashFunction::create_or_throw("SHA-256");
    hash->update(master);
    hash->update("NAME_OBFUSCATION_KEY_V1");
    return hash->final();
}

bool NameKeyMgr::write_full(int fd, const void* data, size_t size)
{
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written <= 0) return false;
        ptr += written;
        remaining -= written;
    }
    return true;
}

bool NameKeyMgr::read_full(int fd, void* data, size_t size)
{
    uint8_t* ptr = static_cast<uint8_t*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t read_bytes = read(fd, ptr, remaining);
        if (read_bytes <= 0) return false;
        ptr += read_bytes;
        remaining -= read_bytes;
    }
    return true;
}

bool NameKeyMgr::save_master_key() 
{
    FileRAII file(key_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!file.valid()) return false;

    Botan::secure_vector<uint8_t> salt = SecureRandom::secure_random(16);

    auto pbkdf2_family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
    auto pbkdf2 = pbkdf2_family->from_params(100000);

    Botan::secure_vector<uint8_t> storage_key(32);
    
    // FIX DE SEGURIDAD: Evita que cualquiera con el binario derive la clave.
    std::string machine_id = "RUBIC_CIPHER_SECURE_V2_" + std::to_string(getuid());

    pbkdf2->hash(storage_key, machine_id, salt);

    auto cipher = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Encryption);
    cipher->set_key(storage_key);
    Botan::secure_vector<uint8_t> iv = SecureRandom::secure_random(16);
    cipher->start(iv);

    Botan::secure_vector<uint8_t> encrypted = master_key;
    cipher->finish(encrypted);

    if (!write_full(file.get(), salt.data(), 16) || !write_full(file.get(), iv.data(), 16) ||
        !write_full(file.get(), encrypted.data(), encrypted.size())) {
        return false;
    }

    auto hash = Botan::HashFunction::create_or_throw("SHA-256");
    hash->update(salt);
    hash->update(iv);
    hash->update(encrypted);
    auto checksum = hash->final();

    if (!write_full(file.get(), checksum.data(), checksum.size())) {
        return false;
    }

    fsync(file.get());
    return true;
}

bool NameKeyMgr::load_master_key() {
    FileRAII file(key_file_path, O_RDONLY);
    if (!file.valid()) return false;

    struct stat st;
    if (fstat(file.get(), &st) != 0) return false;
    if (st.st_size < 112) return false;

    std::vector<uint8_t> buffer(st.st_size);
    if (!read_full(file.get(), buffer.data(), buffer.size())) return false;

    size_t pos = 0;

    Botan::secure_vector<uint8_t> salt(16);
    std::memcpy(salt.data(), buffer.data() + pos, 16);
    pos += 16;

    Botan::secure_vector<uint8_t> iv(16);
    std::memcpy(iv.data(), buffer.data() + pos, 16);
    pos += 16;

    size_t encrypted_size = st.st_size - pos - 32;
    Botan::secure_vector<uint8_t> encrypted(encrypted_size);
    std::memcpy(encrypted.data(), buffer.data() + pos, encrypted_size);
    pos += encrypted_size;

    Botan::secure_vector<uint8_t> stored_checksum(32);
    std::memcpy(stored_checksum.data(), buffer.data() + pos, 32);

    auto hash = Botan::HashFunction::create_or_throw("SHA-256");
    hash->update(salt);
    hash->update(iv);
    hash->update(encrypted);
    auto calculated_checksum = hash->final();

    if (calculated_checksum.size() != stored_checksum.size() ||
        !ConstantTime::compare(calculated_checksum.data(), stored_checksum.data(), 32)) {
        return false;
    }

    auto pbkdf2_family = Botan::PasswordHashFamily::create_or_throw("PBKDF2(SHA-256)");
    auto pbkdf2 = pbkdf2_family->from_params(100000);

    Botan::secure_vector<uint8_t> storage_key(32);
    std::string machine_id = "RUBIC_CIPHER_SECURE_V2_" + std::to_string(getuid());

    pbkdf2->hash(storage_key, machine_id, salt);

    auto cipher = Botan::Cipher_Mode::create_or_throw("AES-256/CBC/PKCS7", Botan::Cipher_Dir::Decryption);
    cipher->set_key(storage_key);
    cipher->start(iv);

    try {
        cipher->finish(encrypted);
        master_key = encrypted;
        return true;
    } catch (const std::exception& e) {
        return false;
    }
}

NameKeyMgr::NameKeyMgr(const std::string& key_file) : key_file_path(key_file) {
    if (load_master_key()) {
        name_key = derive_name_key(master_key);
        initialized = true;
    } else {
        master_key = SecureRandom::secure_random(32);
        name_key = derive_name_key(master_key);
        if (save_master_key()) {
            initialized = true;
        }
    }
}

NameKeyMgr::~NameKeyMgr() {
    if (!master_key.empty()) SecMemGuard::secure_memset(master_key.data(), 0, master_key.size());
    if (!name_key.empty()) SecMemGuard::secure_memset(name_key.data(), 0, name_key.size());
}

//************************************************
// PersistCounter

bool PersistCounter::write_full(int fd, const void* data, size_t size) {
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written <= 0) return false;
        ptr += written;
        remaining -= written;
    }
    return true;
}

bool PersistCounter::read_full(int fd, void* data, size_t size) {
    uint8_t* ptr = static_cast<uint8_t*>(data);
    size_t remaining = size;
    while (remaining > 0) {
        ssize_t read_bytes = read(fd, ptr, remaining);
        if (read_bytes <= 0) return false;
        ptr += read_bytes;
        remaining -= read_bytes;
    }
    return true;
}

void PersistCounter::load_from_file() {
    FileRAII file(storage_file, O_RDONLY);
    if (!file.valid()) return;

    try {
        struct stat st;
        if (fstat(file.get(), &st) != 0 || st.st_size == 0) return;

        std::vector<uint8_t> buffer(st.st_size);
        if (!read_full(file.get(), buffer.data(), buffer.size())) return;

        size_t pos = 0;
        if (buffer.size() < sizeof(uint32_t)) return;

        uint32_t count;
        std::memcpy(&count, buffer.data() + pos, sizeof(count));
        pos += sizeof(count);

        for (uint32_t i = 0; i < count && pos < buffer.size(); i++) {
            if (pos + sizeof(uint16_t) > buffer.size()) break;

            uint16_t name_len;
            std::memcpy(&name_len, buffer.data() + pos, sizeof(name_len));
            pos += sizeof(name_len);

            if (name_len == 0 || name_len > 1024 || pos + name_len > buffer.size()) break;

            std::string name(reinterpret_cast<const char*>(buffer.data() + pos), name_len);
            pos += name_len;

            if (pos + sizeof(uint64_t) > buffer.size()) break;

            uint64_t counter;
            std::memcpy(&counter, buffer.data() + pos, sizeof(counter));
            pos += sizeof(counter);

            counters[name] = counter;
        }
    } catch (const std::exception& e) {}
}

bool PersistCounter::save_to_file_internal() {
    if (is_saving.exchange(true)) return true;

    std::string temp_file = storage_file + ".tmp";
    bool success = false;

    try {
        FileRAII file(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!file.valid()) {
            is_saving = false;
            return false;
        }

        std::shared_lock<std::shared_timed_mutex> lock(counters_mutex);

        uint32_t count = static_cast<uint32_t>(counters.size());
        if (!write_full(file.get(), &count, sizeof(count))) {
            is_saving = false;
            return false;
        }

        for (const auto& [name, counter] : counters) {
            uint16_t name_len = static_cast<uint16_t>(name.size());
            if (!write_full(file.get(), &name_len, sizeof(name_len))) {
                is_saving = false;
                return false;
            }
            if (!write_full(file.get(), name.c_str(), name_len)) {
                is_saving = false;
                return false;
            }
            if (!write_full(file.get(), &counter, sizeof(counter))) {
                is_saving = false;
                return false;
            }
        }

        fsync(file.get());
        file.close();

        if (rename(temp_file.c_str(), storage_file.c_str()) != 0) {
            is_saving = false;
            return false;
        }

        dirty = false;
        success = true;
    } catch (const std::exception& e) {}

    is_saving = false;
    save_cv.notify_all();
    return success;
}

void PersistCounter::auto_save_loop()
{
    while (auto_save_running.load()) {
        std::unique_lock<std::mutex> lock(save_mutex);
        save_cv.wait_for(lock, std::chrono::milliseconds(AUTO_SAVE_INTERVAL_MS), [this]() {
            return !auto_save_running.load();
        });

        if (!auto_save_running.load()) break;
        if (dirty.load() && !is_saving.load()) save_to_file_internal();
    }
}

PersistCounter::PersistCounter(const std::string& file_path) : storage_file(file_path) {
    load_from_file();
    auto_save_running = true;
    auto_save_thread = std::thread(&PersistCounter::auto_save_loop, this);
}

PersistCounter::~PersistCounter() {
    auto_save_running = false;
    save_cv.notify_all();
    if (auto_save_thread.joinable()) auto_save_thread.join();
    std::unique_lock<std::mutex> lock(save_mutex);
    save_cv.wait(lock, [this]() { return !is_saving.load(); });
    if (dirty.load()) save_to_file_internal();
}

uint64_t PersistCounter::get_and_increment(const std::string& key) {
    std::unique_lock<std::shared_timed_mutex> lock(counters_mutex);
    uint64_t& counter = counters[key];
    uint64_t result = counter++;
    dirty = true;

    uint64_t current_save = ++save_counter;
    if (current_save >= SAVE_THRESHOLD) {
        save_counter = 0;
        lock.unlock();
        if (!is_saving.load()) std::thread([this]() { save_to_file_internal(); }).detach();
    }
    return result;
}

uint64_t PersistCounter::get(const std::string& key) const {
    std::shared_lock<std::shared_timed_mutex> lock(counters_mutex);
    auto it = counters.find(key);
    return it != counters.end() ? it->second : 0;
}

// ============================================
// NameObfus
// ============================================

std::string NameObfus::base64_url_encode(const std::string& data) 
{
    std::string encoded = Botan::base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
    std::replace(encoded.begin(), encoded.end(), '+', '-');
    std::replace(encoded.begin(), encoded.end(), '/', '_');
    encoded.erase(std::remove(encoded.begin(), encoded.end(), '='), encoded.end());
    return encoded;
}

std::string NameObfus::base64_url_decode(const std::string& encoded)
{
    std::string base64 = encoded;
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');
    while (base64.length() % 4) base64 += '=';

    try {
        auto vec = Botan::base64_decode(base64);
        return std::string(vec.begin(), vec.end());
    } catch (const std::exception& e) {
        return "";
    }
}

NameObfus::NameObfus(size_t cache_sz, const std::string& counter_file, const std::string& key_file)
    : cache_size(cache_sz) 
{
    key_manager = std::make_unique<NameKeyMgr>(key_file);
    if (key_manager->is_initialized()) name_key = key_manager->get_name_key();
    else name_key = SecureRandom::secure_random(32);

    persistent_counter = std::make_unique<PersistCounter>(counter_file);

    name_cache.reserve(cache_size);
    for (size_t i = 0; i < cache_size; i++) {
        name_cache.push_back(std::make_unique<NameCacheEntry>());
    }
}

NameObfus::~NameObfus() 
{
    if (persistent_counter) persistent_counter->force_save();
    if (!name_key.empty()) {
        SecMemGuard::secure_memset(name_key.data(), 0, name_key.size());
        name_key.clear();
    }
}

std::string NameObfus::obfuscate_name(const std::string& original_name) {
    if (original_name.empty()) return "";

    {
        std::shared_lock<std::shared_mutex> lock(cache_mutex);
        for (const auto& entry : name_cache) {
            if (entry->original == original_name && !entry->original.empty()) {
                entry->hits++;
                return entry->obfuscated;
            }
        }
    }

    try {
        uint64_t counter = persistent_counter->get_and_increment(original_name);
        auto cipher = Botan::StreamCipher::create_or_throw("CTR(AES-256)");
        cipher->set_key(name_key);

        EncryptedName enc_name;
        enc_name.nonce.resize(16);
        std::memcpy(enc_name.nonce.data(), &counter, 8);
         uint64_t random_part = SecureRandom::random_uint64();
        std::memcpy(enc_name.nonce.data() + 8, &random_part, 8);

        cipher->set_iv(enc_name.nonce);

        Botan::secure_vector<uint8_t> name_bytes(original_name.begin(), original_name.end());
        cipher->cipher(name_bytes.data(), name_bytes.data(), name_bytes.size());

        enc_name.ciphertext.assign(name_bytes.begin(), name_bytes.end());
        std::string serialized = enc_name.serialize();
        std::string base64_name = base64_url_encode(serialized);

        if (base64_name.length() > 251) base64_name.resize(251);
        std::string result = base64_name + ".enc";

        {
            std::unique_lock<std::shared_mutex> lock(cache_mutex);
             size_t idx = (cache_index++) % cache_size;
            name_cache[idx]->original = original_name;
            name_cache[idx]->obfuscated = result;
            name_cache[idx]->timestamp = std::chrono::steady_clock::now();
            name_cache[idx]->hits = 1;
        }
        return result;
    } catch (const std::exception& e) {
        return "file_" + std::to_string(SecureRandom::random_uint64()) + ".enc";
    }
}

std::string NameObfus::deobfuscate_name(const std::string& obfuscated_name) {
    if (obfuscated_name.empty()) return obfuscated_name;

    {
        std::shared_lock<std::shared_mutex> lock(cache_mutex);
        for (const auto& entry : name_cache) {
            if (entry->obfuscated == obfuscated_name && !entry->obfuscated.empty()) {
                entry->hits++;
                return entry->original;
            }
        }
    }

    try {
        if (obfuscated_name.length() <= 4 || obfuscated_name.substr(obfuscated_name.length() - 4) != ".enc") {
            return obfuscated_name;
        }

        std::string base64_part = obfuscated_name.substr(0, obfuscated_name.length() - 4);
        std::string serialized = base64_url_decode(base64_part);
        if (serialized.empty()) return "restored_" + obfuscated_name;

        EncryptedName enc_name = EncryptedName::deserialize(serialized);
        if (enc_name.nonce.size() != 16) return "restored_" + obfuscated_name;

        auto cipher = Botan::StreamCipher::create_or_throw("CTR(AES-256)");
        cipher->set_key(name_key);
        cipher->set_iv(enc_name.nonce);

        Botan::secure_vector<uint8_t> encrypted_bytes(enc_name.ciphertext.begin(), enc_name.ciphertext.end());
        cipher->cipher(encrypted_bytes.data(), encrypted_bytes.data(), encrypted_bytes.size());
        std::string original_name(encrypted_bytes.begin(), encrypted_bytes.end());

        {
            std::unique_lock<std::shared_mutex> lock(cache_mutex);
            size_t idx = (cache_index++) % cache_size;
            name_cache[idx]->original = original_name;
            name_cache[idx]->obfuscated = obfuscated_name;
            name_cache[idx]->timestamp = std::chrono::steady_clock::now();
            name_cache[idx]->hits = 1;
        }
        return original_name;
    } catch (const std::exception& e) {
        return "restored_" + obfuscated_name;
    }
}

void NameObfus::force_save_counters() {
    if (persistent_counter) persistent_counter->force_save();
}
