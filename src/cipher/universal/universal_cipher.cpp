// cipher/universal_cipher.cpp - 0.1 alpha
// El orquestador (UniversalCipher).
// NOTA: El motor de cifrado (AES256GCM) vive en universal/universal_pipeline.cpp

#include "universal_cipher.h"
#include "../keygest/key_manager.h"
#include "../rubic_core.h"

// ============================================
// UniversalCipher

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