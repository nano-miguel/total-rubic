// src/cipher/universal/read/read-universal.cpp
#include "../../universal_cipher.h"

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
    static const std::vector<std::string> ignored = {
        ".cipher_counters.dat",
        ".cipher_namekey.dat",
        ".DS_Store",
        "Thumbs.db"
    };
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
        } 
        else {
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