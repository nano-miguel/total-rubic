// keygest/key_manager.cpp - 0.1 alpha
// Implementación de la lógica pura del gestor de claves.
#include "key_manager.h"
#include <sys/stat.h>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <cstdlib>
#include <cstring>


// *****************************************************
// KeyInfo — ciclo de vida
KeyInfo::KeyInfo() : created_at(0), last_used(0), is_active(false), strength(256), requires_access(true) {
key_type = "AES-256";
}
KeyInfo::KeyInfo(const KeyInfo& other)
: key_name(other.key_name), key_value(other.key_value), key_type(other.key_type), key_usage(other.key_usage),
created_at(other.created_at), last_used(other.last_used), is_active(other.is_active), strength(other.strength),
access_code(other.access_code), requires_access(other.requires_access), memory_locker(nullptr) {}
KeyInfo::KeyInfo(KeyInfo&& other) noexcept
: key_name(std::move(other.key_name)), key_value(std::move(other.key_value)), key_type(std::move(other.key_type)),
key_usage(std::move(other.key_usage)), created_at(other.created_at), last_used(other.last_used),
is_active(other.is_active), strength(other.strength), access_code(std::move(other.access_code)),
requires_access(other.requires_access), memory_locker(std::move(other.memory_locker)) {
other.created_at = 0;
other.last_used = 0;
other.is_active = false;
other.strength = 256;
other.requires_access = true;
}
KeyInfo& KeyInfo::operator=(const KeyInfo& other) {
if (this != &other) {
key_name = other.key_name;
key_value = other.key_value;
key_type = other.key_type;
key_usage = other.key_usage;
created_at = other.created_at;
last_used = other.last_used;
is_active = other.is_active;
strength = other.strength;
access_code = other.access_code;
requires_access = other.requires_access;
memory_locker.reset();
}
return *this;
}
KeyInfo& KeyInfo::operator=(KeyInfo&& other) noexcept {
if (this != &other) {
key_name = std::move(other.key_name);
key_value = std::move(other.key_value);
key_type = std::move(other.key_type);
key_usage = std::move(other.key_usage);
 created_at = other.created_at;
  last_used = other.last_used;
   is_active = other.is_active;
strength = other.strength;
access_code = std::move(other.access_code);
requires_access = other.requires_access;
memory_locker = std::move(other.memory_locker);
    other.created_at = 0;
    other.last_used = 0;
    other.is_active = false;
    other.strength = 256;
    other.requires_access = true;
}
return *this;
}
KeyInfo::~KeyInfo() {
access_code.clear();
key_value.clear();
}
void KeyInfo::lockMemory() const {
if (!access_code.empty() && !memory_locker) {
void* ptr = const_cast<uint8_t*>(access_code.data());
memory_locker = std::make_unique<MemoryLC>(ptr, access_code.size());
}
}
void KeyInfo::unlockMemory() const {
memory_locker.reset();
}

// *****************************************************
// KeyInfo — serialización 

Botan::secure_vector<uint8_t> KeyInfo::serialize_secure() const {
    Botan::secure_vector<uint8_t> out;

    auto put_u32 = [&](uint32_t v) {
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    auto put_u64 = [&](uint64_t v) {
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
        }
    };

    auto put_str = [&](const std::string& s) {
        put_u32(static_cast<uint32_t>(s.size()));
        out.insert(out.end(),
                   reinterpret_cast<const uint8_t*>(s.data()),
                   reinterpret_cast<const uint8_t*>(s.data()) + s.size());
    };

    auto put_sec = [&](const Botan::secure_vector<uint8_t>& v) {
        put_u32(static_cast<uint32_t>(v.size()));
        out.insert(out.end(), v.begin(), v.end());
    };

    put_str(key_name);
    put_sec(key_value);       // secreto
    put_sec(access_code);     // secreto
    put_str(key_type);
    put_str(key_usage);
    put_u64(static_cast<uint64_t>(created_at));
    put_u64(static_cast<uint64_t>(last_used));
    out.push_back(is_active ? 1 : 0);
    put_u32(static_cast<uint32_t>(strength));
    out.push_back(requires_access ? 1 : 0);

    return out;
}

bool KeyInfo::deserialize_secure(const Botan::secure_vector<uint8_t>& data) {
    size_t pos = 0;

    auto need = [&](size_t n) -> bool {
        return pos + n <= data.size();
    };

    auto get_u8 = [&](uint8_t& v) -> bool {
        if (!need(1)) return false;
        v = data[pos++];
        return true;
    };

    auto get_u32 = [&](uint32_t& v) -> bool {
        if (!need(4)) return false;
        v = (static_cast<uint32_t>(data[pos]) << 24) |
            (static_cast<uint32_t>(data[pos + 1]) << 16) |
            (static_cast<uint32_t>(data[pos + 2]) << 8) |
            static_cast<uint32_t>(data[pos + 3]);
        pos += 4;
        return true;
    };

    auto get_u64 = [&](uint64_t& v) -> bool {
        if (!need(8)) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) {
            v = (v << 8) | data[pos + i];
        }
        pos += 8;
        return true;
    };

    auto get_str = [&](std::string& dst) -> bool {
        uint32_t len = 0;
        if (!get_u32(len)) return false;
        if (!need(len)) return false;
        dst.assign(reinterpret_cast<const char*>(data.data() + pos), len);
        pos += len;
        return true;
    };

    auto get_sec = [&](Botan::secure_vector<uint8_t>& dst) -> bool {
        uint32_t len = 0;
        if (!get_u32(len)) return false;
        if (!need(len)) return false;
        dst.assign(data.begin() + pos, data.begin() + pos + len);
        pos += len;
        return true;
    };

    uint8_t u8 = 0;

    if (!get_str(key_name)) return false;
    if (!get_sec(key_value)) return false;      // secreto
    if (!get_sec(access_code)) return false;    // secreto
    if (!get_str(key_type)) return false;
    if (!get_str(key_usage)) return false;

    uint64_t tmp = 0;
    if (!get_u64(tmp)) return false;
    created_at = static_cast<time_t>(tmp);

    if (!get_u64(tmp)) return false;
    last_used = static_cast<time_t>(tmp);

    if (!get_u8(u8)) return false;
    is_active = (u8 == 1);

    uint32_t strength32 = 0;
    if (!get_u32(strength32)) return false;
    strength = static_cast<int>(strength32);

    if (!get_u8(u8)) return false;
    requires_access = (u8 == 1);

    return true;
}

// *************************************************************
// KeyManager — helpers privados

std::string KeyManager::getKeysFilePath() const {
std::string data_dir_users;
const char* xdg_data = getenv("XDG_DATA_HOME");
if (xdg_data && xdg_data[0] != '\0') {
     data_dir_users = std::string(xdg_data) + "/RUBIC-A/users";
 } else {
     const char* home = getenv("HOME");
     if (home && home[0] != '\0') {
         data_dir_users = std::string(home) + "/.local/share/RUBIC-A/users";
     } else {
         return "";
     }
 }
 struct stat st;
 if (stat(data_dir_users.c_str(), &st) != 0) {
     std::string current_path;
     std::stringstream ss(data_dir_users);
     std::string segment;
     while (std::getline(ss, segment, '/')) {
         if (segment.empty()) {
             current_path = "/";
             continue;
         }
         if (current_path == "/") {
             current_path += segment;
         } else {
             current_path += "/" + segment;
         }
         if (stat(current_path.c_str(), &st) != 0) {
             mkdir(current_path.c_str(), 0700);
         }
     }
 }
 return data_dir_users + "/" + username + "_keys.dat";
}
bool KeyManager::ensureUsersDirectory() const {
std::string usersDir;
const char* xdg_data = getenv("XDG_DATA_HOME");
if (xdg_data && xdg_data[0] != '\0') {
     usersDir = std::string(xdg_data) + "/RUBIC-A/users";
 } else {
     const char* home = getenv("HOME");
     if (home && home[0] != '\0') {
         usersDir = std::string(home) + "/.local/share/RUBIC-A/users";
     } else {
         return false;
     }
 }
 struct stat buffer;
 if (stat(usersDir.c_str(), &buffer) == 0) {
     if ((buffer.st_mode & 0777) != 0700) {
         chmod(usersDir.c_str(), 0700);
     }
     return true;
 }
 return mkdir(usersDir.c_str(), 0700) == 0;
}
bool KeyManager::setSecureFilePermissions(const std::string& filepath) const {
return chmod(filepath.c_str(), 0600) == 0;
}
Botan::secure_vector<uint8_t> KeyManager::encryptDataWithUserPass(const Botan::secure_vector<uint8_t>& plaintext) {
return KeyCryptoUtils::encryptData(plaintext, userPasswordSecure);
}
Botan::secure_vector<uint8_t> KeyManager::decryptDataWithUserPass(const Botan::secure_vector<uint8_t>& encrypted) {
return KeyCryptoUtils::decryptData(encrypted, userPasswordSecure);
}

//
bool KeyManager::saveKeysToFile() {
try {
if (!ensureUsersDirectory()) {
log(key_log::LogLevel::Error, key_log::LogEvent::UsersDirCreateFailed, "");
return false;
}
    if (userPasswordSecure.empty()) {
         log(key_log::LogLevel::Error, key_log::LogEvent::UserPasswordNotSet, "");
         return false;
     }

     // Construir el plaintext 
     Botan::secure_vector<uint8_t> allKeysData;
     const uint8_t MAGIC[4] = {'R','B','K','1'};

     for (const auto& pair : keys) {
         const KeyInfo& key = pair.second;

         Botan::secure_vector<uint8_t> blob = key.serialize_secure();
         uint32_t blob_len = static_cast<uint32_t>(blob.size());

         // magic + longitud + blob
         allKeysData.insert(allKeysData.end(), MAGIC, MAGIC + 4);
         allKeysData.push_back(static_cast<uint8_t>((blob_len >> 24) & 0xFF));
         allKeysData.push_back(static_cast<uint8_t>((blob_len >> 16) & 0xFF));
         allKeysData.push_back(static_cast<uint8_t>((blob_len >> 8) & 0xFF));
         allKeysData.push_back(static_cast<uint8_t>(blob_len & 0xFF));
         allKeysData.insert(allKeysData.end(), blob.begin(), blob.end());
     }

     Botan::secure_vector<uint8_t> encrypted = encryptDataWithUserPass(allKeysData);
     // Limpiar el plaintext tan pronto como esté cifrado
     allKeysData.clear();

     if (encrypted.empty()) {
         log(key_log::LogLevel::Error, key_log::LogEvent::EncryptKeysFailed, "");
         return false;
     }
     std::string encryptedB64 = Botan::base64_encode(encrypted);
     encrypted.clear();
     std::string keysFile = getKeysFilePath();
     if (keysFile.empty()) {
         log(key_log::LogLevel::Error, key_log::LogEvent::KeysFileCreateFailed, "");
         return false;
     }
     std::ofstream file(keysFile, std::ios::binary);
     if (!file) {
         log(key_log::LogLevel::Error, key_log::LogEvent::KeysFileCreateFailed, keysFile);
         return false;
     }
     file << encryptedB64;
     file.close();
     setSecureFilePermissions(keysFile);
     return true;
 } catch (const std::exception&) {
     return false;
 }
}

bool KeyManager::loadKeysFromFile() {
try {
std::string keysFile = getKeysFilePath();
if (keysFile.empty()) {
return true;
}
    struct stat buffer;
     if (stat(keysFile.c_str(), &buffer) != 0) {
         return true;
     }
     if ((buffer.st_mode & 0777) != 0600) {
         chmod(keysFile.c_str(), 0600);
     }
     std::ifstream file(keysFile, std::ios::binary);
     if (!file) {
         log(key_log::LogLevel::Error, key_log::LogEvent::KeysFileOpenFailed, keysFile);
         return false;
     }
     std::stringstream bufferStream;
     bufferStream << file.rdbuf();
     file.close();
     std::string encryptedB64 = bufferStream.str();
     if (encryptedB64.empty()) {
         return true;
     }
     Botan::secure_vector<uint8_t> encrypted = Botan::base64_decode(encryptedB64);
     Botan::secure_vector<uint8_t> decrypted = decryptDataWithUserPass(encrypted);
     if (decrypted.empty()) {
         log(key_log::LogLevel::Error, key_log::LogEvent::KeysDecryptFailed, "");
         return false;
     }

     // Parsear directamente desde el secure_vector, sin pasar por std::string
     keys.clear();
     size_t pos = 0;
     const uint8_t MAGIC[4] = {'R','B','K','1'};

     while (pos + 8 <= decrypted.size()) {
         if (memcmp(decrypted.data() + pos, MAGIC, 4) != 0) {
             break;
         }
         pos += 4;

         uint32_t blob_len =
             (static_cast<uint32_t>(decrypted[pos]) << 24) |
             (static_cast<uint32_t>(decrypted[pos + 1]) << 16) |
             (static_cast<uint32_t>(decrypted[pos + 2]) << 8) |
             static_cast<uint32_t>(decrypted[pos + 3]);
         pos += 4;

         if (pos + blob_len > decrypted.size()) break;

         Botan::secure_vector<uint8_t> blob(
             decrypted.begin() + pos,
             decrypted.begin() + pos + blob_len
         );

         KeyInfo key;
         if (key.deserialize_secure(blob)) {
             key.lockMemory();
             keys[key.key_name] = std::move(key);
         }

         pos += blob_len;
     }

     return true;
 } catch (const std::exception&) {
     return false;
 }
}
// ▲▲▲ FIN NUEVO ▲▲▲

// *************************************************************
// KeyManager — ciclo de vida
// *************************************************************
KeyManager::KeyManager() : passwordVerified(false) {}
KeyManager::~KeyManager() {
userPasswordSecure.clear();
password_locker.reset();
}
// *************************************************************
// KeyManager — métodos públicos
// *************************************************************
void KeyManager::setUserPasswordSecure(const Botan::secure_vector<uint8_t>& password) {
userPasswordSecure = password;
if (!userPasswordSecure.empty()) {
    password_locker = std::make_unique<MemoryLC>(const_cast<uint8_t*>(userPasswordSecure.data()), userPasswordSecure.size());
    passwordVerified = true;
}
}
void KeyManager::setUsername(const std::string& name) {
username = name;
if (!userPasswordSecure.empty()) {
loadKeysFromFile();
    for (auto& pair : keys) {
        if (!pair.second.access_code.empty() && !pair.second.memory_locker) {
            pair.second.lockMemory();
        }
    }
}
}
void KeyManager::saveKeys() {
if (!username.empty() && !userPasswordSecure.empty() && !keys.empty()) {
saveKeysToFile();
}
}
bool KeyManager::activateKey(const std::string& keyName, const Botan::secure_vector<uint8_t>& accessCode) {
auto it = keys.find(keyName);
if (it == keys.end()) {
return false;
}
KeyInfo& key = it->second;
 if (key.is_active) {
     return true;
 }
 if (!key.requires_access) {
     key.is_active = true;
     key.last_used = time(nullptr);
     saveKeysToFile();
     return true;
 }
 bool match = (accessCode.size() == key.access_code.size() &&
               secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
 if (!match) {
     return false;
 }
 key.is_active = true;
 key.last_used = time(nullptr);
 if (saveKeysToFile()) {
     return true;
 } else {
     key.is_active = false;
     return false;
 }
}
std::vector<std::string> KeyManager::getActiveKeys() const {
std::vector<std::string> activeKeys;
for (const auto& pair : keys) {
if (pair.second.is_active) {
activeKeys.push_back(pair.first);
}
}
return activeKeys;
}
bool KeyManager::verifyPassword(const Botan::secure_vector<uint8_t>& inputPass) {
if (passwordVerified) {
return true;
}
bool match = (inputPass.size() == userPasswordSecure.size() &&
              secure_memcmp(inputPass.data(), userPasswordSecure.data(), inputPass.size()));
if (match) {
    passwordVerified = true;
    return true;
}
return false;
}
std::string KeyManager::createKey(const std::string& keyName,
const std::string& usage,
Botan::secure_vector<uint8_t> accessCode,
std::string& error_out) {
if (keyName.empty()) {
error_out = "err_key_name_empty";
return "";
}
if (keys.find(keyName) != keys.end()) {
     error_out = "err_key_exists";
     return "";
 }
 if (accessCode.empty()) {
     error_out = "err_key_access_empty";
     return "";
 }
 Botan::secure_vector<uint8_t> keyValue = KeyCryptoUtils::generateRandomBytes(32);
 if (keyValue.empty()) {
     error_out = "err_key_gen_fail";
     return "";
 }
 KeyInfo newKey;
 newKey.key_name = keyName;
 newKey.key_value = std::move(keyValue);
 newKey.key_type = "AES-256";
 newKey.key_usage = usage;
 newKey.created_at = time(nullptr);
 newKey.last_used = 0;
 newKey.is_active = false;
 newKey.strength = 256;
 newKey.access_code = std::move(accessCode);
 newKey.requires_access = true;
 newKey.lockMemory();
 keys[keyName] = std::move(newKey);
 if (!saveKeysToFile()) {
     keys.erase(keyName);
     error_out = "err_key_save_fail";
     return "";
 }
 return keyName;
}
bool KeyManager::deleteKey(const std::string& keyName, const Botan::secure_vector<uint8_t>& accessCode, std::string& error_out) {
auto it = keys.find(keyName);
if (it == keys.end()) {
error_out = "err_key_not_found";
return false;
}
KeyInfo& key = it->second;
if (key.requires_access && !key.access_code.empty()) {
    bool match = (accessCode.size() == key.access_code.size() &&
                  secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
    if (!match) {
        error_out = "err_key_access_incorrect";
        return false;
    }
}
keys.erase(keyName);
if (!saveKeysToFile()) {
    error_out = "err_key_save_fail";
    return false;
}
return true;
}
bool KeyManager::toggleKey(const std::string& keyName, const Botan::secure_vector<uint8_t>& accessCode, std::string& error_out) {
auto it = keys.find(keyName);
if (it == keys.end()) {
error_out = "err_key_not_found";
return false;
}
KeyInfo& key = it->second;
 if (key.is_active) {
     key.is_active = false;
     key.last_used = time(nullptr);
 if (!saveKeysToFile()) {
     error_out = "err_key_save_fail";
     key.is_active = true;
     return false;
     }
     return true;
 }
 if (key.requires_access && !key.access_code.empty()) {
     bool match = (accessCode.size() == key.access_code.size() &&
                   secure_memcmp(accessCode.data(), key.access_code.data(), accessCode.size()));
     if (!match) {
         error_out = "err_key_access_incorrect";
         return false;
     }
 }
 key.is_active = true;
 key.last_used = time(nullptr);
 if (!saveKeysToFile()) {
     error_out = "err_key_save_fail";
     key.is_active = false;
     return false;
 }
 return true;
}
std::string KeyManager::getKeysFilePathPublic() const {
return getKeysFilePath();
}
int KeyManager::activeCount() const {
int c = 0;
for (const auto& p : keys)
if (p.second.is_active)
c++;
return c;
}