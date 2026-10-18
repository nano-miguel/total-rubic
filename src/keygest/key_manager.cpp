// keygest/key_manager.cpp - 0.1 alpha
// Implementación de la lógica pura del gestor de claves.
// Los menús viven en ui/key_manager_ui.h
//
// REGLA: este archivo NO formatea texto de presentación.
// Emite eventos estructurados (key_log::LogEvent) y datos crudos.

#include "key_manager.h"

// *************************************************
// KeyCryptoUtils

Botan::secure_vector<uint8_t> KeyCryptoUtils::generateSalt() {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> salt(SALT_SIZE);
        rng.randomize(salt.data(), salt.size());
        return salt;
    } catch (...) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::generateRandomBytes(int bytes) {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> key(bytes);
        rng.randomize(key.data(), key.size());
        return key;
    } catch (...) {
        return Botan::secure_vector<uint8_t>();
    }
}

string KeyCryptoUtils::generateRandomHex(int bytes) {
    try {
        Botan::AutoSeeded_RNG rng;
        vector<uint8_t> key(bytes);
        rng.randomize(key.data(), key.size());
        return Botan::hex_encode(key);
    } catch (...) {
        return "";
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::deriveKey(const Botan::secure_vector<uint8_t>& password,
                                                        const Botan::secure_vector<uint8_t>& salt,
                                                        size_t key_len) {

    try {
        auto argon2_family = Botan::PasswordHashFamily::create("Argon2id");
        if (!argon2_family) {
            return Botan::secure_vector<uint8_t>();
        }

        auto argon2 = argon2_family->from_params(ARGON2_MEMORY_KB, ARGON2_ITERATIONS, ARGON2_PARALLELISM);

        if (!argon2) {
            return Botan::secure_vector<uint8_t>();
        }

        Botan::secure_vector<uint8_t> key(key_len);
        argon2->derive_key(key.data(),
                           key.size(),
                           reinterpret_cast<const char*>(password.data()),
                           password.size(),
                           salt.data(),
                           salt.size());

        return key;
    } catch (...) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::encryptData(const Botan::secure_vector<uint8_t>& plaintext,
                                                          const Botan::secure_vector<uint8_t>& password) {

    try {
        Botan::AutoSeeded_RNG rng;

        Botan::secure_vector<uint8_t> salt = generateSalt();
        if (salt.empty())
            return Botan::secure_vector<uint8_t>();

        Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
        if (key.empty())
            return Botan::secure_vector<uint8_t>();

        Botan::secure_vector<uint8_t> iv(IV_SIZE);
        rng.randomize(iv.data(), iv.size());

        unique_ptr<Botan::Cipher_Mode> cipher =
            Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);

        if (!cipher)
            return Botan::secure_vector<uint8_t>();

        cipher->set_key(key);
        cipher->start(iv.data(), iv.size());

        Botan::secure_vector<uint8_t> ct = plaintext;
        cipher->finish(ct);

        Botan::secure_vector<uint8_t> result;
        result.reserve(salt.size() + iv.size() + ct.size());
        result.insert(result.end(), salt.begin(), salt.end());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ct.begin(), ct.end());

        return result;
    } catch (...) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::decryptData(const Botan::secure_vector<uint8_t>& encrypted,
                                                          const Botan::secure_vector<uint8_t>& password) {

    try {
        if (encrypted.size() < SALT_SIZE + IV_SIZE) {
            return Botan::secure_vector<uint8_t>();
        }

        Botan::secure_vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + SALT_SIZE);
        Botan::secure_vector<uint8_t> iv(encrypted.begin() + SALT_SIZE, encrypted.begin() + SALT_SIZE + IV_SIZE);
        Botan::secure_vector<uint8_t> ct(encrypted.begin() + SALT_SIZE + IV_SIZE, encrypted.end());

        Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
        if (key.empty())
            return Botan::secure_vector<uint8_t>();

        unique_ptr<Botan::Cipher_Mode> cipher =
            Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);

        if (!cipher)
            return Botan::secure_vector<uint8_t>();

        cipher->set_key(key);
        cipher->start(iv.data(), iv.size());

        Botan::secure_vector<uint8_t> pt = ct;
        cipher->finish(pt);

        return pt;
    } catch (...) {
        return Botan::secure_vector<uint8_t>();
    }
}

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
        memory_locker = make_unique<MemoryLC>(ptr, access_code.size());
    }
}

void KeyInfo::unlockMemory() const {
    memory_locker.reset();
}

// *****************************************************
// KeyInfo — serialización

string KeyInfo::serialize() const {
    stringstream ss;
    ss << key_name << "\n";
    ss << Botan::hex_encode(key_value) << "\n";
    ss << key_type << "\n";
    ss << key_usage << "\n";
    ss << created_at << "\n";
    ss << last_used << "\n";
    ss << (is_active ? "1" : "0") << "\n";
    ss << strength << "\n";

    string accessB64 = Botan::base64_encode(access_code);
    ss << accessB64 << "\n";

    ss << (requires_access ? "1" : "0");
    return ss.str();
}

bool KeyInfo::deserialize(const string& data) {
    try {
        stringstream ss(data);
        string line;

        if (!getline(ss, key_name))
            return false;
        if (!getline(ss, line))
            return false;

        auto decoded_key = Botan::hex_decode(line);
        key_value.assign(decoded_key.begin(), decoded_key.end());

        if (!getline(ss, key_type))
            return false;
        if (!getline(ss, key_usage))
            return false;

        if (!getline(ss, line))
            return false;
        created_at = stol(line);

        if (!getline(ss, line))
            return false;
        last_used = stol(line);

        if (!getline(ss, line))
            return false;
        is_active = (line == "1");

        if (!getline(ss, line))
            return false;
        strength = stoi(line);

        if (!getline(ss, line))
            return false;
        access_code = Botan::base64_decode(line);

        if (!getline(ss, line))
            return false;
        requires_access = (line == "1");

        return true;
    } catch (...) {
        return false;
    }
}

// *************************************************************
// KeyManager — helpers privados

string KeyManager::getKeysFilePath() const {
    string data_dir_users;
    const char* xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data && xdg_data[0] != '\0') {
        data_dir_users = string(xdg_data) + "/RUBIC-A/users";
    } else {
        const char* home = getenv("HOME");
        if (home && home[0] != '\0') {
            data_dir_users = string(home) + "/.local/share/RUBIC-A/users";
        } else {
            return "";
        }
    }

    struct stat st;
    if (stat(data_dir_users.c_str(), &st) != 0) {
        string current_path;
        stringstream ss(data_dir_users);
        string segment;
        while (getline(ss, segment, '/')) {
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
    string usersDir;
    const char* xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data && xdg_data[0] != '\0') {
        usersDir = string(xdg_data) + "/RUBIC-A/users";
    } else {
        const char* home = getenv("HOME");
        if (home && home[0] != '\0') {
            usersDir = string(home) + "/.local/share/RUBIC-A/users";
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

bool KeyManager::setSecureFilePermissions(const string& filepath) const {
    return chmod(filepath.c_str(), 0600) == 0;
}

Botan::secure_vector<uint8_t> KeyManager::encryptDataWithUserPass(const Botan::secure_vector<uint8_t>& plaintext) {
    return KeyCryptoUtils::encryptData(plaintext, userPasswordSecure);
}

Botan::secure_vector<uint8_t> KeyManager::decryptDataWithUserPass(const Botan::secure_vector<uint8_t>& encrypted) {
    return KeyCryptoUtils::decryptData(encrypted, userPasswordSecure);
}

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

        stringstream allKeysData;
        for (const auto& pair : keys) {
            const KeyInfo& key = pair.second;
            allKeysData << "=== KEY START ===\n";
            allKeysData << key.serialize();
            allKeysData << "\n=== KEY END ===\n\n";
        }

        string keysData = allKeysData.str();

        Botan::secure_vector<uint8_t> pt_secure(keysData.begin(), keysData.end());

        Botan::secure_vector<uint8_t> encrypted = encryptDataWithUserPass(pt_secure);
        if (encrypted.empty()) {
            log(key_log::LogLevel::Error, key_log::LogEvent::EncryptKeysFailed, "");
            return false;
        }

        string encryptedB64 = Botan::base64_encode(encrypted);

        string keysFile = getKeysFilePath();
        if (keysFile.empty()) {
            log(key_log::LogLevel::Error, key_log::LogEvent::KeysFileCreateFailed, "");
            return false;
        }

        ofstream file(keysFile, ios::binary);
        if (!file) {
            log(key_log::LogLevel::Error, key_log::LogEvent::KeysFileCreateFailed, keysFile);
            return false;
        }

        file << encryptedB64;
        file.close();

        setSecureFilePermissions(keysFile);

        return true;
    } catch (...) {
        return false;
    }
}

bool KeyManager::loadKeysFromFile() {
    try {
        string keysFile = getKeysFilePath();
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

        ifstream file(keysFile, ios::binary);
        if (!file) {
            log(key_log::LogLevel::Error, key_log::LogEvent::KeysFileOpenFailed, keysFile);
            return false;
        }

        stringstream bufferStream;
        bufferStream << file.rdbuf();
        file.close();

        string encryptedB64 = bufferStream.str();
        if (encryptedB64.empty()) {
            return true;
        }

        Botan::secure_vector<uint8_t> encrypted = Botan::base64_decode(encryptedB64);

        Botan::secure_vector<uint8_t> decrypted = decryptDataWithUserPass(encrypted);
        if (decrypted.empty()) {
            log(key_log::LogLevel::Error, key_log::LogEvent::KeysDecryptFailed, "");
            return false;
        }

        string decryptedStr(decrypted.begin(), decrypted.end());

        keys.clear();
        stringstream ss(decryptedStr);
        string line;
        string currentKeyData;
        bool readingKey = false;

        while (getline(ss, line)) {
            if (line == "=== KEY START ===") {
                readingKey = true;
                currentKeyData.clear();
            } else if (line == "=== KEY END ===") {
                readingKey = false;

                KeyInfo key;
                if (key.deserialize(currentKeyData)) {
                    keys[key.key_name] = std::move(key);
                }

                currentKeyData.clear();
            } else if (readingKey) {
                if (!currentKeyData.empty()) {
                    currentKeyData += "\n";
                }
                currentKeyData += line;
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

// *************************************************************
// KeyManager — ciclo de vida

KeyManager::KeyManager() : passwordVerified(false) {}

KeyManager::~KeyManager() {
    userPasswordSecure.clear();
    password_locker.reset();
}

// *************************************************************
// KeyManager — métodos públicos

void KeyManager::setUserPasswordSecure(const Botan::secure_vector<uint8_t>& password) {
    userPasswordSecure = password;

    if (!userPasswordSecure.empty()) {
        password_locker =
            make_unique<MemoryLC>(const_cast<uint8_t*>(userPasswordSecure.data()), userPasswordSecure.size());
        passwordVerified = true;
    }
}

void KeyManager::setUsername(const string& name) {
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

bool KeyManager::activateKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode) {
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

vector<string> KeyManager::getActiveKeys() const {
    vector<string> activeKeys;
    for (const auto& pair : keys) {
        if (pair.second.is_active) {
            activeKeys.push_back(pair.first);
        }
    }
    return activeKeys;
}

bool KeyManager::verifyPassword(const Botan::secure_vector<uint8_t>& inputPass) {
    if (passwordVerified)
        return true;

    bool match = (inputPass.size() == userPasswordSecure.size() &&
                  secure_memcmp(inputPass.data(), userPasswordSecure.data(), inputPass.size()));

    if (match) {
        passwordVerified = true;
        return true;
    }
    return false;
}

string KeyManager::createKey(const string& keyName,
                             const string& usage,
                             Botan::secure_vector<uint8_t> accessCode,
                             string& error_out) {
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

    // LA MAGIA ESTÁ AQUÍ: std::move transfiere el secure_vector sin copiarlo
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

bool KeyManager::deleteKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode, string& error_out) {
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

bool KeyManager::toggleKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode, string& error_out) {
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

string KeyManager::getKeysFilePathPublic() const {
    return getKeysFilePath();
}

int KeyManager::activeCount() const {
    int c = 0;
    for (const auto& p : keys)
        if (p.second.is_active)
            c++;
    return c;
}