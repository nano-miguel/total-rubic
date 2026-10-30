// keygest/key_manager.h 
// Lógica  del gestor de claves.
#ifndef KEYGEST_KEY_MANAGER_H
#define KEYGEST_KEY_MANAGER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <memory>
#include <functional>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <thread>
#include <fcntl.h>
#include <botan/pwdhash.h>
#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/secmem.h>
#include <botan/hash.h>

using namespace std;

// COMPARACION SEGURA

inline bool secure_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}


// EVENTOS ESTRUCTURADOS DEL KEY MANAG

namespace key_log {
enum class LogLevel { Info, Warning, Error, Success };
enum class LogEvent {
    UsersDirCreateFailed,
    KeysFileCreateFailed,
    KeysFileOpenFailed,
    UserPasswordNotSet,
    EncryptKeysFailed,
    KeysDecryptFailed
};
}

// CRYPTO ARGON2id

class KeyCryptoUtils {
public:
    static constexpr int ARGON2_MEMORY_KB = 65536;
    static constexpr int ARGON2_ITERATIONS = 3;
    static constexpr int ARGON2_PARALLELISM = 1;
    static constexpr int SALT_SIZE = 32;
    static constexpr int KEY_SIZE = 32;
    static constexpr int IV_SIZE = 12;

    static Botan::secure_vector<uint8_t> generateSalt();
    static Botan::secure_vector<uint8_t> generateRandomBytes(int bytes = 32);
    static std::string generateRandomHex(int bytes = 32);

    static Botan::secure_vector<uint8_t> deriveKey(
        const Botan::secure_vector<uint8_t>& password,
        const Botan::secure_vector<uint8_t>& salt,
        size_t key_len = KEY_SIZE);

    static Botan::secure_vector<uint8_t> encryptData(
        const Botan::secure_vector<uint8_t>& plaintext,
        const Botan::secure_vector<uint8_t>& password);

    static Botan::secure_vector<uint8_t> decryptData(
        const Botan::secure_vector<uint8_t>& encrypted,
        const Botan::secure_vector<uint8_t>& password);

    static bool isArgon2Available() {
        try {
            auto family = Botan::PasswordHashFamily::create("Argon2id");
            return family != nullptr;
        }   catch (...) {
            return false;
        }
    }
};

// ESTRUCTURA Key

struct KeyInfo {
    std::string key_name;
    Botan::secure_vector<uint8_t> key_value;
    std::string key_type;
    std::string key_usage;
    time_t created_at;
    time_t last_used;
    bool is_active;
    int strength;
    Botan::secure_vector<uint8_t> access_code;
    bool requires_access;

    // Ciclo de vida (implementado en key_manager.cpp)
    KeyInfo();
    KeyInfo(const KeyInfo& other);
    KeyInfo(KeyInfo&& other) noexcept;

    KeyInfo& operator=(const KeyInfo& other);
    KeyInfo& operator=(KeyInfo&& other) noexcept;

    ~KeyInfo();

    // Formato binario (implementado en key_pipeline.cpp — es infraestructura,
    // no dominio: describe cómo se escribe en disco, no qué es una clave)
    Botan::secure_vector<uint8_t> serialize_secure() const;
    bool deserialize_secure(const Botan::secure_vector<uint8_t>& data);
};

// CLASE PRINCIPAL DEL GESTOR DE CLAVES

class KeyManager {

public:
    using LogCallback = std::function<void(
        key_log::LogLevel level,
        key_log::LogEvent event,
        const std::string& data)>;

private:
    std::string username;
    Botan::secure_vector<uint8_t> userPasswordSecure;
    std::map<std::string, KeyInfo> keys;

    bool passwordVerified;
    LogCallback log_cb_;

    void log(key_log::LogLevel level, key_log::LogEvent event,
             const std::string& data = "") {
         if(log_cb_)
            log_cb_(level, event, data);
    }

    // Helpers privados (cuerpos en key_manager.cpp)
    std::string getKeysFilePath() const;
    bool ensureUsersDirectory() const;
    bool setFilePermissions(const std::string& filepath) const;

    // Persistencia: delegan en key_persist::save/load (key_pipeline.cpp)
    bool saveKeysToFile();
    bool loadKeysFromFile();

public:
    KeyManager();
    ~KeyManager();

    void setLogCallback(LogCallback cb) { log_cb_ = std::move(cb); }

    void setUserPasswordSecure(const Botan::secure_vector<uint8_t>& password);
    void setUsername(const std::string& name);
    void saveKeys();

    const std::map<std::string, KeyInfo>& getKeys() const { return keys; }

    bool hasKey(const std::string& keyName) const {
        return keys.find(keyName) != keys.end();
    }

    bool isKeyActive(const std::string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end() && it->second.is_active;
    }

    Botan::secure_vector<uint8_t> getKeyValue(const std::string& keyName) const {
        auto it = keys.find(keyName);
        if (it != keys.end() && it->second.is_active) {
        return it->second.key_value;
        }
        return Botan::secure_vector<uint8_t>();
    }

    bool activateKey(const std::string& keyName,
                     const Botan::secure_vector<uint8_t>& accessCode);

    bool keyRequiresActivation(const std::string& keyName) const {
        auto it = keys.find(keyName);
        if (it == keys.end()) return false;
        return it->second.requires_access;
    }

    bool hasKeys() const { return !keys.empty(); }

    std::vector<std::string> getActiveKeys() const;

    void resetVerification() { passwordVerified = false; }

    static bool isArgon2Available() {
        return KeyCryptoUtils::isArgon2Available();
    }

    // MÉTODOS PÚBLICOS PARA LA UI

    bool verifyPassword(const Botan::secure_vector<uint8_t>& inputPass);
    bool isPasswordVerified() const { return passwordVerified; }

    std::string createKey(const std::string& keyName,
                          const std::string& usage,
                          Botan::secure_vector<uint8_t> accessCode,
                          std::string& error_out);

    bool deleteKey(const std::string& keyName,
                   const Botan::secure_vector<uint8_t>& accessCode,
                   std::string& error_out);

    bool toggleKey(const std::string& keyName,
                   const Botan::secure_vector<uint8_t>& accessCode,
                   std::string& error_out);

    std::string getKeysFilePathPublic() const;
    std::string getUsername() const { return username; }

    size_t keyCount() const { return keys.size(); }
    int activeCount() const;

    const KeyInfo* getKeyInfo(const std::string& keyName) const {
        auto it = keys.find(keyName);

        if (it == keys.end()) return nullptr;
        return &it->second;
    }
};

/* 
// Persistencia en disco (implementado en key_pipeline.cpp)
//   save: serialize → compress(zlib) → encrypt(Argon2id+GCM) → write atómico
//   load: read → decrypt → decompress → deserialize
*/ 
namespace key_persist {
bool save(const std::map<std::string, KeyInfo>& keys,
          const std::string& filepath,
          const Botan::secure_vector<uint8_t>& user_password);

bool load(const std::string& filepath,
          std::map<std::string, KeyInfo>& out_keys,
          const Botan::secure_vector<uint8_t>& user_password);
} // namespace key_persist

#endif // KEYGEST_KEY_MANAGER_H
