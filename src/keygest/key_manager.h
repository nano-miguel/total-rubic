// keygest/key_manager.h - 0.1 alpha
// Lógica pura del gestor de claves.
// rubic gpl3v

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
#include <sys/mman.h>
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

// ***********************************************
// CLASE  MLOCK PROTECION DE MEMORIA //

class MemoryLC {
  private:
    void* ptr;
    size_t size;
    bool locked;

  public:
    MemoryLC() : ptr(nullptr), size(0), locked(false) {}

    explicit MemoryLC(void* memory_ptr, size_t memory_size) : ptr(memory_ptr), size(memory_size), locked(false) {
        if (ptr && size > 0) {
            if (mlock(ptr, size) == 0) {
                locked = true;
            }
        }
    }

    MemoryLC(const MemoryLC&) = delete;
    MemoryLC& operator=(const MemoryLC&) = delete;

    MemoryLC(MemoryLC&& other) noexcept : ptr(other.ptr), size(other.size), locked(other.locked) {
        other.ptr = nullptr;
        other.size = 0;
        other.locked = false;
    }

    MemoryLC& operator=(MemoryLC&& other) noexcept {
        if (this != &other) {
            unlock();
            ptr = other.ptr;
            size = other.size;
            locked = other.locked;
            other.ptr = nullptr;
            other.size = 0;
            other.locked = false;
        }
        return *this;
    }

    void unlock() {
        if (locked && ptr && size > 0) {
            munlock(ptr, size);
            locked = false;
        }
    }

    ~MemoryLC() {
        unlock();
    }

    bool isLocked() const {
        return locked;
    }
};

// ************************************
// COMPARACION //
inline bool secure_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= (a[i] ^ b[i]);
    }
    return result == 0;
}

//  eventos estructurados del key manager
namespace key_log {

enum class LogLevel { Info, Warning, Error, Success };

enum class LogEvent {
    // Archivos / directorios
    UsersDirCreateFailed,
    KeysFileCreateFailed,
    KeysFileOpenFailed,

    // Cifrado / contraseña
    UserPasswordNotSet,
    EncryptKeysFailed,
    KeysDecryptFailed
};

} // namespace key_log

// *************************************************
// CRYPTO ARGON2ID //

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
    static string generateRandomHex(int bytes = 32);

    static Botan::secure_vector<uint8_t> deriveKey(const Botan::secure_vector<uint8_t>& password,
                                                   const Botan::secure_vector<uint8_t>& salt,
                                                   size_t key_len = KEY_SIZE);

    static Botan::secure_vector<uint8_t> encryptData(const Botan::secure_vector<uint8_t>& plaintext,
                                                     const Botan::secure_vector<uint8_t>& password);

    static Botan::secure_vector<uint8_t> decryptData(const Botan::secure_vector<uint8_t>& encrypted,
                                                     const Botan::secure_vector<uint8_t>& password);

    static bool isArgon2Available() {
        try {
            auto family = Botan::PasswordHashFamily::create("Argon2id");
            return family != nullptr;
        } catch (...) {
            return false;
        }
    }
};

// *****************************************************
// Estructura para almacenar información de claves //

struct KeyInfo {
    string key_name;
    Botan::secure_vector<uint8_t> key_value;
    string key_type;
    string key_usage;
    time_t created_at;
    time_t last_used;
    bool is_active;
    int strength;
    Botan::secure_vector<uint8_t> access_code;
    bool requires_access;

    mutable unique_ptr<MemoryLC> memory_locker;

    // *****************************************
    // Ciclo de vida

    KeyInfo();
    KeyInfo(const KeyInfo& other);
    KeyInfo(KeyInfo&& other) noexcept;
    KeyInfo& operator=(const KeyInfo& other);
    KeyInfo& operator=(KeyInfo&& other) noexcept;
    ~KeyInfo();

    void lockMemory() const;
    void unlockMemory() const;

    string serialize() const;
    bool deserialize(const string& data);
};

// *************************************************
// CLASE PRINCIPAL DEL GESTOR DE CLAVES (sin UI) //

class KeyManager {
  public:
    using LogCallback = std::function<void(key_log::LogLevel level, key_log::LogEvent event, const std::string& data)>;

  private:
    string username;
    Botan::secure_vector<uint8_t> userPasswordSecure;
    map<string, KeyInfo> keys;
    bool passwordVerified;

    unique_ptr<MemoryLC> password_locker;
    LogCallback log_cb_;

    // ▼▼▼ Helper de log con eventos estructurados ▼▼▼
    void log(key_log::LogLevel level, key_log::LogEvent event, const std::string& data = "") {
        if (log_cb_)
            log_cb_(level, event, data);
    }
    // ▲▲▲

    // Helpers privados (cuerpos en .cpp)
    string getKeysFilePath() const;
    bool ensureUsersDirectory() const;
    bool setSecureFilePermissions(const string& filepath) const;

    Botan::secure_vector<uint8_t> encryptDataWithUserPass(const Botan::secure_vector<uint8_t>& plaintext);
    Botan::secure_vector<uint8_t> decryptDataWithUserPass(const Botan::secure_vector<uint8_t>& encrypted);

    bool saveKeysToFile();
    bool loadKeysFromFile();

  public:
    KeyManager();
    ~KeyManager();

    void setLogCallback(LogCallback cb) {
        log_cb_ = std::move(cb);
    }

    void setUserPasswordSecure(const Botan::secure_vector<uint8_t>& password);
    void setUsername(const string& name);

    void saveKeys();

    const map<string, KeyInfo>& getKeys() const {
        return keys;
    }

    bool hasKey(const string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end();
    }

    bool isKeyActive(const string& keyName) const {
        auto it = keys.find(keyName);
        return it != keys.end() && it->second.is_active;
    }

    Botan::secure_vector<uint8_t> getKeyValue(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it != keys.end() && it->second.is_active) {
            return it->second.key_value;
        }
        return Botan::secure_vector<uint8_t>();
    }

    bool activateKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode);

    bool keyRequiresActivation(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it == keys.end()) {
            return false;
        }
        return it->second.requires_access;
    }

    bool hasKeys() const {
        return !keys.empty();
    }

    vector<string> getActiveKeys() const;

    void resetVerification() {
        passwordVerified = false;
    }

    static bool isArgon2Available() {
        return KeyCryptoUtils::isArgon2Available();
    }

    //************************************************
    // MÉTODOS PÚBLICOS PARA LA UI

    bool verifyPassword(const Botan::secure_vector<uint8_t>& inputPass);

    bool isPasswordVerified() const {
        return passwordVerified;
    }

    string
    createKey(const string& keyName, const string& usage, Botan::secure_vector<uint8_t> accessCode, string& error_out);

    bool deleteKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode, string& error_out);

    bool toggleKey(const string& keyName, const Botan::secure_vector<uint8_t>& accessCode, string& error_out);

    string getKeysFilePathPublic() const;
    string getUsername() const {
        return username;
    }

    size_t keyCount() const {
        return keys.size();
    }
    int activeCount() const;

    const KeyInfo* getKeyInfo(const string& keyName) const {
        auto it = keys.find(keyName);
        if (it == keys.end())
            return nullptr;
        return &it->second;
    }
};

#endif // KEYGEST_KEY_MANAGER_H