#ifndef RUBIC_CORE_H
#define RUBIC_CORE_H

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <ctime>

// Botan 3
#include <botan/pwdhash.h>
#include <botan/base64.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/secmem.h>
#include <botan/dilithium.h>

using namespace std;

#include "keygest/key_manager.h"
#include "share/share_manager.h"
#include "cipher/universal_cipher.h" 
#include "cipher/unit_encryptor.h"

constexpr int SALT_SIZE = 32;
constexpr int KEY_SIZE = 32;
constexpr int IV_SIZE = 12;
constexpr int HASH_SIZE = 32;
constexpr size_t ARGON2_MEMORY = 64 * 1024;
constexpr size_t ARGON2_ITERATIONS = 4;
constexpr size_t ARGON2_PARALLELISM = 4;
constexpr int MASTER_KEY_SIZE = 32;

// ==========================================
// CRASH HANDLER
// ==========================================
class CrashHnd {
  public:
    static void setup();
};

// ==========================================
// LIMPIEZA DE MEMORIA (Templates se quedan en .h)
// ==========================================
inline void secure_z(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) *p++ = 0;
    }
}

template <typename T> inline void secure_c_container(T& container) {
    if (!container.empty()) {
        secure_z(container.data(), container.size() * sizeof(typename T::value_type));
        container.clear();
    }
}

inline bool ct_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

template <typename T> inline bool secure_compare(const T& a, const T& b) {
    if (a.size() != b.size()) return false;
    return ct_compare(reinterpret_cast<const uint8_t*>(a.data()),
                      reinterpret_cast<const uint8_t*>(b.data()),
                      a.size() * sizeof(typename T::value_type));
}

// ==========================================
// UTILIDADES
// ==========================================
namespace XDG {
    string get_xdg_data_home();
    string get_xdg_config_home();
    bool create_dir_recursive(const string& path);
    string get_rubic_data_dir();
    string get_rubic_config_dir();
}

namespace FileUtil {
    bool exists(const string& path);
    bool is_dir(const string& path);
    bool create_dir(const string& path);
    bool create_dir_recursive(const string& path);
    string get_downloads();
    Botan::secure_vector<uint8_t> read_all(const string& path);
    bool write_all(const string& path, const void* data, size_t len);
    bool secure_remove(const string& path);
}

namespace Crypto {
    Botan::secure_vector<uint8_t> rand_bytes(size_t n);
    string b64enc(const uint8_t* data, size_t len);
    Botan::secure_vector<uint8_t> b64dec(const string& s);
    string hex(const uint8_t* data, size_t len);
    Botan::secure_vector<uint8_t> argon2(const Botan::secure_vector<uint8_t>& pass, const Botan::secure_vector<uint8_t>& salt, size_t out_len = KEY_SIZE);
    Botan::secure_vector<uint8_t> combine_keys_hmac(const Botan::secure_vector<uint8_t>& master_key, const Botan::secure_vector<uint8_t>& system_key);
    Botan::secure_vector<uint8_t> get_system_key(const string& context = "");
    Botan::secure_vector<uint8_t> aes_gcm_enc(const Botan::secure_vector<uint8_t>& plain, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& system_key = {});
    Botan::secure_vector<uint8_t> aes_gcm_dec(const Botan::secure_vector<uint8_t>& encrypted, const Botan::secure_vector<uint8_t>& key, const Botan::secure_vector<uint8_t>& system_key = {});
    Botan::secure_vector<uint8_t> gen_master_key();
}

// ==========================================
// DILITHIUM & USUARIOS
// ==========================================
class DiliID {
  private:
    unique_ptr<Botan::Private_Key> priv_key;
    unique_ptr<Botan::Public_Key> pub_key;
    vector<uint8_t> pub_key_enc;
    string fprint;
    bool init = false;
    Botan::AutoSeeded_RNG rng;

  public:
    DiliID() = default;
    bool generate();
    bool loadFromPubKey(const vector<uint8_t>& pub_data);
    bool verify(const vector<uint8_t>& data, const vector<uint8_t>& sig);
    const vector<uint8_t>& getPubKey()const { return pub_key_enc; }
    string getFprint() const { return fprint; }
    bool isInit() const { return init; }
    Botan::secure_vector<uint8_t> getPrivKeyEncoded() const;
};

struct UserRec {
    string name_hash;
    Botan::secure_vector<uint8_t> pwd_hash;
    Botan::secure_vector<uint8_t> salt;
    Botan::secure_vector<uint8_t> enc_name;
    time_t created = 0;
    time_t last_login = 0;
    string algo = "ARGON2";
    int version = 5;
    bool has_id = false;
    vector<uint8_t> id_pub_key;
    Botan::secure_vector<uint8_t> id_priv_key;
    string id_fprint;
    string preferred_lang = "es";

    ~UserRec();
    string serialize() const;
    bool deserialize(const string& data);
};

class UserMgr {
  public:
    struct AuthResult { bool ok = false; std::string error; bool throttled = false; int seconds_left = 0; std::string preferred_lang; };
    struct RegisterResult { bool ok = false; std::string error; bool id_generated = false; std::string id_fingerprint; std::string preferred_lang; };
    struct UserInfo { std::string username; std::string algo; time_t created = 0; time_t last_login = 0; bool has_id = false; std::string id_fprint; };

  private:
    string users_dir;
    string cur_user;
    string cur_user_hash;
    Botan::secure_vector<uint8_t> mast_pwd;
    Botan::secure_vector<uint8_t> mast_key;
    string mast_key_path;
    bool auth = false;
    bool modules_init = false;

    unique_ptr<KeyManager> key_mgr;
    unique_ptr<ShareManager> share_mgr;
    unique_ptr<UniversalCipher> univ_ciph;
    unique_ptr<UnitEncryptor> unit_enc;
    unique_ptr<DiliID> id_mgr;

    struct LoginThrottle {
        map<string, pair<int, time_t>> attempts;
        const int MAX_FAIL = 5;
        const int LOCK_SEC = 300;
        bool can_try(const string& u);
        int wait_time(const string& u);
        void rec_fail(const string& u);
        void rec_success(const string& u) { attempts.erase(u); }
    } throttle;

    void ensure_dirs();
    void init_master_key();
    string hash_user(const string& u);
    string user_path(const string& u_hash);
    string idx_path();
    vector<string> load_idx();
    void save_idx(const vector<string>& users);
    bool user_exists(const string& u_hash);
    void cleanup_modules();
    void init_modules();
    UserRec load_user(const string& u_hash, const string& username, const Botan::secure_vector<uint8_t>& pass);
    bool save_user(const string& username, const UserRec& rec);

  public:
    UserMgr();
    ~UserMgr();
    AuthResult authenticate(const string& user, const Botan::secure_vector<uint8_t>& pass);
    RegisterResult createAccount(const string& user, const Botan::secure_vector<uint8_t>& pass);
    void logout();
    void shutdown();
    UserInfo getUserInfo();
    bool changePassword(const Botan::secure_vector<uint8_t>& old_pass, 
    const Botan::secure_vector<uint8_t>& new_pass, string& error_out);
    bool setPreferredLang(const std::string& lang);
    bool generateIdentity(string& fingerprint_out, string& error_out);
    bool isAuthenticated() const { return auth; }
    string getCurrentUser() const { return cur_user; }
    
    KeyManager* getKeyManager() { return key_mgr.get(); }
    ShareManager* getShareManager() { return share_mgr.get(); }
    UniversalCipher* getUniversalCipher() { return univ_ciph.get(); }
    UnitEncryptor* getUnitEncryptor() { return unit_enc.get(); }
};

#endif // RUBIC_CORE_H