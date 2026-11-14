// src/core/read/read-core.cpp
#include "../../rubic_core.h"
#include <fstream>
#include <sstream>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <algorithm>
#include <filesystem>

// XDG
namespace XDG {
string get_xdg_data_home() {
    const char* xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data && xdg_data[0] != '\0') 
        return string(xdg_data);
    const char* home = getenv("HOME");
    if (home && home[0] != '\0')
        return string(home) + "/.local/share";
    throw std::runtime_error("err_no_data_dir");
}

string get_xdg_config_home() {
    const char* xdg_config = getenv("XDG_CONFIG_HOME");
    if (xdg_config && xdg_config[0] != '\0') 
        return string(xdg_config);
    const char* home = getenv("HOME");
    if (home && home[0] != '\0') 
        return string(home) + "/.config";
    throw std::runtime_error("err_no_config_dir");
}

bool create_dir_recursive(const string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
        return true;string current_path;stringstream ss(path);string segment;
    while (getline(ss, segment, '/')) {
    if (segment.empty()) { current_path = "/"; 
        continue; }
    if (current_path == "/") current_path += segment;
        else current_path += "/" + segment;
    if (stat(current_path.c_str(), &st) != 0) {
    if (mkdir(current_path.c_str(), 0700) != 0) 
        return false;
        }
    }
        return true;
}

string get_rubic_data_dir() {
    string data_dir = get_xdg_data_home() + "/RUBIC-A";
    create_dir_recursive(data_dir);
        return data_dir;
}

string get_rubic_config_dir() {
    string config_dir = get_xdg_config_home() + "/RUBIC-A";
    create_dir_recursive(config_dir);
        return config_dir;
}
} // namespace XDG

// FileUtil
namespace FileUtil {
bool exists(const string& path) { 
    struct stat st; 
        return stat(path.c_str(), &st) == 0; }
bool is_dir(const string& path) { 
    struct stat st; 
        return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode); }
bool create_dir(const string& path) { 
        return mkdir(path.c_str(), 0700) == 0; }
bool create_dir_recursive(const string& path) {
        return XDG::create_dir_recursive(path); }

string get_downloads() {
    const char* home = getenv("HOME");
    if (!home) return ""; vector<string> dirs = {string(home) + "/Descargas", string(home) + "/Downloads"};
    for (const auto& d : dirs) { 
    if (is_dir(d)) return d; }
        return string(home);
}

    Botan::secure_vector<uint8_t> read_all(const string& path) {
    Botan::secure_vector<uint8_t> data;ifstream f(path, ios::binary | ios::ate);
    if (!f) return data;size_t sz = f.tellg(); f.seekg(0);
        data.resize(sz);f.read(reinterpret_cast<char*>(data.data()), sz);
        return data;
}

bool write_all(const string& path, const void* data, size_t len) {
    ofstream f(path, ios::binary);
    if (!f) return false;f.write(static_cast<const char*>(data), len);chmod(path.c_str(), 0600);
        return f.good();
}

bool secure_remove(const string& path) {
    if (!exists(path)) return true;
    struct stat st;
    if (stat(path.c_str(), &st) == 0 && st.st_size > 0) {
        vector<uint8_t> zeros(st.st_size, 0);
        write_all(path, zeros.data(), zeros.size());
    }
        return remove(path.c_str()) == 0;
}
} // namespace FileUtil

// Crypto
namespace Crypto {
        Botan::secure_vector<uint8_t> rand_bytes(size_t n) {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> out(n);rng.randomize(out.data(), n);
        return out;
}
    string b64enc(const uint8_t* data, size_t len) {
        return Botan::base64_encode(data, len); }
    Botan::secure_vector<uint8_t> b64dec(const string& s) {
        return Botan::base64_decode(s); }
    string hex(const uint8_t* data, size_t len) { 
        return Botan::hex_encode(data, len); }

    Botan::secure_vector<uint8_t> argon2(
    const Botan::secure_vector<uint8_t>& pass, 
    const Botan::secure_vector<uint8_t>& salt, size_t out_len) {
          Botan::secure_vector<uint8_t> key(out_len);
    auto pwdhash_fam = Botan::PasswordHashFamily::create("Argon2id");
    if (!pwdhash_fam) return key;
    auto pwdhash = pwdhash_fam->from_params(ARGON2_MEMORY, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
        pwdhash->derive_key(key.data(),key.size(),
        reinterpret_cast<const char*>(pass.data()),pass.size(),salt.data(),salt.size());
        return key;
}
    Botan::secure_vector<uint8_t> combine_keys_hmac(
    const Botan::secure_vector<uint8_t>& master_key, 
    const Botan::secure_vector<uint8_t>& system_key) {
    auto hmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-256)");
   if (!hmac) return master_key;
        hmac->set_key(system_key);
        hmac->update(master_key.data(), master_key.size());
        return hmac->final();
}

    Botan::secure_vector<uint8_t> get_system_key(const string& context) {
    string sys_id = "";
    char hostname[256];
   if (gethostname(hostname, sizeof(hostname)) == 0) sys_id += string(hostname);ifstream machine_id("/etc/machine-id");
   if (machine_id.good()) { string mid; machine_id >> mid; sys_id += "-" + mid; }
        sys_id += "-RUBIC-BIND-" + context;
    auto hash = Botan::HashFunction::create("SHA-256");
   if (!hash) return rand_bytes(32);vector<uint8_t> out(32);
        hash->update(reinterpret_cast<const uint8_t*>(sys_id.data()), sys_id.size());
        hash->final(out.data());
        return Botan::secure_vector<uint8_t>(out.begin(), out.end());
}

     Botan::secure_vector<uint8_t> aes_gcm_enc(
     const Botan::secure_vector<uint8_t>& plain,
     const Botan::secure_vector<uint8_t>& key,
     const Botan::secure_vector<uint8_t>& system_key) {
     auto salt = rand_bytes(SALT_SIZE);
     auto master_key = argon2(key, salt);
     Botan::secure_vector<uint8_t> final_key = master_key;
    if (!system_key.empty()) final_key = combine_keys_hmac(master_key, system_key);
     auto iv = rand_bytes(IV_SIZE);
     auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
    if (!cipher) return {};
        cipher->set_key(final_key);
        cipher->start(iv.data(), iv.size());
     Botan::secure_vector<uint8_t> ct = plain;
        cipher->finish(ct);
     Botan::secure_vector<uint8_t> out;
        out.insert(out.end(), salt.begin(), salt.end());
        out.insert(out.end(), iv.begin(), iv.end());
        out.insert(out.end(), ct.begin(), ct.end());
        return out;
}

     Botan::secure_vector<uint8_t> aes_gcm_dec(
     const Botan::secure_vector<uint8_t>& encrypted,
     const Botan::secure_vector<uint8_t>& key, 
     const Botan::secure_vector<uint8_t>& system_key) {
    if (encrypted.size() < SALT_SIZE + IV_SIZE)
        return {};
     Botan::secure_vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + SALT_SIZE);
     Botan::secure_vector<uint8_t> iv(encrypted.begin() + SALT_SIZE, encrypted.begin() + SALT_SIZE + IV_SIZE);
     Botan::secure_vector<uint8_t> ct(encrypted.begin() + SALT_SIZE + IV_SIZE, encrypted.end());
    auto master_key = argon2(key, salt);
     Botan::secure_vector<uint8_t> final_key = master_key;
    if (!system_key.empty()) final_key = combine_keys_hmac(master_key, system_key);
    auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
    if (!cipher) return {};
        cipher->set_key(final_key);
        cipher->start(iv.data(), iv.size());
    Botan::secure_vector<uint8_t> pt = ct;
    try { 
        cipher->finish(pt);
        return pt; } 
        catch (...) { 
        return {}; }
}
    Botan::secure_vector<uint8_t> gen_master_key() { 
    return rand_bytes(MASTER_KEY_SIZE); }
} // namespace Crypto

// UserRec (Serialización)
UserRec::~UserRec() {
    secure_c_container(pwd_hash); secure_c_container(salt); secure_c_container(enc_name);
    secure_c_container(id_pub_key); secure_c_container(id_priv_key);
}

string UserRec::serialize() const {
    stringstream ss;
    ss << name_hash << "\n" 
       << Crypto::b64enc(pwd_hash.data(), pwd_hash.size()) << "\n"
       << Crypto::b64enc(salt.data(),salt.size()) << "\n"
       << Crypto::b64enc(enc_name.data(),enc_name.size()) << "\n"
       << created << "\n"<< last_login << "\n"<< algo << "\n" << version << "\n" 
       << (has_id ? "1" : "0") << "\n";
    
    if (has_id) {
        ss << Crypto::b64enc(id_pub_key.data(),id_pub_key.size()) << "\n"
           << Crypto::b64enc(id_priv_key.data(),id_priv_key.size()) << "\n" << id_fprint << "\n";
    }
    ss << preferred_lang << "\n";
    return ss.str();  
}

bool UserRec::deserialize(const string& data) {
    stringstream ss(data); string line;
    if (!getline(ss, line)) return false; name_hash = line;
    if (!getline(ss, line)) return false; pwd_hash = Crypto::b64dec(line);
    if (!getline(ss, line)) return false; salt = Crypto::b64dec(line);
    if (!getline(ss, line)) return false; enc_name = Crypto::b64dec(line);
    if (!getline(ss, line)) return false; created = stoll(line);
    if (!getline(ss, line)) return false; last_login = stoll(line);
    if (!getline(ss, line)) return false; algo = line;
    if (!getline(ss, line)) return false; version = stoi(line);
    if (!getline(ss, line)) return false; has_id = (line == "1");
    if (has_id) {
     if (!getline(ss, line)) return false; auto decoded = Crypto::b64dec(line); id_pub_key.assign(decoded.begin(), decoded.end());
     if (!getline(ss, line)) return false; id_priv_key = Crypto::b64dec(line);
     if (!getline(ss, line)) return false; id_fprint = line;
    }
    if (getline(ss, line) && !line.empty()) preferred_lang = line;
    return true;
}

// UserMgr I/O (Persistencia en disco)
void UserMgr::ensure_dirs() {
    users_dir = XDG::get_rubic_data_dir() + "/users";
    if (!FileUtil::is_dir(users_dir)) XDG::create_dir_recursive(users_dir);
    mast_key_path = users_dir + "/.system";
}

void UserMgr::init_master_key() {
    bool key_loaded = false;
    if (FileUtil::exists(mast_key_path)) {
    auto enc_key = FileUtil::read_all(mast_key_path);
    if (enc_key.size() >= SALT_SIZE + IV_SIZE) {
    auto sys_key = Crypto::get_system_key("SYSTEM_ROOT");
    auto decrypted = Crypto::aes_gcm_dec(enc_key, sys_key);
    if (!decrypted.empty() && decrypted.size() == MASTER_KEY_SIZE) { mast_key = decrypted; key_loaded = true; }
    else throw std::runtime_error("err_core_integrity_fail");
        }
    }
    if (!key_loaded) {
    if (FileUtil::exists(idx_path())) 
    throw std::runtime_error("err_core_master_key_missing"); 
    else {
        mast_key = Crypto::gen_master_key();
    auto sys_key = Crypto::get_system_key("SYSTEM_ROOT");
    auto enc_key = Crypto::aes_gcm_enc(mast_key, sys_key);
    if (!enc_key.empty()) FileUtil::write_all(mast_key_path, enc_key.data(), enc_key.size());
    else throw std::runtime_error("err_core_master_key_encrypt");
        }
    }
}

string UserMgr::hash_user(const string& u) {
    auto h = Botan::HashFunction::create("SHA-256");
    if (!h) return "";vector<uint8_t> out(HASH_SIZE);
         h->update(reinterpret_cast<const uint8_t*>(u.data()), u.size());
         h->final(out.data());
        return Crypto::hex(out.data(), out.size());
}
string UserMgr::user_path(const string& u_hash) { 
        return users_dir + "/" + u_hash + ".enc"; }
string UserMgr::idx_path() { 
        return users_dir + "/.idx"; }

vector<string> UserMgr::load_idx() {
    vector<string> users; 
    if (!FileUtil::exists(idx_path())) return users;
    auto enc = FileUtil::read_all(idx_path());
    if (enc.empty()) return users;
    auto dec = Crypto::aes_gcm_dec(enc, mast_key);
    if (dec.empty()) return users;stringstream ss(string(dec.begin(), dec.end())); string u;
    while (getline(ss, u)) { if (!u.empty()) users.push_back(u); }
        return users;
}

void UserMgr::save_idx(const vector<string>& users) {
    stringstream ss; for (const auto& u : users) ss << u << "\n";
    string data = ss.str();
    Botan::secure_vector<uint8_t> pt(data.begin(), data.end());
    auto enc = Crypto::aes_gcm_enc(pt, mast_key); 
    if (!enc.empty()) FileUtil::write_all(idx_path(),enc.data(),enc.size());
}

bool UserMgr::user_exists(const string& u_hash) {
    auto users = load_idx(); 
        return find(users.begin(), users.end(), u_hash) != users.end();
}

UserRec UserMgr::load_user(
     const string& u_hash, const string& username,
     const Botan::secure_vector<uint8_t>& pass) {
      UserRec rec; string path = user_path(u_hash); 
    if (!FileUtil::exists(path)) return rec;
     auto sys_key = Crypto::get_system_key(username);
     auto enc = FileUtil::read_all(path);
     auto dec = Crypto::aes_gcm_dec(enc, pass, sys_key); 
    if (dec.empty()) return rec;
        rec.deserialize(string(dec.begin(),dec.end())); 
        return rec;
}

bool UserMgr::save_user(const string& username, const UserRec& rec) {
     string data = rec.serialize();
    Botan::secure_vector<uint8_t> pt(data.begin(), data.end());
     auto sys_key = Crypto::get_system_key(username);
     auto enc = Crypto::aes_gcm_enc(pt, mast_pwd, sys_key);
    if (enc.empty()) return false;
        return FileUtil::write_all(user_path(rec.name_hash), enc.data(), enc.size());
}
