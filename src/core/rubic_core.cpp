// src/core/rubic_core.cpp
#include "../rubic_core.h"
#include <stdexcept>
#include <signal.h>
#include <unistd.h>
#include <cstring>

// Botan extra para DiliID
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/data_src.h>

// ==========================================
// CRASH HANDLER
// ==========================================
void CrashHnd::setup() {
    struct sigaction sa;sa.sa_handler = [](int sig) {
    const char* msg = "\n\x1b[91m✗ CRASH: Limpiando memoria segura...\x1b[0m\n";
    if (write(STDERR_FILENO, msg, strlen(msg)) < 0) {}
    signal(sig, SIG_DFL);raise(sig);
    };
    sigemptyset(&sa.sa_mask);sa.sa_flags = SA_RESETHAND;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
}

// ==========================================
// DiliID
// ==========================================
bool DiliID::generate() {
    try {
    Botan::DilithiumMode mode("Dilithium-6x5-AES-r3");
    Botan::Dilithium_PrivateKey priv(rng, mode);
        priv_key = make_unique<Botan::Dilithium_PrivateKey>(priv);
        pub_key = make_unique<Botan::Dilithium_PublicKey>(priv);
        pub_key_enc = Botan::X509::BER_encode(*pub_key);
    auto hash = Botan::HashFunction::create("SHA-256");
        vector<uint8_t> h(32);
        hash->update(pub_key_enc);
        hash->final(h.data());
        fprint = Botan::hex_encode(h.data(), 16);init = true;
        return true;
    }   catch (...) {
        return false; }
}

bool DiliID::loadFromPubKey(
    const vector<uint8_t>& pub_data) {
    try {
        Botan::DataSource_Memory src(pub_data);pub_key = Botan::X509::load_key(src);pub_key_enc = pub_data;
    auto hash = Botan::HashFunction::create("SHA-256");
        vector<uint8_t> h(32);hash->update(pub_data); hash->final(h.data());
        fprint = Botan::hex_encode(h.data(), 16);
        init = true;
        return true;
    }   catch (...) { 
        return false; }
}

bool DiliID::verify(
    const vector<uint8_t>& data,
    const vector<uint8_t>& sig) {
    if (!init || !pub_key)
       return false;
    try { Botan::PK_Verifier verifier(*pub_key, "SHA-512");
       return verifier.verify_message(data, sig); } 
       catch (...) {
       return false; }
}

Botan::secure_vector<uint8_t> DiliID::getPrivKeyEncoded() 
const {
    if (!priv_key) 
       return {};
    try { 
        return Botan::PKCS8::BER_encode(*priv_key); } 
        catch (...) { 
        return {}; }
}

// ==========================================
// UserMgr (Lógica de Negocio Pura)
// ==========================================
bool UserMgr::LoginThrottle::can_try(const string& u) {
    auto it = attempts.find(u);
    if (it == attempts.end())
        return true;
    if (it->second.second > time(nullptr)) 
        return false;
        return true;
}

int UserMgr::LoginThrottle::wait_time(
    const string& u) {
    auto it = attempts.find(u);
    if (it == attempts.end())
        return 0;
        return max(0L, it->second.second - time(nullptr));
}

void UserMgr::LoginThrottle::rec_fail(
    const string& u) {
    auto& a = attempts[u];a.first++;
    if (a.first >= MAX_FAIL) a.second = time(nullptr) + LOCK_SEC;
}

UserMgr::UserMgr() { 
    ensure_dirs();
    init_master_key(); 
}

UserMgr::~UserMgr() { 
    cleanup_modules();
    secure_c_container(mast_pwd);
    secure_c_container(mast_key); 
}

void UserMgr::cleanup_modules() {
    if (key_mgr) key_mgr->saveKeys();
        unit_enc.reset(); 
        univ_ciph.reset();
        share_mgr.reset();
        id_mgr.reset();
        key_mgr.reset(); modules_init = false;
}

void UserMgr::init_modules() {
    if (modules_init) cleanup_modules();
        key_mgr = make_unique<KeyManager>(); 
        share_mgr = make_unique<ShareManager>();
        univ_ciph = make_unique<UniversalCipher>(); 
        unit_enc = make_unique<UnitEncryptor>(); 
        id_mgr = make_unique<DiliID>();

        key_mgr->setUserPasswordSecure(mast_pwd);
        key_mgr->setUsername(cur_user);
        univ_ciph->setKeyManager(key_mgr.get());
        unit_enc->setKeyManager(key_mgr.get());

    if (share_mgr) 
        share_mgr->setUsername(cur_user);UserRec rec = load_user(cur_user_hash, cur_user, mast_pwd);
    if (rec.has_id && ! rec.id_pub_key.empty()) {
        id_mgr->loadFromPubKey(rec.id_pub_key);
        std::vector<uint8_t> priv_vec(
        rec.id_priv_key.begin(),
        rec.id_priv_key.end());
        share_mgr->setIdentity(
        rec.id_pub_key, priv_vec,
        rec.id_fprint);
        secure_z(priv_vec.data(), priv_vec.size());
    }
    modules_init = true;
}

UserMgr::AuthResult UserMgr::authenticate(
     const string& user,
     const Botan::secure_vector<uint8_t>& pass) {
     AuthResult result; string user_hash = hash_user(user);
    if (!throttle.can_try(user_hash)) { 
         result.throttled = true;
         result.seconds_left = throttle.wait_time(user_hash);
         result.error = "err_user_blocked"; 
        return result; }
    if (!user_exists(user_hash)) {
         throttle.rec_fail(user_hash); 
         result.error = "err_user_not_found";
        return result; }
    auto rec = load_user(user_hash, user, pass);
    if (rec.name_hash.empty()) { 
         throttle.rec_fail(user_hash);
         result.error = "err_credentials_invalid"; 
        return result; }
    auto computed = Crypto::argon2(pass,
         rec.salt);
    bool pwd_ok = secure_compare(computed,
         rec.pwd_hash); secure_c_container(computed);
    if (!pwd_ok) { throttle.rec_fail(user_hash);
         result.error = "err_pwd_incorrect";
        return result; }
         throttle.rec_success(user_hash);
         rec.last_login = time(nullptr); mast_pwd = pass;
        save_user(user, rec);cur_user = user; cur_user_hash = user_hash; auth = true;init_modules();
         result.preferred_lang = rec.preferred_lang;
         result.ok = true; 
        return result;
}

UserMgr::RegisterResult UserMgr::createAccount(
    const string& user,
    const Botan::secure_vector<uint8_t>& pass) {
         RegisterResult result;
    if (user.empty()) { 
        result.error = "err_user_empty";
        return result; }
        string user_hash = hash_user(user);
    if (user_exists(user_hash)) { 
         result.error = "err_user_exists";
        return result; }
         UserRec rec; 
         
         rec.name_hash = user_hash; 
         rec.salt = Crypto::rand_bytes(SALT_SIZE);
         rec.pwd_hash = Crypto::argon2(pass, rec.salt);
        Botan::secure_vector<uint8_t> name_vec(user.begin(), user.end()); 
         rec.enc_name = Crypto::aes_gcm_enc(name_vec, pass);
         rec.created = time(nullptr); 
         rec.last_login = time(nullptr);DiliID temp_id;
    if (temp_id.generate()) {
         rec.id_pub_key = temp_id.getPubKey();
         rec.id_priv_key = temp_id.getPrivKeyEncoded();
         rec.id_fprint = temp_id.getFprint(); 
         rec.has_id = true;
         result.id_generated = true;
         result.id_fingerprint = rec.id_fprint;
    }
    mast_pwd = pass;
    if (!save_user(user, rec)) { 
        result.error = "err_save_failed"; secure_c_container(mast_pwd); 
        return result; }
    auto users = load_idx();
        users.push_back(user_hash); save_idx(users);cur_user = user; cur_user_hash = user_hash; auth = true; init_modules();
        result.preferred_lang = rec.preferred_lang; 
        result.ok = true; 
        return result;
}

void UserMgr::logout() { cleanup_modules();
        secure_c_container(mast_pwd); auth = false; 
        cur_user.clear();
        cur_user_hash.clear(); }
void UserMgr::shutdown() { cleanup_modules();
        secure_c_container(mast_pwd);
        secure_c_container(mast_key); }

UserMgr::UserInfo UserMgr::getUserInfo() {
    UserInfo info;
    auto rec = load_user(cur_user_hash, cur_user, mast_pwd); 
    if (rec.name_hash.empty()) 
        return info;
          info.username = cur_user;
          info.algo = rec.algo;
          info.created = rec.created;
          info.last_login = rec.last_login;
          info.has_id = rec.has_id;
          info.id_fprint = rec.id_fprint;
        return info;
}

bool UserMgr::changePassword(
    const Botan::secure_vector<uint8_t>& old_pass,
    const Botan::secure_vector<uint8_t>& new_pass, string& error_out) {
    auto rec = load_user(cur_user_hash, cur_user, old_pass);
    if (rec.name_hash.empty()) { error_out = "err_pwd_incorrect"; 
        return false; }
         rec.salt = Crypto::rand_bytes(SALT_SIZE);
         rec.pwd_hash = Crypto::argon2(new_pass, 
         rec.salt);
    auto old_pwd_backup = std::move(mast_pwd); mast_pwd = new_pass;
    if (save_user(cur_user, rec)) { 
    if (key_mgr) key_mgr->setUserPasswordSecure(mast_pwd);
        secure_c_container(old_pwd_backup);
        return true; }
        else { mast_pwd = std::move(old_pwd_backup); error_out = "err_save_failed";
        return false; }
}

bool UserMgr::setPreferredLang(const std::string& lang) {
    if (!auth) 
        return false; auto rec = load_user(cur_user_hash, cur_user, mast_pwd);
    if (rec.name_hash.empty()) 
        return false;
         rec.preferred_lang = lang; 
        return save_user(cur_user, rec);
}

bool UserMgr::generateIdentity(string& fingerprint_out, string& error_out) {
    DiliID temp_id; 
    if (!temp_id.generate()) { error_out = "err_id_gen_failed";
         return false; }
    auto rec = load_user(cur_user_hash, cur_user, mast_pwd); 
    if (rec.name_hash.empty()) { error_out = "err_user_load_failed";
         return false; }
         rec.id_pub_key = temp_id.getPubKey();
         rec.id_priv_key = temp_id.getPrivKeyEncoded(); 
         rec.id_fprint = temp_id.getFprint(); 
         rec.has_id = true;
    if (!save_user(cur_user, rec)) { error_out = "err_id_save_failed";
         return false; }
    id_mgr->loadFromPubKey(rec.id_pub_key);
    if (share_mgr) {
        std::vector<uint8_t> priv_vec2(
          rec.id_priv_key.begin(),
          rec.id_priv_key.end());
          share_mgr->setIdentity(
          rec.id_pub_key, priv_vec2, 
          rec.id_fprint); secure_z(priv_vec2.data(), priv_vec2.size());
    }
    fingerprint_out = rec.id_fprint; 
    return true;
}