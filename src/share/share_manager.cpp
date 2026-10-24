// share/share_manager.cpp - 0.1 alpha
// Implementación de la lógica pura de compartir archivos.
// La UI vive en ui/share_manager_ui.h
// NOTA: La lógica del servidor vive en share_server.cpp

#include "share_manager.h"

// ******************************************
// FUNCIONES HELPER & TOFU

void ShareManager::loadTrust() {
    trust_fprints.clear();
    std::ifstream file(cfg_dir + "/trusted_hosts.txt");
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty())
            trust_fprints.insert(line);
    }
}

void ShareManager::saveTrust() {
    std::ofstream file(cfg_dir + "/trusted_hosts.txt");
    for (const auto& fp : trust_fprints) {
        file << fp << "\n";
    }
}

bool ShareManager::checkTrust(const std::string& rem_user, const std::string& fprint, bool is_srv) {
    if (fprint.empty())
        return false;
    if (trust_fprints.count(fprint))
        return true;

    // Delegar a la UI (que preguntará al usuario)
    if (!trust_prompt_cb_)
        return false;

    log(share_log::LogLevel::Warning, share_log::LogEvent::TrustPromptShown, rem_user + ":" + fprint);

    bool accept = trust_prompt_cb_(rem_user, fprint, is_srv);
    if (accept) {
        trust_fprints.insert(fprint);
        saveTrust();
        log(share_log::LogLevel::Success, share_log::LogEvent::TrustAccepted, rem_user);
        return true;
    }
    log(share_log::LogLevel::Warning, share_log::LogEvent::TrustRejected, rem_user);
    return false;
}

std::vector<uint8_t> ShareManager::toVec(const Botan::secure_vector<uint8_t>& sec) {
    return std::vector<uint8_t>(sec.begin(), sec.end());
}

Botan::secure_vector<uint8_t> ShareManager::toSec(const std::vector<uint8_t>& vec) {
    return Botan::secure_vector<uint8_t>(vec.begin(), vec.end());
}

bool ShareManager::safeSend(int sock, const void* buf, size_t len) {
    const char* ptr = static_cast<const char*>(buf);
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(sock, ptr + total, len - total, MSG_NOSIGNAL);
        if (sent <= 0)
            return false;
        total += sent;
    }
    return true;
}

bool ShareManager::safeRecv(int sock, void* buf, size_t len) {
    char* ptr = static_cast<char*>(buf);
    size_t total = 0;
    while (total < len) {
        ssize_t recvd = recv(sock, ptr + total, len - total, 0);
        if (recvd <= 0)
            return false;
        total += recvd;
    }
    return true;
}

void ShareManager::setSockTimeout(int sock, int secs) {
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void ShareManager::setSockAlive(int sock) {
    int alive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &alive, sizeof(alive));
}

bool ShareManager::checkRate(int cli_sock, const std::string& cli_ip) {
    if (act_conns.load() >= MAX_CONNS)
        return false;
    std::lock_guard<std::mutex> r_lock(rate_mtx);
    time_t now = time(nullptr);
    if (now - conn_attempts[cli_ip] < RATE_LIMIT)
        return false;
    conn_attempts[cli_ip] = now;
    return true;
}

// *************************************************
// Cifrado y generacion de llaves

bool ShareManager::genKyber() {
    try {
        Botan::Kyber_PrivateKey kyber_key(rng, Botan::KyberMode::Kyber1024_R3);
        kyber_priv_key.reset(new Botan::Kyber_PrivateKey(kyber_key));
        kyber_pub_key = Botan::X509::copy_key(*kyber_priv_key);
        return true;
    } catch (...) {
        return false;
    }
}

std::string ShareManager::hashFile(const std::string& path) {
    try {
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        std::ifstream file(path, std::ios::binary);
        if (!file)
            return "";
        std::vector<char> buf(8192);
        while (file.read(buf.data(), buf.size()) || file.gcount() > 0) {
            hash->update(reinterpret_cast<const uint8_t*>(buf.data()), file.gcount());
        }
        return Botan::hex_encode(hash->final());
    } catch (...) {
        return "";
    }
}

std::vector<uint8_t> ShareManager::encChunk(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    try {
        std::vector<uint8_t> nonce(12);
        rng.randomize(nonce.data(), nonce.size());

        auto chacha = Botan::AEAD_Mode::create("ChaCha20Poly1305", Botan::Cipher_Dir::Encryption);
        if (!chacha)
            return {};

        chacha->set_key(key);
        chacha->start(nonce.data(), nonce.size());

        auto sec_data = toSec(data);
        chacha->finish(sec_data);

        std::vector<uint8_t> result;
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), sec_data.begin(), sec_data.end());
        return result;
    } catch (...) {
        return {};
    }
}

std::vector<uint8_t> ShareManager::decChunk(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    try {
        if (data.size() < 12)
            return {};

        std::vector<uint8_t> nonce(data.begin(), data.begin() + 12);
        auto ctext = toSec(std::vector<uint8_t>(data.begin() + 12, data.end()));

        auto chacha = Botan::AEAD_Mode::create("ChaCha20Poly1305", Botan::Cipher_Dir::Decryption);
        if (!chacha)
            return {};

        chacha->set_key(key);
        chacha->start(nonce.data(), nonce.size());
        chacha->finish(ctext);

        return std::vector<uint8_t>(ctext.begin(), ctext.end());
    } catch (...) {
        return {};
    }
}

// **********************************************
// ARCHIVOS

size_t ShareManager::getFileSz(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
        return st.st_size;
    return 0;
}

std::vector<std::string> ShareManager::expandFiles(const std::string& path) {
    std::vector<std::string> files;
    if (!std::filesystem::exists(path))
        return files;

    if (std::filesystem::is_regular_file(path)) {
        files.push_back(path);
    } else if (std::filesystem::is_directory(path)) {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
                if (std::filesystem::is_regular_file(entry.path())) {
                    files.push_back(entry.path().string());
                }
            }
        } catch (...) {
        }
    }
    return files;
}

// ********************************
// IP ACTUAL & PARSEO

std::string ShareManager::getCurrentIP() {
    std::string ip = "127.0.0.1";
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
                std::string ifname = ifa->ifa_name;
                std::string ipaddr = host;
                if (ipaddr != "127.0.0.1" && ifname.find("lo") == std::string::npos) {
                    ip = ipaddr;
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
    return ip;
}

bool ShareManager::parseAddress(const std::string& input, std::string& addr, int& port) {
    std::string ad = input;
    ad.erase(std::remove(ad.begin(), ad.end(), ' '), ad.end());

    if (ad.empty()) {
        return false;
    }

    size_t colon = ad.find(':');
    if (colon == std::string::npos) {
        return false;
    }

    addr = ad.substr(0, colon);
    std::string port_str = ad.substr(colon + 1);

    for (char c : port_str) {
        if (!isdigit(c)) {
            return false;
        }
    }

    port = std::stoi(port_str);
    if (port < 1 || port > 65535) {
        return false;
    }
    return true;
}

// *****************************************
// INTERCAMBIO DE CLAVES (Cliente)

bool ShareManager::exchKeys(const std::string& rem_addr,
                            int rem_port,
                            std::string& rem_user,
                            std::unique_ptr<Botan::Public_Key>& rem_kyber_key,
                            std::unique_ptr<Botan::Public_Key>& rem_dili_key,
                            std::string& rem_fprint,
                            std::vector<uint8_t>& sess_key) {
    try {
        log(share_log::LogLevel::Info, share_log::LogEvent::Connecting, rem_addr + ":" + std::to_string(rem_port));

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            log(share_log::LogLevel::Error, share_log::LogEvent::ConnectFailed, "socket()");
            return false;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rem_port);

        if (inet_pton(AF_INET, rem_addr.c_str(), &addr.sin_addr) <= 0) {
            close(sock);
            log(share_log::LogLevel::Error, share_log::LogEvent::ConnectFailed, "inet_pton");
            return false;
        }

        setSockTimeout(sock, SOCK_TIMEOUT);
        setSockAlive(sock);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            log(share_log::LogLevel::Error, share_log::LogEvent::ConnectFailed, "connect()");
            return false;
        }

        // Intercambio de Identidad (Nombre y Huella de Dilithium)
        size_t len = username.size();
        safeSend(sock, &len, sizeof(len));
        safeSend(sock, username.c_str(), len);

        size_t fp_len = id_fprint.size();
        safeSend(sock, &fp_len, sizeof(fp_len));
        if (fp_len > 0)
            safeSend(sock, id_fprint.c_str(), fp_len);

        size_t rem_len;
        if (!safeRecv(sock, &rem_len, sizeof(rem_len)) || rem_len > 100) {
            close(sock);
            return false;
        }
        std::vector<char> rem_buf(rem_len + 1);
        safeRecv(sock, rem_buf.data(), rem_len);
        rem_buf[rem_len] = '\0';
        rem_user = std::string(rem_buf.data());

        size_t rem_fp_len;
        safeRecv(sock, &rem_fp_len, sizeof(rem_fp_len));
        if (rem_fp_len > 0 && rem_fp_len < 256) {
            std::vector<char> fp_buf(rem_fp_len + 1);
            safeRecv(sock, fp_buf.data(), rem_fp_len);
            fp_buf[rem_fp_len] = '\0';
            rem_fprint = std::string(fp_buf.data());
        }

        // TOFU
        if (!checkTrust(rem_user, rem_fprint, false)) {
            close(sock);
            return false;
        }

        // Intercambio de Claves Dilithium
        if (!id_pub_key.empty()) {
            size_t dil_len = id_pub_key.size();
            safeSend(sock, &dil_len, sizeof(dil_len));
            safeSend(sock, id_pub_key.data(), dil_len);
        } else {
            size_t zero = 0;
            safeSend(sock, &zero, sizeof(zero));
        }

        size_t rem_dil_len;
        safeRecv(sock, &rem_dil_len, sizeof(rem_dil_len));
        if (rem_dil_len > 0 && rem_dil_len < 65536) {
            std::vector<uint8_t> rem_dil_buf(rem_dil_len);
            if (safeRecv(sock, rem_dil_buf.data(), rem_dil_len)) {
                try {
                    Botan::DataSource_Memory src(rem_dil_buf);
                    rem_dili_key = Botan::X509::load_key(src);
                } catch (...) {
                }
            }
        }

        // Envío de Clave Kyber y Firma Digital
        std::string kyber_pem = Botan::X509::PEM_encode(*kyber_pub_key);
        size_t kyber_len = kyber_pem.size();
        safeSend(sock, &kyber_len, sizeof(kyber_len));
        safeSend(sock, kyber_pem.c_str(), kyber_len);

        if (dili_priv_key) {
            Botan::PK_Signer signer(*dili_priv_key, rng, "Pure");
            signer.update(reinterpret_cast<const uint8_t*>(kyber_pem.data()), kyber_len);
            std::vector<uint8_t> sig = signer.signature(rng);

            size_t sig_len = sig.size();
            safeSend(sock, &sig_len, sizeof(sig_len));
            safeSend(sock, sig.data(), sig_len);
        } else {
            size_t zero = 0;
            safeSend(sock, &zero, sizeof(zero));
        }

        // recepcion de claves Remota y verificar
        size_t rem_kyber_len;
        safeRecv(sock, &rem_kyber_len, sizeof(rem_kyber_len));
        if (rem_kyber_len == 0 || rem_kyber_len > 65536) {
            close(sock);
            return false;
        }

        std::vector<char> rem_kyber_buf(rem_kyber_len + 1);
        safeRecv(sock, rem_kyber_buf.data(), rem_kyber_len);
        rem_kyber_buf[rem_kyber_len] = '\0';

        size_t rem_sig_len;
        safeRecv(sock, &rem_sig_len, sizeof(rem_sig_len));

        if (rem_sig_len > 0) {
            std::vector<uint8_t> rem_sig(rem_sig_len);
            safeRecv(sock, rem_sig.data(), rem_sig_len);

            if (rem_dili_key) {
                Botan::PK_Verifier verifier(*rem_dili_key, "Pure");
                verifier.update(reinterpret_cast<const uint8_t*>(rem_kyber_buf.data()), rem_kyber_len);
                if (!verifier.check_signature(rem_sig)) {
                    log(share_log::LogLevel::Security, share_log::LogEvent::MitmDetected, rem_user + "@" + rem_addr);
                    close(sock);
                    return false;
                }
            }
        }

        try {
            Botan::DataSource_Memory src(rem_kyber_buf.data());
            rem_kyber_key = Botan::X509::load_key(src);
        } catch (...) {
            close(sock);
            return false;
        }

        // encapsulación-kyber
        Botan::PK_KEM_Encryptor kem(*rem_kyber_key, "KDF2(SHA-256)");
        auto result = kem.encrypt(rng, 32);

        auto shared_sec = result.shared_key();
        auto encap_sec = result.encapsulated_shared_key();

        sess_key.assign(shared_sec.begin(), shared_sec.end());
        std::vector<uint8_t> encap(encap_sec.begin(), encap_sec.end());

        size_t enc_len = encap.size();
        safeSend(sock, &enc_len, sizeof(enc_len));
        safeSend(sock, encap.data(), enc_len);

        char confirm;
        safeRecv(sock, &confirm, sizeof(confirm));

        int xfer_port_local = xfer_port;
        safeSend(sock, &xfer_port_local, sizeof(xfer_port_local));

        close(sock);
        return confirm == 'Y';
    } catch (...) {
        log(share_log::LogLevel::Error, share_log::LogEvent::ExchangeKeysFailed, rem_addr);
        return false;
    }
}

// *****************************************
// ENVIAR (Cliente)

bool ShareManager::sendFile(const std::string& path,
                            const std::string& rem_addr,
                            int rem_port,
                            const std::vector<uint8_t>& key) {
    try {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            return false;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(rem_port);

        if (inet_pton(AF_INET, rem_addr.c_str(), &addr.sin_addr) <= 0) {
            close(sock);
            return false;
        }
        setSockTimeout(sock, SOCK_TIMEOUT);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            return false;
        }

        std::string file_hash = hashFile(path);
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) {
            close(sock);
            return false;
        }

        size_t file_sz = file.tellg();
        file.seekg(0);

        std::string fname = std::filesystem::path(path).filename().string();
        std::string meta = "F:" + std::to_string(file_sz) + ":" + fname + ":" + file_hash;
        size_t meta_len = meta.size();

        safeSend(sock, &meta_len, sizeof(meta_len));
        safeSend(sock, meta.c_str(), meta_len);

        std::vector<char> buf(CHUNK_SIZE);
        while (true) {
            file.read(buf.data(), CHUNK_SIZE);
            size_t read = file.gcount();
            if (read == 0)
                break;

            std::vector<uint8_t> data(buf.begin(), buf.begin() + read);
            std::vector<uint8_t> enc = encChunk(data, key);

            if (enc.empty()) {
                close(sock);
                return false;
            }

            size_t enc_sz = enc.size();
            safeSend(sock, &enc_sz, sizeof(enc_sz));
            safeSend(sock, enc.data(), enc_sz);
        }

        size_t end = 0;
        safeSend(sock, &end, sizeof(end));
        char confirm;
        bool ok = safeRecv(sock, &confirm, sizeof(confirm)) && confirm == 'Y';
        close(sock);
        return ok;
    } catch (...) {
        return false;
    }
}

bool ShareManager::sendFiles(const std::vector<std::string>& file_paths, const std::string& rem_addr, int rem_port) {
    if (file_paths.empty()) {
        log(share_log::LogLevel::Warning, share_log::LogEvent::NoFilesToSend, "");
        return false;
    }

    // Establecer sesión segura (KEM exchange + TOFU)
    std::string rem_user, rem_fprint;
    std::unique_ptr<Botan::Public_Key> rem_kyber_key, rem_dili_key;
    std::vector<uint8_t> sess_key;

    if (!exchKeys(rem_addr, rem_port, rem_user, rem_kyber_key, rem_dili_key, rem_fprint, sess_key)) {
        log(share_log::LogLevel::Error, share_log::LogEvent::SendFailed, rem_addr);
        return false;
    }

    log(share_log::LogLevel::Info, share_log::LogEvent::SendingFiles, std::to_string(file_paths.size()));

    // Enviar archivos uno por uno
    size_t sent = 0;
    for (size_t i = 0; i < file_paths.size(); i++) {
        if (file_send_cb_)
            file_send_cb_(file_paths[i], i + 1, file_paths.size(), false);
        bool ok = sendFile(file_paths[i], rem_addr, xfer_port, sess_key);
        if (file_send_cb_)
            file_send_cb_(file_paths[i], i + 1, file_paths.size(), ok);
        if (ok)
            sent++;
    }

    SecUtil::secure_clear(sess_key);

    if (sent > 0) {
        log(share_log::LogLevel::Success,
            share_log::LogEvent::SendComplete,
            std::to_string(sent) + "/" + std::to_string(file_paths.size()));
    }
    return sent > 0;
}

// *****************************************
// CICLO DE VIDA & SERVIDOR

void ShareManager::stopSrvs() {
    stop_req = true;
    kem_srv_run = false;
    xfer_srv_run = false;

    if (kem_sock >= 0) {
        shutdown(kem_sock, SHUT_RDWR);
        close(kem_sock);
    }
    if (xfer_sock >= 0) {
        shutdown(xfer_sock, SHUT_RDWR);
        close(xfer_sock);
    }

    if (kem_thread.joinable())
        kem_thread.join();
    if (xfer_thread.joinable())
        xfer_thread.join();

    {
        std::lock_guard<std::mutex> lock(th_mtx);
        for (auto& t : conn_threads) {
            if (t.joinable())
                t.join();
        }
        conn_threads.clear();
    }

    stop_req = false;

    std::lock_guard<std::mutex> lock(sess_mtx);
    for (auto& s : act_sessions)
        s->clearSensitive();
    act_sessions.clear();
}

ShareManager::ShareManager() {
    signal(SIGPIPE, SIG_IGN);
    std::string dl_base = getDlFolder();
    recv_dir = dl_base + "/RUBIC-Recibidos";
    std::filesystem::create_directories(recv_dir);
}

ShareManager::~ShareManager() {
    stopSrvs();
    SecUtil::secure_clear(id_priv_raw);
}

// *****************************************
// IDENTIDAD

void ShareManager::setUsername(const std::string& name) {
    username = name;

    // Usar XDG_CONFIG_HOME para la configuración del usuario
    const char* xdg_config = getenv("XDG_CONFIG_HOME");
    std::string config_base;
    if (xdg_config && xdg_config[0] != '\0') {
        config_base = std::string(xdg_config);
    } else {
        const char* home = getenv("HOME");
        if (home) {
            config_base = std::string(home) + "/.config";
        } else {
            config_base = "/tmp";
        }
    }

    cfg_dir = config_base + "/RUBIC-A/" + name;
    create_dir_recursive(cfg_dir);
    loadTrust();
}

void ShareManager::setIdentity(const std::vector<uint8_t>& pub_key,
                               const std::vector<uint8_t>& priv_key,
                               const std::string& fp) {
    id_pub_key = pub_key;
    id_priv_raw = Botan::secure_vector<uint8_t>(priv_key.begin(), priv_key.end());
    id_fprint = fp;

    try {
        if (!pub_key.empty()) {
            Botan::DataSource_Memory src_pub(pub_key);
            dili_pub_key = Botan::X509::load_key(src_pub);
        }
        if (!priv_key.empty()) {
            Botan::DataSource_Memory src_priv(priv_key);
            dili_priv_key = Botan::PKCS8::load_key(src_priv);
        }
    } catch (...) {
        log(share_log::LogLevel::Error, share_log::LogEvent::IdentityLoadError, "");
    }
}

// *****************************************
// TOFU / TRUST (interfaz pública)

std::vector<std::string> ShareManager::getTrustedFingerprints() const {
    std::vector<std::string> result;
    for (const auto& fp : trust_fprints) {
        result.push_back(fp);
    }
    return result;
}

bool ShareManager::addTrustedFingerprint(const std::string& fprint) {
    if (fprint.empty())
        return false;
    trust_fprints.insert(fprint);
    saveTrust();
    return true;
}

bool ShareManager::removeTrustedFingerprint(const std::string& fprint) {
    auto it = trust_fprints.find(fprint);
    if (it == trust_fprints.end())
        return false;
    trust_fprints.erase(it);
    saveTrust();
    return true;
}

bool ShareManager::isTrusted(const std::string& fprint) const {
    return trust_fprints.count(fprint) > 0;
}

// *****************************************
// RECIBIR

bool ShareManager::startReceiving() {
    if (!kyber_priv_key && !genKyber()) {
        log(share_log::LogLevel::Error, share_log::LogEvent::KyberGenFailed, "");
        return false;
    }

    stop_req = false;

    kem_thread = std::thread([this]() { startKemSrv(); });
    xfer_thread = std::thread([this]() { startXferSrv(); });

    // Esperar a que arranquen los servidores
    for (int i = 0; i < 20 && !kem_srv_run; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    if (!kem_srv_run) {
        log(share_log::LogLevel::Error, share_log::LogEvent::ServerStartFailed, "");
        stopSrvs();
        return false;
    }

    log(share_log::LogLevel::Success, share_log::LogEvent::ServerStarted, "");
    return true;
}

void ShareManager::stopReceiving() {
    stopSrvs();
    log(share_log::LogLevel::Info, share_log::LogEvent::ServerStopped, "");
}