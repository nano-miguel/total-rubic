// share/share_server.cpp - 0.1 alpha
// Lógica de red entrante: Servidores KEM y Transferencia de archivos.

#include "share_manager.h"

// SERVIDOR KEM (Handshake inicial)
void ShareManager::startKemSrv() {
    kem_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (kem_sock < 0)
        return;

    int opt = 1;
    setsockopt(kem_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(kem_port);

    if (bind(kem_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(kem_sock);
        return;
    }
    if (listen(kem_sock, 5) < 0) {
        close(kem_sock);
        return;
    }

    kem_srv_run = true;

    while (kem_srv_run && !stop_req) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(kem_sock, &fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(kem_sock + 1, &fds, nullptr, nullptr, &tv) <= 0)
            continue;

        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli = accept(kem_sock, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli < 0)
            continue;

        char cli_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_ip, INET_ADDRSTRLEN);

        if (!checkRate(cli, cli_ip)) {
            close(cli);
            continue;
        }

        act_conns++;
        std::thread t([this, cli, ip = std::string(cli_ip)]() {
            handleKemConn(cli, ip);
            act_conns--;
        });

        std::lock_guard<std::mutex> lock(th_mtx);
        conn_threads.push_back(std::move(t));
    }
    close(kem_sock);
}

void ShareManager::handleKemConn(int cli_sock, const std::string& cli_ip) {
    try {
        setSockTimeout(cli_sock, SOCK_TIMEOUT);

        size_t rem_len;
        if (!safeRecv(cli_sock, &rem_len, sizeof(rem_len)) || rem_len > 100) {
            close(cli_sock);
            return;
        }

        std::vector<char> rem_buf(rem_len + 1);
        safeRecv(cli_sock, rem_buf.data(), rem_len);
        rem_buf[rem_len] = '\0';
        std::string rem_user(rem_buf.data());

        size_t rem_fp_len;
        std::string rem_fprint;
        safeRecv(cli_sock, &rem_fp_len, sizeof(rem_fp_len));
        if (rem_fp_len > 0) {
            std::vector<char> fp_buf(rem_fp_len + 1);
            safeRecv(cli_sock, fp_buf.data(), rem_fp_len);
            fp_buf[rem_fp_len] = '\0';
            rem_fprint = std::string(fp_buf.data());
        }

        // VERIFICACIÓN TOFU
        if (!checkTrust(rem_user, rem_fprint, true)) {
            close(cli_sock);
            return;
        }

        // Enviar identidad
        size_t len = username.size();
        safeSend(cli_sock, &len, sizeof(len));
        safeSend(cli_sock, username.c_str(), len);

        size_t fp_len = id_fprint.size();
        safeSend(cli_sock, &fp_len, sizeof(fp_len));
        if (fp_len > 0)
            safeSend(cli_sock, id_fprint.c_str(), fp_len);

        // 2. Intercambio Dilithium
        size_t rem_dil_len;
        std::unique_ptr<Botan::Public_Key> rem_dili_key;
        safeRecv(cli_sock, &rem_dil_len, sizeof(rem_dil_len));
        if (rem_dil_len > 0 && rem_dil_len < 65536) {
            std::vector<uint8_t> rem_dil_buf(rem_dil_len);
            if (safeRecv(cli_sock, rem_dil_buf.data(), rem_dil_len)) {
                try {
                    Botan::DataSource_Memory src(rem_dil_buf);
                    rem_dili_key = Botan::X509::load_key(src);
                } catch (...) {
                }
            }
        }

        if (!id_pub_key.empty()) {
            size_t dil_len = id_pub_key.size();
            safeSend(cli_sock, &dil_len, sizeof(dil_len));
            safeSend(cli_sock, id_pub_key.data(), dil_len);
        } else {
            size_t zero = 0;
            safeSend(cli_sock, &zero, sizeof(zero));
        }

        // Recibir Kyber y verificar
        size_t rem_kyber_len;
        safeRecv(cli_sock, &rem_kyber_len, sizeof(rem_kyber_len));
        if (rem_kyber_len == 0 || rem_kyber_len > 65536) {
            close(cli_sock);
            return;
        }

        std::vector<char> rem_kyber_buf(rem_kyber_len + 1);
        safeRecv(cli_sock, rem_kyber_buf.data(), rem_kyber_len);

        size_t rem_sig_len;
        safeRecv(cli_sock, &rem_sig_len, sizeof(rem_sig_len));

        if (rem_sig_len > 0) {
            std::vector<uint8_t> rem_sig(rem_sig_len);
            safeRecv(cli_sock, rem_sig.data(), rem_sig_len);

            if (rem_dili_key) {
                Botan::PK_Verifier verifier(*rem_dili_key, "Pure");
                verifier.update(reinterpret_cast<const uint8_t*>(rem_kyber_buf.data()), rem_kyber_len);
                if (!verifier.check_signature(rem_sig)) {
                    log(share_log::LogLevel::Security, share_log::LogEvent::MitmDetected, rem_user + "@" + cli_ip);
                    close(cli_sock);
                    return;
                }
            }
        }

        std::unique_ptr<Botan::Public_Key> rem_kyber_key;
        try {
            Botan::DataSource_Memory src(rem_kyber_buf.data());
            rem_kyber_key = Botan::X509::load_key(src);
        } catch (...) {
            close(cli_sock);
            return;
        }

        //  Enviar Kyber y Firma
        std::string kyber_pem = Botan::X509::PEM_encode(*kyber_pub_key);
        size_t kyber_len = kyber_pem.size();
        safeSend(cli_sock, &kyber_len, sizeof(kyber_len));
        safeSend(cli_sock, kyber_pem.c_str(), kyber_len);

        if (dili_priv_key) {
            Botan::PK_Signer signer(*dili_priv_key, rng, "Pure");
            signer.update(reinterpret_cast<const uint8_t*>(kyber_pem.data()), kyber_len);
            std::vector<uint8_t> sig = signer.signature(rng);

            size_t sig_len = sig.size();
            safeSend(cli_sock, &sig_len, sizeof(sig_len));
            safeSend(cli_sock, sig.data(), sig_len);
        } else {
            size_t zero = 0;
            safeSend(cli_sock, &zero, sizeof(zero));
        }

        //  Desencapsular KEM
        size_t enc_len;
        safeRecv(cli_sock, &enc_len, sizeof(enc_len));

        std::vector<uint8_t> encap(enc_len);
        safeRecv(cli_sock, encap.data(), enc_len);

        Botan::PK_KEM_Decryptor kem(*kyber_priv_key, rng, "KDF2(SHA-256)");
        auto enc_sec = toSec(encap);
        auto shared = kem.decrypt(enc_sec, 32);
        std::vector<uint8_t> sess_key_vec(shared.begin(), shared.end());

        char confirm = 'Y';
        safeSend(cli_sock, &confirm, sizeof(confirm));

        int xfer_port_remote;
        safeRecv(cli_sock, &xfer_port_remote, sizeof(xfer_port_remote));

        auto sess = std::make_shared<ShareSess>();
        std::vector<uint8_t> rnd_id(16);
        rng.randomize(rnd_id.data(), rnd_id.size());
        sess->sess_id = Botan::hex_encode(rnd_id) + "_" + rem_user;
        sess->local_user = username;
        sess->rem_user = rem_user;
        sess->rem_addr = cli_ip;
        sess->rem_fprint = rem_fprint;
        sess->rem_port = xfer_port_remote;
        sess->created = time(nullptr);
        sess->active = true;
        sess->sess_key = sess_key_vec;
        sess->rem_kyber_key = std::move(rem_kyber_key);
        sess->rem_dili_key = std::move(rem_dili_key);

        SecUtil::secure_clear(sess_key_vec);

        {
            std::lock_guard<std::mutex> lock(sess_mtx);
            act_sessions.push_back(sess);
        }

        // Notificar a la UI que hay una sesión nueva
        if (session_cb_) {
            session_cb_(rem_user, cli_ip);
        }

        close(cli_sock);
    } catch (...) {
        close(cli_sock);
    }
}

// SERVIDOR DE TRANSFERENCIA (Archivo)

void ShareManager::startXferSrv() {
    xfer_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (xfer_sock < 0)
        return;

    int opt = 1;
    setsockopt(xfer_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(xfer_port);

    if (bind(xfer_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(xfer_sock);
        return;
    }
    if (listen(xfer_sock, 5) < 0) {
        close(xfer_sock);
        return;
    }

    xfer_srv_run = true;

    while (xfer_srv_run && !stop_req) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(xfer_sock, &fds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        if (select(xfer_sock + 1, &fds, nullptr, nullptr, &tv) <= 0)
            continue;

        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int cli = accept(xfer_sock, (struct sockaddr*)&cli_addr, &cli_len);
        if (cli < 0)
            continue;

        char cli_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli_addr.sin_addr, cli_ip, INET_ADDRSTRLEN);

        if (!checkRate(cli, cli_ip)) {
            close(cli);
            continue;
        }

        act_conns++;
        std::thread t([this, cli, ip = std::string(cli_ip)]() {
            handleXferConn(cli, ip);
            act_conns--;
        });

        std::lock_guard<std::mutex> lock(th_mtx);
        conn_threads.push_back(std::move(t));
    }
    close(xfer_sock);
}

void ShareManager::handleXferConn(int cli_sock, const std::string& cli_ip) {
    try {
        setSockTimeout(cli_sock, 300);

        std::shared_ptr<ShareSess> sess;
        {
            std::lock_guard<std::mutex> lock(sess_mtx);
            for (auto& s : act_sessions) {
                if (s->rem_addr == cli_ip && s->active) {
                    sess = s;
                    break;
                }
            }
        }

        if (!sess) {
            close(cli_sock);
            return;
        }

        log(share_log::LogLevel::Info, share_log::LogEvent::ReceivingFrom, sess->rem_user);

        size_t meta_len;
        if (!safeRecv(cli_sock, &meta_len, sizeof(meta_len)) || meta_len == 0 || meta_len > 4096) {
            close(cli_sock);
            return;
        }

        std::vector<char> meta_buf(meta_len + 1);
        safeRecv(cli_sock, meta_buf.data(), meta_len);
        meta_buf[meta_len] = '\0';
        std::string meta(meta_buf.data());

        size_t c1 = meta.find(':');
        size_t c2 = meta.find(':', c1 + 1);
        size_t c3 = meta.find(':', c2 + 1);

        if (c1 == std::string::npos || c2 == std::string::npos || c3 == std::string::npos) {
            close(cli_sock);
            return;
        }

        size_t file_sz = std::stoull(meta.substr(c1 + 1, c2 - c1 - 1));
        std::string fname = meta.substr(c2 + 1, c3 - c2 - 1);
        std::string exp_hash = meta.substr(c3 + 1);

        for (char& c : fname) {
            if (c == '/' || c == '\\')
                c = '_';
        }

        std::string out_path = recv_dir + "/" + fname;
        if (std::filesystem::exists(out_path)) {
            size_t dot = fname.rfind('.');
            std::string name = (dot != std::string::npos) ? fname.substr(0, dot) : fname;
            std::string ext = (dot != std::string::npos) ? fname.substr(dot) : "";
            out_path = recv_dir + "/" + name + "_" + std::to_string(time(nullptr)) + ext;
        }

        std::ofstream file(out_path, std::ios::binary);
        if (!file) {
            char err = 'N';
            safeSend(cli_sock, &err, sizeof(err));
            close(cli_sock);
            return;
        }

        size_t recvd = 0;
        while (recvd < file_sz) {
            size_t chunk_sz;
            if (!safeRecv(cli_sock, &chunk_sz, sizeof(chunk_sz)))
                break;
            if (chunk_sz == 0)
                break;

            std::vector<uint8_t> enc(chunk_sz);
            if (!safeRecv(cli_sock, enc.data(), chunk_sz))
                break;

            std::vector<uint8_t> dec = decChunk(enc, sess->sess_key);
            if (dec.empty())
                break;

            file.write(reinterpret_cast<const char*>(dec.data()), dec.size());
            recvd += dec.size();
        }
        file.close();

        std::string hash = hashFile(out_path);
        if (hash == exp_hash) {
            char ok = 'Y';
            safeSend(cli_sock, &ok, sizeof(ok));
            if (file_recv_cb_)
                file_recv_cb_(fname, file_sz, true);
        } else {
            std::filesystem::remove(out_path);
            char err = 'N';
            safeSend(cli_sock, &err, sizeof(err));
            if (file_recv_cb_)
                file_recv_cb_(fname, file_sz, false);
        }
        close(cli_sock);
    } catch (...) {
        close(cli_sock);
    }
}
