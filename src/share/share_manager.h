// share/share_manager.h - 0.1 alpha
// Lógica pura de compartir archivos. CERO cout/cerr. Todo por callbacks.
// La UI vive en ui/share_manager_ui.h

#ifndef SHARE_MANAGER_H
#define SHARE_MANAGER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <ctime>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>
#include <memory>
#include <thread>
#include <atomic>
#include <future>
#include <queue>
#include <functional>
#include <filesystem>
#include <mutex>
#include <random>
#include <pwd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <dirent.h>
#include <termios.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/ioctl.h>

// Botan :)
#include <botan/auto_rng.h>
#include <botan/rng.h>
#include <botan/pubkey.h>
#include <botan/kyber.h>
#include <botan/dilithium.h>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>
#include <botan/cipher_mode.h>
#include <botan/aead.h>
#include <botan/hex.h>
#include <botan/base64.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/data_src.h>
#include <botan/kdf.h>
#include <botan/secmem.h>

// Constantes
const size_t CHUNK_SIZE = 65536; // tamaño de bloques para transferir archivos
const int SOCK_TIMEOUT = 30;

// LIMPIEZA DE MEMORIA
// **************************************

namespace SecUtil {
inline void secure_z(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }
}

template <typename T> inline void secure_clear(T& container) {
    if (!container.empty()) {
        secure_z(container.data(), container.size() * sizeof(typename T::value_type));
        container.clear();
    }
}
} // namespace SecUtil

// ▼▼▼ NUEVO: eventos estructurados del share ▼▼▼
namespace share_log {

enum class LogLevel {
    Info,
    Warning,
    Error,
    Success,
    Security // nivel especial para alertas críticas (MITM, firma inválida)
};

enum class LogEvent {
    // Conexión / intercambio
    Connecting, // data = "addr:port"
    ConnectFailed,
    ExchangeKeysFailed,
    MitmDetected,       // ← CRÍTICO: firma Kyber inválida
    SessionEstablished, // data = "usuario (ip)"

    // Recepción
    ReceivingFrom, // data = usuario remoto
    ServerStartFailed,
    KyberGenFailed,
    ServerStarted,
    ServerStopped,

    // Envío
    NoFilesToSend,
    SendingFiles, // data = "N archivos"
    SendComplete,
    SendFailed,

    // Identidad
    IdentityLoadError,

    // TOFU
    TrustPromptShown, // data = "usuario:fingerprint"
    TrustAccepted,
    TrustRejected
};

} // namespace share_log
// ▲▲▲ NUEVO ▲▲▲

// ********************************************************
// FUNCIONES AUXILIARES

inline std::string getHome() {
    const char* sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd* pw = getpwnam(sudo_user);
        if (pw)
            return std::string(pw->pw_dir);
    }
    const char* home = getenv("HOME");
    if (home)
        return std::string(home);
    struct passwd* pw = getpwuid(getuid());
    if (pw)
        return std::string(pw->pw_dir);
    return "/tmp";
}

inline std::string getDlFolder() {
    std::string home = getHome();
    std::vector<std::string> dirs = {home + "/Descargas", home + "/Downloads", home + "/downloads"};
    for (const auto& d : dirs) {
        if (std::filesystem::exists(d))
            return d;
    }
    std::string downloads = home + "/Descargas";
    std::filesystem::create_directories(downloads);
    return downloads;
}

// ********************************************************
// Función  para crear directorios recursivamente

inline bool create_dir_recursive(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) == 0)
        return true;

    std::string current_path;
    std::stringstream ss(path);
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
            if (mkdir(current_path.c_str(), 0700) != 0)
                return false;
        }
    }
    return true;
}

// ***********************************
// ESTRUCTURA DE SESIÓN

struct ShareSess {
    std::string sess_id;
    std::string local_user;
    std::string rem_user;
    std::string rem_addr;
    std::string rem_fprint;
    int rem_port;
    time_t created;
    bool active;

    std::vector<uint8_t> sess_key;
    std::unique_ptr<Botan::Public_Key> rem_kyber_key;
    std::unique_ptr<Botan::Public_Key> rem_dili_key;

    std::atomic<size_t> bytes_xfer{0};
    std::atomic<size_t> files_xfer{0};

    ShareSess() : rem_port(0), created(0), active(false) {}

    ShareSess(ShareSess&& other) noexcept = default;
    ShareSess& operator=(ShareSess&& other) noexcept = default;
    ShareSess(const ShareSess&) = delete;
    ShareSess& operator=(const ShareSess&) = delete;

    void clearSensitive() {
        SecUtil::secure_clear(sess_key);
    }
};

// *************************************************
// clase central del ShareManager (lógica pura)

class ShareManager {
  public:
    // ============================================================
    // Callbacks (toda la presentación vive en la UI)
    // ============================================================
    // ▼▼▼ Firma actualizada con eventos estructurados ▼▼▼
    using LogCallback =
        std::function<void(share_log::LogLevel level, share_log::LogEvent event, const std::string& data)>;
    // ▲▲▲
    using TrustPromptCallback = std::function<bool(const std::string& user, const std::string& fprint, bool is_server)>;
    using SessionCallback = std::function<void(const std::string& rem_user, const std::string& rem_ip)>;
    using FileRecvCallback = std::function<void(const std::string& filename, size_t bytes, bool ok)>;
    using FileSendCallback = std::function<void(const std::string& filename, size_t current, size_t total, bool ok)>;

    // ============================================================
    // Ciclo de vida
    // ============================================================
    ShareManager();
    ~ShareManager();
    ShareManager(const ShareManager&) = delete;
    ShareManager& operator=(const ShareManager&) = delete;

    // ============================================================
    // Callbacks
    // ============================================================
    void setLogCallback(LogCallback cb) {
        log_cb_ = std::move(cb);
    }
    void setTrustPromptCallback(TrustPromptCallback cb) {
        trust_prompt_cb_ = std::move(cb);
    }
    void setSessionCallback(SessionCallback cb) {
        session_cb_ = std::move(cb);
    }
    void setFileRecvCallback(FileRecvCallback cb) {
        file_recv_cb_ = std::move(cb);
    }
    void setFileSendCallback(FileSendCallback cb) {
        file_send_cb_ = std::move(cb);
    }

    // ============================================================
    // Identidad
    // ============================================================
    void setUsername(const std::string& name);
    void setIdentity(const std::vector<uint8_t>& pub_key, const std::vector<uint8_t>& priv_key, const std::string& fp);

    std::string getFingerprint() const {
        return id_fprint;
    }
    bool hasIdentity() const {
        return !id_pub_key.empty();
    }
    std::string getUsername() const {
        return username;
    }

    // ============================================================
    // Red / Puertos
    // ============================================================
    std::string getCurrentIP();
    static bool parseAddress(const std::string& input, std::string& addr, int& port);

    int getKemPort() const {
        return kem_port;
    }
    int getXferPort() const {
        return xfer_port;
    }
    void setKemPort(int p) {
        kem_port = p;
    }
    void setXferPort(int p) {
        xfer_port = p;
    }

    // ============================================================
    // TOFU / Trust
    // ============================================================
    std::vector<std::string> getTrustedFingerprints() const;
    bool addTrustedFingerprint(const std::string& fprint);
    bool removeTrustedFingerprint(const std::string& fprint);
    bool isTrusted(const std::string& fprint) const;

    // ============================================================
    // Enviar
    // ============================================================
    bool sendFiles(const std::vector<std::string>& file_paths, const std::string& rem_addr, int rem_port);

    // ============================================================
    // Recibir
    // ============================================================
    bool startReceiving();
    void stopReceiving();
    bool isReceiving() const {
        return kem_srv_run.load() || xfer_srv_run.load();
    }

    // ============================================================
    // Info / utilidades
    // ============================================================
    std::string getRecvDir() const {
        return recv_dir;
    }
    static std::vector<std::string> expandFiles(const std::string& path);

  private:
    // ============================================================
    // Estado
    // ============================================================
    std::string username;
    std::string cfg_dir;
    std::string recv_dir;

    // Puertos configurables
    int kem_port = 2122;
    int xfer_port = 2123;

    // Identidad Dilithium
    std::vector<uint8_t> id_pub_key;
    Botan::secure_vector<uint8_t> id_priv_raw;
    std::string id_fprint;

    std::unique_ptr<Botan::Public_Key> dili_pub_key;
    std::unique_ptr<Botan::Private_Key> dili_priv_key;

    // Sesiones y concurrencia
    std::vector<std::shared_ptr<ShareSess>> act_sessions;
    std::mutex sess_mtx;

    std::atomic<bool> kem_srv_run{false};
    std::atomic<bool> xfer_srv_run{false};
    std::atomic<bool> stop_req{false};

    int kem_sock{-1};
    int xfer_sock{-1};

    std::thread kem_thread;
    std::thread xfer_thread;

    std::vector<std::thread> conn_threads;
    std::mutex th_mtx;

    // Limiting
    std::mutex rate_mtx;
    std::map<std::string, time_t> conn_attempts;
    std::atomic<int> act_conns{0};
    const int MAX_CONNS = 20;
    const int RATE_LIMIT = 2;

    // TOFU y  I/O
    std::set<std::string> trust_fprints;
    std::mutex trust_mtx;

    std::unique_ptr<Botan::Private_Key> kyber_priv_key;
    std::unique_ptr<Botan::Public_Key> kyber_pub_key;
    Botan::AutoSeeded_RNG rng;

    // Callbacks
    LogCallback log_cb_;
    TrustPromptCallback trust_prompt_cb_;
    SessionCallback session_cb_;
    FileRecvCallback file_recv_cb_;
    FileSendCallback file_send_cb_;

    // ▼▼▼ Helper de log con eventos estructurados ▼▼▼
    void log(share_log::LogLevel level, share_log::LogEvent event, const std::string& data = "") {
        if (log_cb_)
            log_cb_(level, event, data);
    }
    // ▲▲▲

    // ============================================================
    // Helpers privados (implementación en .cpp)
    // ============================================================
    void loadTrust();
    void saveTrust();
    bool checkTrust(const std::string& rem_user, const std::string& fprint, bool is_srv);

    std::vector<uint8_t> toVec(const Botan::secure_vector<uint8_t>& sec);
    Botan::secure_vector<uint8_t> toSec(const std::vector<uint8_t>& vec);

    bool safeSend(int sock, const void* buf, size_t len);
    bool safeRecv(int sock, void* buf, size_t len);
    void setSockTimeout(int sock, int secs);
    void setSockAlive(int sock);
    bool checkRate(int cli_sock, const std::string& cli_ip);

    bool genKyber();
    std::string hashFile(const std::string& path);
    std::vector<uint8_t> encChunk(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    std::vector<uint8_t> decChunk(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

    size_t getFileSz(const std::string& path);

    bool exchKeys(const std::string& rem_addr,
                  int rem_port,
                  std::string& rem_user,
                  std::unique_ptr<Botan::Public_Key>& rem_kyber_key,
                  std::unique_ptr<Botan::Public_Key>& rem_dili_key,
                  std::string& rem_fprint,
                  std::vector<uint8_t>& sess_key);

    void startKemSrv();
    void handleKemConn(int cli_sock, const std::string& cli_ip);
    void startXferSrv();
    void handleXferConn(int cli_sock, const std::string& cli_ip);
    bool sendFile(const std::string& path, const std::string& rem_addr, int rem_port, const std::vector<uint8_t>& key);
    void stopSrvs();
};

#endif
// SHARE_MANAGER_H