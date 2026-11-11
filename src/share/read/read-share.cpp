// src/share/read/read-share.cpp
#include "../share_manager.h"
#include <stdexcept>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

// ******************************************
// HELPERS DE CONVERSIÓN

std::vector<uint8_t> ShareManager::toVec(const Botan::secure_vector<uint8_t>& sec) {
    return std::vector<uint8_t>(sec.begin(), sec.end());
}

Botan::secure_vector<uint8_t> ShareManager::toSec(const std::vector<uint8_t>& vec) {
    return Botan::secure_vector<uint8_t>(vec.begin(), vec.end());
}

// ******************************************
// HELPERS DE RED

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

// **********************************************
// ARCHIVOS Y HASH

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
// IP Y CONFIGURACIÓN

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

void ShareManager::setUsername(const std::string& name) {
    username = name;

    const char* xdg_config = getenv("XDG_CONFIG_HOME");
    std::string config_base;
    if (xdg_config && xdg_config[0] != '\0') {
        config_base = std::string(xdg_config);
    } else {
        const char* home = getenv("HOME");
        if (home && home[0] != '\0') {
            config_base = std::string(home) + "/.config";
        } else {
            throw std::runtime_error("err_no_safe_config_dir");
        }
    }

    cfg_dir = config_base + "/RUBIC-A/" + name;
    create_dir_recursive(cfg_dir);
    loadTrust();
}
