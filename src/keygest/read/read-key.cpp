// src/keygest/read/read-key.cpp
#include "../key_manager.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <cstdlib>
#include <sstream>

// Helper seguro para crear directorios sin TOCTOU
static bool secure_mkdir(const std::string& path, mode_t mode) {
    if (mkdirat(AT_FDCWD, path.c_str(), mode) == 0) {
        // fchmodat con AT_SYMLINK_NOFOLLOW evita seguir enlaces simbólicos
        fchmodat(AT_FDCWD, path.c_str(), mode, AT_SYMLINK_NOFOLLOW);
    }
    return true;
}

std::string KeyManager::getKeysFilePath() const {
    std::string data_dir_users;
    const char* xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data && xdg_data[0] != '\0') {
        data_dir_users = std::string(xdg_data) + "/RUBIC-A/users";
    } else {
        const char* home = getenv("HOME");
        if (home && home[0] != '\0') {
            data_dir_users = std::string(home) + "/.local/share/RUBIC-A/users";
        } else {
            return "";
        }
    }
    
    // Crear la carpeta de forma recursiva con permisos seguros
    std::string current_path;
    std::stringstream ss(data_dir_users);
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
        secure_mkdir(current_path, 0700);
    }
    
    return data_dir_users + "/" + username + "_keys.dat";
}

bool KeyManager::ensureUsersDirectory() const {
    std::string usersDir;
    const char* xdg_data = getenv("XDG_DATA_HOME");
    if (xdg_data && xdg_data[0] != '\0') {
        usersDir = std::string(xdg_data) + "/RUBIC-A/users";
    } else {
        const char* home = getenv("HOME");
        if (home && home[0] != '\0') {
            usersDir = std::string(home) + "/.local/share/RUBIC-A/users";
        } else {
          return false;
        }
    }
    
    secure_mkdir(usersDir, 0700);
    
    struct stat buffer;
    if (stat(usersDir.c_str(), &buffer) == 0) {
        return true;
    }
    return false;
}

bool KeyManager::setFilePermissions(const std::string& filepath) const {
    // open + fchmod: elimina la ventana de tiempo (TOCTOU) de SonarQube
    int fd = open(filepath.c_str(), O_WRONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    
    bool ok = (fchmod(fd, 0600) == 0);
    close(fd);
    return ok;
}
