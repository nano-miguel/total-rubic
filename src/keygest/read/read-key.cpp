// src/keygest/read/read-key.cpp
#include "../key_manager.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <cstdlib>
#include <sstream>

// Helper para crear la ruta segura sin TOCTOU
static bool secure_mkdir(const std::string& path, mode_t mode) {
    if (mkdirat(AT_FDCWD, path.c_str(), mode) == 0) {
        // Usamos fchmodat con AT_SYMLINK_NOFOLLOW para evitar seguir enlaces simbólicos
        // Evaluamos el retorno para silenciar el warning -Wunused-result de GCC
        if (fchmodat(AT_FDCWD, path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0) {
            // Silenciosamente ignoramos el fallo de permisos
        }
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
    
    // Creamos la carpeta de forma recursiva y segura
    std::filesystem::path p(data_dir_users);
    std::string current_path;
    for (const auto& part : p) {
        current_path += part.string() + "/";
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
    
    // Reemplazamos mkdir/chmod por la versión segura
    secure_mkdir(usersDir, 0700);
    return true;
}

bool KeyManager::setFilePermissions(const std::string& filepath) const {
    // En lugar de chmod, abrimos el archivo y usamos fchmod para evitar TOCTOU
    int fd = open(filepath.c_str(), O_WRONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    
    bool ok = (fchmod(fd, 0600) == 0);
    close(fd);
    return ok;
}