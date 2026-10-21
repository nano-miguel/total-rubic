/*
 * RUBIC-A 
 * cipher/unit/devdetect.cpp
 */

#include "../unit_encryptor.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <string>
#include <string_view>

namespace {

/* 
 * Lee un archivo del sistema  y limpia los saltos 
 */
std::string readSysFile(const std::string& path) {
     std::ifstream file(path);
     std::string line;
    
    if (!std::getline(file, line)) {
        return "";
    }
    
    // npos + 1 desborda a 0, por lo que si no encuentra nada, borra todo.
    line.erase(line.find_last_not_of(" \n\r\t") + 1);
    return line;
}

}  
// namespace
/*
 * Obtiene la ruta base del sistema sysfs 
 */
std::string DevDetect::getSysPath(const std::string& device) {
    std::string_view devname = device;

    if (devname.starts_with("/dev/")) {
        devname.remove_prefix(5);
    }

    while (!devname.empty() && std::isdigit(static_cast<unsigned char>(devname.back()))) {
            devname.remove_suffix(1);
    }

    return "/sys/block/" + std::string(devname);
}

/*
 * Comprueba si el dispositivo está conectado mediante bus USB.
 */
bool DevDetect::checkUSB(const std::string& syspath) {
    // Analizar el archivo  en busca de la firma USB
    std::ifstream uevent_file(syspath + "/device/uevent");
    std::string line;

    while (std::getline(uevent_file, line)) {
        // Búsqueda case-insensitive 
        auto it = std::search(line.begin(), line.end(), "usb", "usb" + 3, 
        [](char c1, char c2) { return std::toupper(c1) == std::toupper(c2); });
            
        if (it != line.end()) {
            return true;
        }
    }

    // Verificar el controlador del usb
    char buf[256];
    ssize_t len = readlink(syspath.c_str(), buf, sizeof(buf) - 1);
        if (len != -1) {
            buf[len] = '\0';
        if (std::string_view(buf).find("usb") != std::string_view::npos) {
            return true;
        }
    }

    return false;
}

std::string DevDetect::readSpeed(const std::string& syspath) {
    return readSysFile(syspath + "/device/speed");
}

bool DevDetect::checkNVMe(const std::string& d) {
    return d.find("nvme") != std::string::npos;
}

bool DevDetect::checkSD(const std::string& d) {
    return d.find("mmcblk") != std::string::npos;
}

bool DevDetect::isRemovable(const std::string& syspath) {
    return readSysFile(syspath + "/removable") == "1";
}

/*
 * Identifica y clasifica el tipo de dispositivo de almacenamiento.
 * Good Taste: Usamos Early Returns y eliminamos los if anidados.
 */
DevType DevDetect::detect(const std::string& device) {
    std::string_view devname = device;
    if (devname.starts_with("/dev/")) {
        devname.remove_prefix(5);
    }

    // Detección por nombre (sin I/O)
    if (checkNVMe(std::string(devname))) return DevType::NVME;
    if (checkSD(std::string(devname)))   return DevType::SD_CARD;

    // 2Detección por sysfs (I/O)
    std::string syspath = getSysPath(device);

    // Si es USB o extraíble, intentamos leer la velocidad.
    if (checkUSB(syspath) || isRemovable(syspath)) {
        try {
            // Si falla y asume USB2.
            return std::stoi(readSpeed(syspath)) >= 500 ? DevType::USB3 : DevType::USB2;
        }   catch (...) {
            return DevType::USB2;
        }
    }

    //  Si no es USB/SD, evaluamos si es HDD o SSD.
    std::string rot_val = readSysFile(syspath + "/queue/rotational");
    
    // Si está vacío, salimos temprano.
    if (rot_val.empty()) return DevType::UNKNOWN;

    // "rot_val" tiene algo xd.
    return rot_val == "0" ? DevType::SSD_SATA : DevType::HDD;
}