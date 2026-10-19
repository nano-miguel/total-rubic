// cipher/unit/devdetect.cpp
#include "../unit_encryptor.h" 

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <unistd.h>
#include <string>

namespace {
    // Helper privado a para leer una línea de sysfs 
    std::string readSysFile(const std::string& path) {
         std::ifstream file(path);
        if (!file.is_open()) return "";
         std::string line;
        if (std::getline(file, line)) {
            // Limpiar saltos de línea al final
            line.erase(line.find_last_not_of(" \n\r\t") + 1);
         return line;
        }
        return "";
    }
}

std::string DevDetect::getSysPath(const std::string& device){
    std::string devname = device;
    if (devname.rfind("/dev/", 0) == 0) {
        devname.erase(0, 5);
    }
    while (!devname.empty() && std::isdigit(static_cast<unsigned char>(devname.back()))) {
            devname.pop_back();
    }
    return "/sys/block/" + devname;
}

bool DevDetect::checkUSB(const std::string& syspath) {
    // 1. Revisar uevent usando el helper de streams
    std::ifstream uevent_file(syspath + "/device/uevent");
    std::string line;
    while (std::getline(uevent_file, line)) {
        std::string upper_line = line;
        std::transform(upper_line.begin(), upper_line.end(), upper_line.begin(), ::toupper);
        if (upper_line.find("USB") != std::string::npos) {
            return true;
        }
    }

    // 2. Verificar enlace simbólico
    char buf[256];
    ssize_t len = readlink(syspath.c_str(), buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        if (std::string(buf).find("usb") != std::string::npos) {
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
    std::string val = readSysFile(syspath + "/removable");
    return val == "1";
}

DevType DevDetect::detect(const std::string& device) {
    std::string devname = device;
    if (devname.rfind("/dev/", 0) == 0) devname.erase(0, 5);

    if (checkNVMe(devname)) return DevType::NVME;
    if (checkSD(devname))   return DevType::SD_CARD;

    std::string syspath = getSysPath(device);

    if (checkUSB(syspath) || isRemovable(syspath)) {
        std::string speed_str = readSpeed(syspath);
        if (!speed_str.empty()) {
            try {
                return std::stoi(speed_str) >= 500 ? DevType::USB3 : DevType::USB2;
            }   catch (...) {
                return DevType::USB2;
            }
        }
        return DevType::USB2;
    }

    std::string rot_val = readSysFile(syspath + "/queue/rotational");
    if (!rot_val.empty()) {
        return rot_val == "0" ? DevType::SSD_SATA : DevType::HDD;
    }

    return DevType::UNKNOWN; //nosabo
}
