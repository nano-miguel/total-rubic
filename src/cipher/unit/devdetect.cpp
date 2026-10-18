// cipher/unit/devdetect.cpp
#include "../unit_encryptor.h" 

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <unistd.h>
#include <string>

std::string DevDetect::getSysPath(const std::string& device) {
    std::string devname = device;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
        while(!devname.empty() && isdigit(static_cast<unsigned char>(devname.back())))
                devname.pop_back();
    return "/sys/block/" + devname;
}

bool DevDetect::checkUSB(const std::string& syspath) {
    std::string uevent = syspath + "/device/uevent";
    FILE* f = fopen(uevent.c_str(), "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) 
        {
            if (strstr(line, "USB") || strstr(line, "usb")) {
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    char buf[256];
    ssize_t len = readlink(syspath.c_str(), buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        if (std::string(buf).find("usb") != std::string::npos) return true;
    }
    return false;
}

std::string DevDetect::readSpeed(const std::string& syspath) {
    FILE* f = fopen((syspath + "/device/speed").c_str(), "r");
    if (!f) return "";
     char speed[32];
    if (fgets(speed, sizeof(speed), f)) {
        speed[strcspn(speed, "\n")] = 0;
        fclose(f);
        return speed;
    }
        fclose(f);
    return "";
}

bool DevDetect::checkNVMe(const std::string& d) {
    return d.find("nvme") != std::string::npos;
}

bool DevDetect::checkSD(const std::string& d) {
    return d.find("mmcblk") != std::string::npos;
}

bool DevDetect::isRemovable(const std::string& syspath) {
    FILE* f = fopen((syspath + "/removable").c_str(), "r");
    if (f) {
        char r;
         if (fscanf(f, "%c", &r) == 1) {
            fclose(f);
            return r == '1';
        }
        fclose(f);
    }
    return false;
}

DevType DevDetect::detect(const std::string& device)
{
    std::string devname = device;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);

    if (checkNVMe(devname)) return DevType::NVME;
    if (checkSD(devname))   return DevType::SD_CARD;

    std::string syspath = getSysPath(device);

    if (checkUSB(syspath) || isRemovable(syspath))

    {
        std::string speed = readSpeed(syspath);
        if (!speed.empty())
            return atoi(speed.c_str()) >= 500 ? DevType::USB3 : DevType::USB2;
            return DevType::USB2;
    }

    FILE* f = fopen((syspath + "/queue/rotational").c_str(), "r");
     if (f) {
        char rot;
         if (fscanf(f, "%c", &rot) == 1) {
            fclose(f);
            return rot == '0' ? DevType::SSD_SATA : DevType::HDD;
        }
        fclose(f);
    }

    return DevType::UNKNOWN;
}