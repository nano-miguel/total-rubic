// cipher/unit/device/read-unit.cpp
#include "../unit_encryptor.h"

#include <filesystem>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fstream>
#include <sstream>

bool UnitEncryptor::isPhysicalDevice(
    const std::string& p) {
    return p.find("/dev/loop") ==
        std::string::npos && p.find("/dev/ram") ==
        std::string::npos;
}

std::string UnitEncryptor::getParentDevice(
    const std::string& path) {
        std::string dev = path;

    if (dev.find("/dev/") == 0) dev = dev.substr(5);
    if (dev.find("nvme") == 0) {
        size_t p = dev.find('p');
        return "/dev/" + (p != std::string::npos ? dev.substr(0, p) : dev);
    }
    size_t p = dev.find_first_of("0123456789");
        return p != std::string::npos ? "/dev/" + dev.substr(0, p) : "";
}

bool UnitEncryptor::isSystemDisk(
    const std::string& path) {
    int pipefd[2];
    if (pipe(pipefd) == -1) return true; // Fail-safe

    pid_t pid = fork();
    if (pid == -1) {
        close(pipefd[0]); close(pipefd[1]);
        return true; // Fail-safe
    }

    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        const char* lsblk_path = "/usr/bin/lsblk";
        if (access(lsblk_path, X_OK) != 0) lsblk_path = "/bin/lsblk";

        execl(lsblk_path, "lsblk", "-rno", "MOUNTPOINTS", path.c_str(), nullptr);
        _exit(127); 
    }

    close(pipefd[1]);
    char buffer[256];
    bool is_system = false;
    ssize_t n;

    while ((n = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[n] = '\0';
        std::string output(buffer);
        if (output.find("/\n") != std::string::npos ||
            output.find("/boot") != std::string::npos ||
            output.find("[SWAP]") != std::string::npos) {
            is_system = true;
            break;
        }
    }

    close(pipefd[0]);
    waitpid(pid, nullptr, 0);
    return is_system;
}

FSInfo UnitEncryptor::getFSInfo(
    const std::string& path) {
    FSInfo info;
        std::ifstream mounts("/proc/mounts");
        std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fs;
        iss >> dev >> mnt >> fs;
        if (dev == path) {
            strncpy(info.fstype, fs.c_str(), sizeof(info.fstype) - 1);
            return info;
        }
    }
    return info;
}

bool UnitEncryptor::isPartition(
    const std::string& dev) {
    std::string devname = std::filesystem::path(dev).filename().string();
    struct stat st;
    return stat(("/sys/class/block/" + devname + "/partition").c_str(), &st) == 0;
}

void UnitEncryptor::gather_device_data(
    StorUnit& u) {
    std::string devname = std::filesystem::path(u.device_path).filename().string();
    
    std::ifstream sf("/sys/class/block/" + devname + "/size");
    uint64_t sectors = 0;
    if (sf >> sectors) u.total_size = sectors * 512ULL;

    int fd = open(u.device_path.c_str(), O_RDONLY);
    if (fd >= 0) {
        u.is_encrypted = isUnitEncrypt(u.device_path);
        u.fs_info = getFSInfo(u.device_path);
        u.label = u.fs_info.label;
        close(fd);
    } else if (errno == EACCES || errno == EPERM) {
        u.requires_elevation = true;
    }
    
    u.device_type = DevDetect::detect(u.device_path);
    u.has_header_backup = backup_mgr.backupExists(u.device_path);
    u.is_system_disk = isSystemDisk(u.device_path);
    u.parent_device = getParentDevice(u.device_path);
    u.is_partition = isPartition(u.device_path); 
}

std::vector<StorUnit> UnitEncryptor::detectUnits() {
    std::vector<StorUnit> units;
    std::map<std::string, StorUnit> uniq;
    std::set<std::string> seen;
    std::string root_dev;

    std::ifstream mounts("/proc/mounts");
    std::string line;

    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fs;
        iss >> dev >> mnt >> fs;

        if (mnt == "/") root_dev = dev; 
        if (dev.find("/dev/") != 0 || !isPhysicalDevice(dev)) continue;

        StorUnit u;
        u.device_path = dev;
        u.mount_point = mnt;
        u.filesystem = fs;
        u.is_mounted = true;
        
        gather_device_data(u);
        uniq[dev] = u;
        seen.insert(dev);
    }

    DIR* d = opendir("/dev");
    if (d) {
        struct dirent* e;
        while ((e = readdir(d))) {
            std::string name = e->d_name;
            std::string dev = "/dev/" + name;

            if ((name.find("sd") != 0 && name.find("hd") != 0 && 
                 name.find("nvme") != 0 && name.find("mmcblk") != 0) ||
                seen.count(dev) || !isPhysicalDevice(dev)) continue;

            if (!isPartition(dev)) {
                bool has_parts = false;
                for (auto& p : uniq) {
                    if (p.second.parent_device == dev) { has_parts = true; break; }
                }
                if (has_parts) continue;
            }

            StorUnit u;
            u.device_path = dev;
            gather_device_data(u);
            if (u.total_size > 0) uniq[dev] = u;
        }
        closedir(d);
    }

    units.reserve(uniq.size());
    for (auto& p : uniq) units.push_back(p.second);
        
    std::sort(units.begin(), units.end(), [](
        const StorUnit& a, const StorUnit& b) {
        if (a.is_system_disk != b.is_system_disk) 
            return a.is_system_disk > b.is_system_disk;
            return a.total_size > b.total_size;
    }); 
    return units;
}

std::vector<StorUnit> UnitEncryptor::getUnits() { 
    refreshUnits();
    return cached_units; 
}

void UnitEncryptor::refresh() { 
    cached_units = detectUnits(); 
    last_refresh = time(nullptr); 
}
