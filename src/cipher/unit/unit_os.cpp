// cipher/unit/unit_os.cpp
#include "../unit_encryptor.h"
#include <sys/wait.h>
#include <unistd.h>

int UnitEncryptor::safeExec(
    const std::vector<std::string>& args,
    bool need_sudo) {
    if (args.empty()) return -1;

    pid_t pid = fork();
    if (pid == -1) return -1;

    if (pid == 0) {
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);

        std::vector<char*> c_args;
        if (need_sudo && geteuid() != 0) {
            c_args.push_back(const_cast<char*>("sudo"));
            c_args.push_back(const_cast<char*>("-n")); 
        }
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }   c_args.push_back(nullptr);

        execvp(c_args[0], c_args.data());
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

bool UnitEncryptor::mountDevice(
    const StorUnit& u,
    const std::string& point) {
        log(LogLevel::Info, LogEvent::Mounting, point);safeExec(
        {"mkdir", "-p", point}, true);

        std::string fs = u.filesystem;
    
    if (fs.empty() && strlen(u.fs_info.fstype) > 0)
        fs = u.getSafeFSType();
        
    int ret = fs.empty() ? safeExec({"mount", u.device_path, point}, true) 
                         : safeExec({"mount", "-t", fs, u.device_path, point}, true);
    
    if (ret == 0) {
        log(LogLevel::Success, LogEvent::Mounted, point);
        return true;}
        log(LogLevel::Error, LogEvent::MountFailed, std::to_string(ret));
        return false;
}

bool UnitEncryptor::unmountDevice(StorUnit& u) {
    if (!u.is_mounted) return true;
    log(LogLevel::Info, LogEvent::Unmounting, u.mount_point);
    
    safeExec({"umount", "-l", u.mount_point}, true);

    std::ifstream mounts("/proc/mounts");
    std::string line;

    while (std::getline(mounts, line))
        if (line.find(u.device_path) != std::string::npos)
            return false;
            
    u.is_mounted = false;
    u.mount_point.clear();
    log(LogLevel::Success, LogEvent::Unmounted, "");
    return true;
}

bool UnitEncryptor::formatDevice(
    const StorUnit& unit,
    const std::string& fstype) {
    log(LogLevel::Info, LogEvent::FormatStart, fstype);

    int res = -1;
    if (fstype == "vfat" || fstype == "fat32") res = safeExec(
        {"mkfs.vfat", "-F", "32", unit.device_path}, true);
    else if (fstype == "ntfs") res = safeExec(
        {"mkfs.ntfs", "-f", unit.device_path}, true);
    else if (fstype == "ext4") res = safeExec(
        {"mkfs.ext4", "-F", unit.device_path}, true);
    else res = safeExec(
        {"mkfs." + fstype, unit.device_path}, true);

    if (res == 0) {
        log(LogLevel::Success, LogEvent::FormatOk, "");
        return true;
    }
    log(LogLevel::Error, LogEvent::FormatFailed, std::to_string(res));
    return false;
}
