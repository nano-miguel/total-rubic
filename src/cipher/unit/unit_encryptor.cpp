// cipher/unit/unit_encryptor.cpp - 0.1 alpha
#include "../unit_encryptor.h"
#include "../../keygest/key_manager.h"

#include <limits.h>
#include <sys/wait.h>
#include <filesystem>
#include <fcntl.h>
#include <span>
#include <stdexcept>
#include <cstdio> 

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <mntent.h>
#include <sys/mman.h>
#include <sys/statvfs.h>

/* Declaración para el worker */
namespace UnitEvents {
    void print_cli(LogLevel level, LogEvent event, const std::string& data);
    void print_cli_progress(uint64_t cur, uint64_t total, double speed);
    void print_worker_result(bool ok);
}

/* StorUnit */
std::string StorUnit::formatBytes(uint64_t bytes) {
    const char* s[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0; 
    double d = bytes;
    while (d >= 1024.0 && i < 4) { d /= 1024.0; i++; }
    std::stringstream ss;ss << std::fixed << std::setprecision(2) << d << " " << s[i];
    return ss.str();
}

std::string StorUnit::getSafeFSType() const {
    if (strlen(fs_info.fstype) == 0) 
        return "";
    for (size_t i = 0; i < strlen(fs_info.fstype); i++)
        if (!isprint(fs_info.fstype[i])) 
            return "";
    return std::string(fs_info.fstype);
}

/* UnitEncryptor */
UnitEncryptor::UnitEncryptor() : last_refresh(0) {
    refreshUnits();
}

bool UnitEncryptor::setDirectKeyHex(
    const std::string& hexKey, std::string& error_out) {
    if (hexKey.length() != 64) {
        useDirectKey = false; 
        error_out = "err_hex_len_64"; 
        return false;
    }
    try {
        Botan::secure_vector<uint8_t> k(32);
        for (size_t i = 0; i < 64; i += 2) {
            k[i/2] = static_cast<uint8_t>(std::stoul(hexKey.substr(i, 2), nullptr, 16));
        }
        directKey = k;
        useDirectKey = true;
        keyManager = nullptr;
        return true;
    } catch (const std::exception&) {
        useDirectKey = false;
        error_out = "err_hex_invalid"; 
        return false;
    }
}

bool UnitEncryptor::hasKey() const {
    if (useDirectKey) return !directKey.empty();
    return keyManager && !keyManager->getActiveKeys().empty();
}

void UnitEncryptor::refreshUnits() {
    if (time(nullptr) - last_refresh > 2) {
        cached_units = detectUnits();
        last_refresh = time(nullptr);
    }
}

bool UnitEncryptor::isPhysicalDevice(const std::string& p) {
    return p.find("/dev/loop") == std::string::npos && p.find("/dev/ram") == std::string::npos;
}

std::string UnitEncryptor::getParentDevice(const std::string& path) {
    std::string dev = path;
    if (dev.find("/dev/") == 0) dev = dev.substr(5);
    
    if (dev.find("nvme") == 0) {
        size_t p = dev.find('p');
        return "/dev/" + (p != std::string::npos ? dev.substr(0, p) : dev);
    }
    size_t p = dev.find_first_of("0123456789");
    return p != std::string::npos ? "/dev/" + dev.substr(0, p) : "";
}

// FIX TICKET #2: Detección real de particiones (funciona en SATA, NVMe, MMC)
bool UnitEncryptor::isPartition(const std::string& dev) {
    std::string devname = std::filesystem::path(dev).filename().string();
    struct stat st;
    return stat(("/sys/class/block/" + devname + "/partition").c_str(), &st) == 0;
}

// Contiene al sistema operativo usando lsblk (Seguro contra Command Injection)
bool UnitEncryptor::isSystemDisk(const std::string& path) {
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

FSInfo UnitEncryptor::getFSInfo(const std::string& path) {
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

bool UnitEncryptor::isUnitEncrypt(
    const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0) 
    return false;EncUnitHdr hdr;
    bool ok = read_enc_header(fd, hdr);close(fd);
    return ok;
}

bool UnitEncryptor::readHdr(
    int fd, EncUnitHdr& hdr) {
    return read_enc_header(fd, hdr);
}

bool UnitEncryptor::writeHdr(
    int fd, const EncUnitHdr& hdr) {
    ssize_t w = -1;
    {
        DirectIOGuard guard(fd);
        if (!guard.valid()) return false;
        w = pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    }
    if (w != sizeof(hdr)) return false;
    if (fsync(fd) != 0) return false;
    return true;
}

// Extrae toda la metadata de un dispositivo (DRY Principle)
void UnitEncryptor::gather_device_data(StorUnit& u) {
    std::string devname = std::filesystem::path(u.device_path).filename().string();
    
    std::ifstream sf("/sys/class/block/" + devname + "/size");
    uint64_t sectors = 0;
    if (sf >> sectors) u.total_size = sectors * 512ULL;

    int fd = open(u.device_path.c_str(), O_RDONLY);
    if (fd >= 0) {
        u.is_encrypted = isUnitEncrypt(u.device_path);
        u.fs_info = getFSInfo(u.device_path);
        u.label = u.fs_info.label;close(fd);
    } 
    else if (errno == EACCES || errno == EPERM) {
        u.requires_elevation = true;
    }
        u.device_type = DevDetect::detect(u.device_path);
        u.has_header_backup = backup_mgr.backupExists(u.device_path);
        u.is_system_disk = isSystemDisk(u.device_path);
        u.parent_device = getParentDevice(u.device_path);
        u.is_partition = isPartition(u.device_path); 
}

std::vector<StorUnit> UnitEncryptor::detectUnits() {
    std::map<std::string, StorUnit> uniq;
    std::set<std::string> seen;
    std::string root_dev;

    std::ifstream mounts("/proc/mounts");
    std::string line;

    // 1. Escanear montados
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

    // 2. Escanear /dev
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

    // 3. Vectorizar y ordenar
    std::vector<StorUnit> units;
    units.reserve(uniq.size());
    for (auto& p : uniq) units.push_back(p.second);

    std::sort(units.begin(), units.end(), [](const StorUnit& a, const StorUnit& b) {
        if (a.is_system_disk != b.is_system_disk) 
            
        return a.is_system_disk > b.is_system_disk;
        return a.total_size > b.total_size;
    });

    return units;
}

std::vector<StorUnit> UnitEncryptor::getUnits() { refreshUnits(); 
        return cached_units; }
void UnitEncryptor::refresh() { cached_units = detectUnits(); last_refresh = time(nullptr); }
void UnitEncryptor::reloadCustomConfig() { settings_.load(); }

bool UnitEncryptor::validateUnitProcess(
    const StorUnit& unit,
     bool encrypt,
     const Botan::secure_vector<uint8_t>& master_key) {

    if (encrypt && unit.is_encrypted) { 
        log(LogLevel::Warning, LogEvent::UnitAlreadyEncrypted, ""); 
        return false; }
    if (!encrypt && !unit.is_encrypted) { 
        log(LogLevel::Warning, LogEvent::UnitNotEncrypted, "");
         return false; }
    if (unit.is_system_disk) {
         log(LogLevel::Error, LogEvent::SystemDiskBlocked, ""); 
         return false; }
    if (unit.is_mounted) { 
        log(LogLevel::Warning, LogEvent::UnitMounted, unit.mount_point);
         return false; }

    if (master_key.empty() || master_key.size() != 32) { 
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
         return false; }
    if (geteuid() != 0) { 
        log(LogLevel::Error, LogEvent::RequiresRoot, "");
         return false; }
    return true;
}

bool UnitEncryptor::processUnit(StorUnit& unit,
     bool encrypt,
     const Botan::secure_vector<uint8_t>& master_key) {
    if (!validateUnitProcess(unit, encrypt, master_key))
        return false;
    
    stop_requested = false;
    processing_active = true;
    speed_meter.reset();
    stats = Stats();

    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = doProcess(unit, master_key, encrypt);
    auto t1 = std::chrono::high_resolution_clock::now();
    processing_active = false;

    if (ok) {
        stats.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        stats.total_bytes = speed_meter.getTotalBytes();
        stats.avg_speed_mbps = speed_meter.getAvgSpeed();
        stats.peak_speed_mbps = speed_meter.getPeakSpeed();
        unit.is_encrypted = encrypt;
        unit.has_header_backup = encrypt;
        refreshUnits();
    }
    return ok;
}

bool UnitEncryptor::doProcess(
    const StorUnit& unit,
     const Botan::secure_vector<uint8_t>& master_key,
      bool encrypt) {
    ThCfg cfg = settings_.resolveConfig(unit.device_type);

    log(LogLevel::Info, LogEvent::DeviceTypeDetected, unit.getDevTypeStr());
    log(LogLevel::Info, settings_.isCustomMode() ? LogEvent::ConfigCustom : LogEvent::ConfigAuto,
        std::to_string(cfg.num_threads) + " threads");
    log(LogLevel::Info, LogEvent::ChunkSizeInfo,
        std::to_string(cfg.chunk_size_mb));
    log(LogLevel::Info, LogEvent::IoModeInfo, cfg.use_direct_io ? "direct" : "normal");

    int flags = O_RDWR | O_SYNC;
    if (cfg.use_direct_io) flags |= O_DIRECT;
    int fd = open(unit.device_path.c_str(), flags);
    
    if (fd < 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));

    if (cfg.use_direct_io && errno == EINVAL) {
        log(LogLevel::Warning, LogEvent::DeviceOpenRetry, strerror(errno));
            flags &= ~O_DIRECT;fd = open(unit.device_path.c_str(), flags);

            if (fd < 0) return false;
            cfg.use_direct_io = false;
        } else {
            return false;
        }
    }

    uint64_t total_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) {
        log(LogLevel::Error, LogEvent::DeviceSizeFailed, strerror(errno));
        close(fd);
        return false;
    }

    uint64_t total_sectors = total_size / SECTOR_SIZE;
    uint64_t data_start_sector = DATA_OFFSET_SECTORS;
    Botan::secure_vector<uint8_t> xts_key;
    FSInfo fs_info = unit.fs_info;

    auto log_cb = [this](LogLevel l, LogEvent e,
    const std::string& d) { this->log(l, e, d); };
    bool header_ok = false;

    if (encrypt) {
        if (strlen(fs_info.fstype) == 0) fs_info = getFSInfo(unit.device_path);
        header_ok = unit_pipeline::HeaderProcesEncrypt(fd, unit, master_key, data_start_sector, total_sectors, backup_mgr, xts_key, fs_info, log_cb);
    } else {
        header_ok = unit_pipeline::HeaderProcessoDecrypt(fd, unit, master_key, backup_mgr, xts_key, data_start_sector, fs_info, log_cb);
        if (header_ok && (data_start_sector >= total_sectors || data_start_sector < DATA_OFFSET_SECTORS)) {
            log(LogLevel::Error, LogEvent::InvalidHeaderRegion, "");
            header_ok = false;
        }
    }

    if (!header_ok) {
        close(fd);
        return false;
    }

    uint64_t data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;
    unit_pipeline::ProcessContext pipe_ctx{
        fd, data_size, data_start_sector, cfg, unit.device_type, xts_key, encrypt,
        speed_meter, stop_requested, log_cb,
        [this](uint64_t c, uint64_t t, double s) { this->progress(c, t, s); }
    };

    bool pipeline_ok = unit_pipeline::runDataPipeline(pipe_ctx);

    if (encrypt && pipeline_ok) {
        uint8_t zeros[512] = {0};
        if (safe_pwrite(fd, zeros, sizeof(zeros), 0) && fsync(fd) == 0) {
            log(LogLevel::Info, LogEvent::Sector0Wiped, ""); 
        } else {
            log(LogLevel::Warning, LogEvent::Sector0WipeFailed, ""); 
        }
    }

    if (!encrypt && pipeline_ok) {
        log(LogLevel::Info, LogEvent::CleanupHeader, "");
        size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(hsz, 0);

        if (safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE)) {
            if (fsync(fd) == 0) {
                log(LogLevel::Success, LogEvent::HeaderRemoved, ""); }
            else {
                log(LogLevel::Error, LogEvent::HeaderCleanFsyncFailed, "");
                pipeline_ok = false; 
            }
        }   else {
                log(LogLevel::Error, LogEvent::HeaderCleanWriteFailed, "");
                pipeline_ok = false; 
        }

        if (backup_mgr.removeBackup(unit.device_path))
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
    }

    close(fd);
    return pipeline_ok;
}

bool UnitEncryptor::cleanHeader(
    const StorUnit& unit) {
    log(LogLevel::Info, LogEvent::CleanupHeader, unit.device_path);
    
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { 
    log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));
        return false; 
    }
    
    size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
    std::vector<uint8_t> zeros(hsz, 0);
    bool ok = safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE);

    if (ok && fsync(fd) != 0) ok = false;
    close(fd);

    if (!ok) { 
        log(LogLevel::Error, LogEvent::HeaderCleanFailed, "");
        return false; 
    }
    
    log(LogLevel::Success, LogEvent::HeaderRemoved, "");
    if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
    log(LogLevel::Success, LogEvent::BackupRemoved, "");
    return true;
}

bool UnitEncryptor::restoreHeader(
    const StorUnit& unit,
     const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info, LogEvent::HeaderRestoring, ""); EncUnitHdr hdr;

    if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
        log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
        return false;
    }
    
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { 
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); 
        return false;
    }
    
    if (!writeHdr(fd, hdr)) {
        log(LogLevel::Error, LogEvent::HeaderRestoreFailed, "");
        close(fd);
        return false;
    }

    close(fd);
    log(LogLevel::Success, LogEvent::HeaderRestored, "");
    return true;
}

// SISTEMA OPERATIVO
int UnitEncryptor::safeExec(
    const std::vector<std::string>& args,
     bool need_sudo) {
    if (args.empty()) return -1;

    pid_t pid = fork();
    if (pid == -1) return -1;

    if (pid == 0) {
        // Sanitizar el PATH para evitar ejecución de binarios maliciosos
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);

        std::vector<char*> c_args;
        if (need_sudo && geteuid() != 0) {
            c_args.push_back(const_cast<char*>("sudo"));
            c_args.push_back(const_cast<char*>("-n"));
        }
        for (const auto& arg : args) {
            c_args.push_back(const_cast<char*>(arg.c_str()));
        }   
            c_args.push_back(nullptr);
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
    log(LogLevel::Info, LogEvent::Mounting, point);
    safeExec({"mkdir", "-p", point}, true);
    std::string fs = u.filesystem;
    
    if (fs.empty() && strlen(u.fs_info.fstype) > 0)
        fs = u.getSafeFSType();
        
    int ret = fs.empty() ? safeExec(
        {"mount", u.device_path, point}, true) : safeExec(
        {"mount", "-t", fs, u.device_path, point}, true);
    
    if (ret == 0) {
        log(LogLevel::Success, 
            LogEvent::Mounted, point);
        return true;
    }
        log(LogLevel::Error,
            LogEvent::MountFailed,
        std::to_string(ret));
        return false;
}

bool UnitEncryptor::unmountDevice(StorUnit& u) {
    if (!u.is_mounted)
        return true;
    log(LogLevel::Info,
         LogEvent::Unmounting, u.mount_point);
    
    safeExec({"umount", "-l", u.mount_point}, true);
    
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
    if (line.find(u.device_path) != std::string::npos)
        return false;
    }
    
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
    
    if (fstype == "vfat" || fstype == "fat32") res = safeExec({"mkfs.vfat", "-F", "32", unit.device_path}, true);
    else if (fstype == "ntfs") res = safeExec(
        {"mkfs.ntfs", "-f", unit.device_path}, true);
    else if (fstype == "ext4") res = safeExec(
        {"mkfs.ext4", "-F", unit.device_path}, true);
    else res = safeExec({"mkfs." + fstype, unit.device_path}, true);

    if (res == 0) {
        log(LogLevel::Success, LogEvent::FormatOk, "");
        return true;
    }
        log(LogLevel::Error, LogEvent::FormatFailed, std::to_string(res));
        return false;
}

bool UnitEncryptor::executeElevatedOp(
    const StorUnit& unit, bool encrypt,
     const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.empty() || master_key.size() != 32)
        return false;

    // TRUCO DE SEGURIDAD: El archivo se borra del sistema apenas se abre.
    char keyfile[] = "/dev/shm/.rubic_key_XXXXXX";
    int kfd = mkstemp(keyfile);
    if (kfd < 0) return false;

    unlink(keyfile); // El archivo ya no tiene nombre, pero el fd (kfd) sigue vivo.
    fchmod(kfd, 0600);
    
    bool write_ok = (write(kfd,
        master_key.data(),
        master_key.size()) == (ssize_t)
        master_key.size());
    fsync(kfd);
    close(kfd);

    if (!write_ok) return false;

    // Como borramos el archivo, el hijo no puede abrirlo por nombre. 
    // Pero como es un fork, el hijo HEREDA el fd (kfd).
    pid_t pid = fork();
    if (pid < 0) return false;

    if (pid == 0) {
        const char* env_lang = getenv("LANG");
        std::string cur_lang = env_lang ? env_lang : "en";
        setenv("LANG", cur_lang.c_str(), 1);
        
        const char* sudo_path = "/usr/bin/sudo";
        if (access(sudo_path, X_OK) != 0) sudo_path = "/bin/sudo";

        // Pasamos el fd heredado
        execl(sudo_path, "sudo", "/proc/self/exe", "--unit-op",
              unit.device_path.c_str(),
              encrypt ? "encrypt" : "decrypt",
              "--keyfd", std::to_string(kfd).c_str(), nullptr);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);

    if (!WIFEXITED(status)) return false;
    return WEXITSTATUS(status) == 0;
}

// WORKER CLI
struct WorkerArgs {
    std::string device;
    bool encrypt;
    int keyfd = -1;
};

static bool parseWorkerArgs(
    int argc, char* argv[], WorkerArgs& args) {
    if (argc < 6) return false;args.device = argv[2];
    std::string action = argv[3];

    if (args.device.rfind("/dev/", 0) != 0) return false;
    if (action == "encrypt") args.encrypt = true;
    else if (action == "decrypt") args.encrypt = false;
    else return false;

    for (int i = 4; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--keyfd") {
            args.keyfd = std::stoi(argv[i + 1]);
        break;
        }
    }
    return args.keyfd >= 0;
}

int UnitEncryptor::tryRunAsWorker(int argc, char* argv[]) {
    if (argc < 2 || std::string(argv[1]) != "--unit-op") 
        return -1;
    if (geteuid() != 0) { std::cerr << "[-] --unit-op requiere sudo (root).\n"; 
        return 1; }

    WorkerArgs args;
    if (!parseWorkerArgs(argc, argv, args)) return 1;

    Botan::secure_vector<uint8_t> master_key(32);
    ssize_t r = read(args.keyfd, master_key.data(), 32);
    close(args.keyfd);
    
    if (r != 32) return 1;

    StorUnit u;
        u.device_path = args.device;
        u.is_encrypted = !args.encrypt;
        u.is_mounted = false;
        u.is_system_disk = false;
        u.device_type = DevDetect::detect(args.device);

    UnitEncryptor enc;
        enc.setLogCallback([](LogLevel level, LogEvent event,const std::string& data) {
        UnitEvents::print_cli(level, event, data);
    });
        enc.setProgressCallback([](uint64_t cur, uint64_t total,double speed) {
        UnitEvents::print_cli_progress(cur, total, speed);
    });

    bool ok = enc.processUnit(u, args.encrypt, master_key);
    UnitEvents::print_worker_result(ok);
    
    return ok ? 0 : 1;
}
