// cipher/unit/unit_encryptor.cpp - 0.1 alpha
#include "../unit_encryptor.h"
#include "../../keygest/key_manager.h"

#include <limits.h>
#include <sys/wait.h>
#include <filesystem>
#include <fcntl.h>
#include <span>
#include <stdexcept>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <mntent.h>
#include <sys/mman.h>
#include <sys/statvfs.h>

// Declaración de las funciones de presentación para el worker (viven en unit_events.cpp)
namespace UnitEvents {
    void print_cli(LogLevel level, LogEvent event, const std::string& data);
    void print_cli_progress(uint64_t cur, uint64_t total, double speed);
}

/* AlignBuf*/
AlignBuf::AlignBuf(size_t size) : data_ptr(nullptr), size_bytes(size) {
    if (posix_memalign(&data_ptr, ALIGNMENT, size) != 0) throw std::bad_alloc();
    memset(data_ptr, 0, size);
}

AlignBuf::~AlignBuf() {
    if (data_ptr) {
        rubic_sec::secure_wipe(data_ptr, size_bytes);
        free(data_ptr);
    }
}

AlignBuf::AlignBuf(AlignBuf&& other) noexcept
    : data_ptr(other.data_ptr), size_bytes(other.size_bytes) {
    other.data_ptr = nullptr;
    other.size_bytes = 0;
}

AlignBuf& AlignBuf::operator=(AlignBuf&& other) noexcept {
    if (this != &other) {
    if (data_ptr) {
        rubic_sec::secure_wipe(data_ptr, size_bytes);
        free(data_ptr);
        }
        data_ptr = other.data_ptr;
        size_bytes = other.size_bytes;
        other.data_ptr = nullptr;
        other.size_bytes = 0;
    }
    return *this;
}

uint8_t* AlignBuf::data() { 
    return static_cast<uint8_t*>(data_ptr); }
const uint8_t* AlignBuf::data() const { 
    return static_cast<const uint8_t*>(data_ptr); }
size_t AlignBuf::size() const { 
    return size_bytes; }

// ============================================
// SpeedMtr
// esto podria ir en pipeline xd 

SpeedMtr::SpeedMtr() { reset(); }
void SpeedMtr::addBytes(uint64_t b) { total_bytes += b; }
double SpeedMtr::getCurrentSpeed() {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();
    if (ms >= 200) {
        uint64_t cur = total_bytes.load();
        double speed = ((cur - last_bytes) / 1048576.0) / (ms / 1000.0);
        current_speed = speed;
    if (speed > peak_speed) peak_speed = speed;
        last_bytes = cur;
        last_time = now;
    }
    return current_speed.load();
}
double SpeedMtr::getAvgSpeed() {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
    return ms > 0 ? (total_bytes / 1048576.0) / (ms / 1000.0) : 0;
}
double SpeedMtr::getPeakSpeed() { 
    return peak_speed.load(); }
uint64_t SpeedMtr::getTotalBytes() { 
    return total_bytes.load(); }
void SpeedMtr::reset() {
    start_time = last_time = std::chrono::steady_clock::now();
    total_bytes = last_bytes = 0;
    current_speed = peak_speed = 0;
}

/* StorUnit*/
std::string StorUnit::formatBytes(uint64_t bytes) {
    const char* s[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0; 
    double d = bytes;
    while (d >= 1024.0 && i < 4) { d /= 1024.0; i++; }
    std::stringstream ss;ss << 
    std::fixed << std::setprecision(2) << d << " " << s[i];
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

// FIX: Ahora usa error_out en vez de throw
bool UnitEncryptor::setDirectKeyHex(const std::string& hexKey, std::string& error_out) {
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
    }   catch (const std::exception&) {
        useDirectKey = false;error_out = "err_hex_invalid";
        return false;
    }
}

bool UnitEncryptor::hasKey() const {
    if (useDirectKey) 
    return !directKey.empty();
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

bool UnitEncryptor::isSystemDisk(const std::string& path) {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev, mnt;
            iss >> dev >> mnt;
        if (mnt == "/") 
        return path == dev;
        }
    }
    return false;
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

bool UnitEncryptor::isUnitEncrypt(const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0)
     return false;
    EncUnitHdr hdr;
    bool ok = read_enc_header(fd, hdr);
    close(fd);
    return ok;
}

bool UnitEncryptor::readHdr(int fd, EncUnitHdr& hdr) {
    return read_enc_header(fd, hdr);
}

bool UnitEncryptor::writeHdr(int fd, const EncUnitHdr& hdr) {
    ssize_t w = -1;
    {
        DirectIOGuard guard(fd);
        if (!guard.valid()) 
        return false;
        w = pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    }
    if (w != sizeof(hdr))
        return false;
    if (fsync(fd) != 0) 
        return false;
    return true;
}

std::vector<StorUnit> UnitEncryptor::detectUnits() {
    std::vector<StorUnit> units;
    std::map<std::string, StorUnit> uniq;
    std::set<std::string> seen;
    std::string root_dev;
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev; iss >> dev;
            root_dev = dev;
            break;
        }
    }

    mounts.clear(); mounts.seekg(0);
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fs;iss >> dev >> mnt >> fs;
    if (dev.find("/dev/") != 0 || !isPhysicalDevice(dev)) continue;
        StorUnit u;
        u.device_path = dev;
        u.mount_point = mnt;
        u.filesystem = fs;
        u.is_mounted = true;
        u.is_partition = dev.find_first_of("0123456789") != std::string::npos;
        u.parent_device = getParentDevice(dev);
        u.is_system_disk = dev == root_dev;

        std::string devname = std::filesystem::path(dev).filename().string();
        std::ifstream sf("/sys/class/block/" + devname + "/size");
        uint64_t sectors = 0;
    if (sf >> sectors) u.total_size = sectors * 512ULL;

        int fd = open(dev.c_str(), O_RDONLY);
    if (fd >= 0) {
        u.is_encrypted = isUnitEncrypt(dev);
        u.fs_info = getFSInfo(dev);
        u.label = u.fs_info.label;
        close(fd);
        } 
    else if (errno == EACCES || errno == EPERM) {
            u.requires_elevation = true;
        }
        u.device_type = DevDetect::detect(dev);
        u.has_header_backup = backup_mgr.backupExists(dev);

        uniq[dev] = u;
        seen.insert(dev);
    }

    DIR* d = opendir("/dev");
    if (d) {
        struct dirent* e;
        while ((e = readdir(d))) {
            std::string name = e->d_name;
            std::string dev = "/dev/" + name;
        if ((name.find("sd") == 0 || name.find("hd") == 0 ||name.find("nvme") == 0 || name.find("mmcblk") == 0) &&
            !seen.count(dev) && isPhysicalDevice(dev)) {
            bool is_part = name.find_first_of("0123456789") != std::string::npos;
        if (!is_part) {
            bool has_parts = false;
        for (auto& p : uniq)
        if (p.second.parent_device == dev) { has_parts = true; break; }
        if (has_parts) continue;
                }
            StorUnit u;u.device_path = dev;
            u.is_partition = is_part;
            u.parent_device = getParentDevice(dev);
            u.is_system_disk = dev == root_dev;
            
            std::string devname = std::filesystem::path(dev).filename().string();
            std::ifstream sf("/sys/class/block/" + devname + "/size");
            uint64_t sectors = 0;
        if (sf >> sectors) u.total_size = sectors * 512ULL;
        if (u.total_size > 0) {
            int fd = open(dev.c_str(), O_RDONLY);
        if (fd >= 0) {
            u.is_encrypted = isUnitEncrypt(dev);
            u.fs_info = getFSInfo(dev);
            u.label = u.fs_info.label;
                        close(fd);
                    } 
        else if (errno == EACCES || errno == EPERM) {
            u.requires_elevation = true; }
            u.device_type = DevDetect::detect(dev);
            u.has_header_backup = backup_mgr.backupExists(dev);
            uniq[dev] = u;

                }
            }
        }
        closedir(d);
    }

    units.reserve(uniq.size());
    for (auto& p : uniq) units.push_back(p.second);
    std::sort(units.begin(), units.end(), [](
        const StorUnit& a,
        const StorUnit& b) {
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
    const StorUnit& unit, bool encrypt,
    const Botan::secure_vector<uint8_t>& master_key) {
    if (encrypt && unit.is_encrypted)   { log(LogLevel::Warning, LogEvent::UnitAlreadyEncrypted, "");
        return false; }
    if (!encrypt && !unit.is_encrypted) { log(LogLevel::Warning, LogEvent::UnitNotEncrypted, "");
        return false; }
    if (unit.is_system_disk)            { log(LogLevel::Error,   LogEvent::SystemDiskBlocked, "");
        return false; }
    if (unit.is_mounted)                { log(LogLevel::Warning, LogEvent::UnitMounted, unit.mount_point);
        return false; }
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    if (geteuid() != 0) {
        log(LogLevel::Error, LogEvent::RequiresRoot, "");
        return false;
    }
    return true;
}

bool UnitEncryptor::processUnit(StorUnit& unit, bool encrypt,
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
    const Botan::secure_vector<uint8_t>& master_key, bool encrypt) {
    ThCfg cfg = settings_.resolveConfig(unit.device_type);

    log(LogLevel::Info, LogEvent::DeviceTypeDetected, unit.getDevTypeStr());
    log(LogLevel::Info, settings_.isCustomMode() ? LogEvent::ConfigCustom : LogEvent::ConfigAuto, std::to_string(cfg.num_threads) + " threads");
    log(LogLevel::Info, LogEvent::ChunkSizeInfo, std::to_string(cfg.chunk_size_mb));
    log(LogLevel::Info, LogEvent::IoModeInfo, cfg.use_direct_io ? "direct" : "normal");

        int flags = O_RDWR | O_SYNC;
    if (cfg.use_direct_io) flags |= O_DIRECT;
        int fd = open(unit.device_path.c_str(), flags);
    if (fd < 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));
    if (cfg.use_direct_io && errno == EINVAL) {
        log(LogLevel::Warning, LogEvent::DeviceOpenRetry, strerror(errno));
       flags &= ~O_DIRECT;fd = open(unit.device_path.c_str(), flags);
    if (fd < 0) 
          return false;cfg.use_direct_io = false;
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
        header_ok = unit_pipeline::HeaderProcesEncrypt(
        fd, unit, master_key, data_start_sector, total_sectors, backup_mgr, xts_key, fs_info, log_cb);
    }   else {
        header_ok = unit_pipeline::HeaderProcessoDecrypt(
        fd, unit, master_key, backup_mgr, xts_key, data_start_sector, fs_info, log_cb);
        if (header_ok) {
        if (data_start_sector >= total_sectors || data_start_sector < DATA_OFFSET_SECTORS) {
            log(LogLevel::Error, LogEvent::InvalidHeaderRegion, "");
                header_ok = false;
            }
        }
    }

    if (!header_ok) {
        close(fd);
        return false;
    }

    uint64_t data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;

    unit_pipeline::ProcessContext pipe_ctx{
        fd, data_size, data_start_sector, cfg, unit.device_type, xts_key, encrypt,
        speed_meter, stop_requested,
        log_cb,
        [this](uint64_t c, uint64_t t, double s) { this->progress(c, t, s); }
    };

    bool pipeline_ok = unit_pipeline::runDataPipeline(pipe_ctx);

    if (encrypt && pipeline_ok) {
        uint8_t zeros[512] = {0};
        if (safe_pwrite(fd, zeros, sizeof(zeros), 0) && fsync(fd) == 0) {
        log(LogLevel::Info, LogEvent::Sector0Wiped, "");
        } 
        else {
        log(LogLevel::Warning, LogEvent::Sector0WipeFailed, "");
        }
    }

    if (!encrypt && pipeline_ok) {
        log(LogLevel::Info, LogEvent::CleanupHeader, "");
        size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(hsz, 0);

        if (safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE)) {
            if (fsync(fd) == 0) {
            log(LogLevel::Success, LogEvent::HeaderRemoved, "");
            } 
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
        return false; }
    size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
    std::vector<uint8_t> zeros(hsz, 0);

    bool ok = safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    if (ok) {
    if (fsync(fd) != 0) ok = false;
    }
    close(fd);

    if (!ok) { log(LogLevel::Error, LogEvent::HeaderCleanFailed, "");
        return false; }

    log(LogLevel::Success, LogEvent::HeaderRemoved, "");
    if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
    log(LogLevel::Success, LogEvent::BackupRemoved, "");
        return true;
}

bool UnitEncryptor::restoreHeader(
    const StorUnit& unit,
    const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info, LogEvent::HeaderRestoring, "");
    EncUnitHdr hdr;
    if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
    log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
        return false;
    }
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); 
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

// ========================================================================
// SISTEMA OPERATIVO Y PRIVILEGIOS (Core puro, sin traducciones)
// ========================================================================

int UnitEncryptor::safeExec(const std::vector<std::string>& args, bool need_sudo) {
    if (args.empty())
     return -1;pid_t pid = fork();
    if (pid == -1)
     return -1;
    if (pid == 0) {
        std::vector<char*> c_args;
    if (need_sudo && geteuid() != 0) {
        c_args.push_back(const_cast<char*>("sudo"));
        }
        for (const auto& arg : args) 
        c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);execvp(c_args[0], c_args.data());_exit(127);
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
    if (fs.empty() && strlen(u.fs_info.fstype) > 0) fs = u.getSafeFSType();
    int ret = fs.empty() ? safeExec({"mount", u.device_path, point}, true)
                         : safeExec({"mount", "-t", fs, u.device_path, point}, true);
    if (ret == 0) {
    log(LogLevel::Success, LogEvent::Mounted, point);
        return true;
    }
    log(LogLevel::Error, LogEvent::MountFailed, std::to_string(ret));
        return false;
}

bool UnitEncryptor::unmountDevice(StorUnit& u) {
    if (!u.is_mounted)
        return true;
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
    if (fstype == "vfat" || fstype == "fat32")
        res = safeExec({"mkfs.vfat", "-F", "32", unit.device_path}, true);
    else if (fstype == "ntfs")
        res = safeExec({"mkfs.ntfs", "-f", unit.device_path}, true);
    else if (fstype == "ext4")
        res = safeExec({"mkfs.ext4", "-F", unit.device_path}, true);
    else
        res = safeExec({"mkfs." + fstype, unit.device_path}, true)

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
    if (master_key.empty() || master_key.size() != 32) return false;

    char keyfile[] = "/dev/shm/.rubic_key_XXXXXX";
    int kfd = mkstemp(keyfile);
    if (kfd < 0) 
        return false;
    fchmod(kfd, 0600);
    bool write_ok = (write(kfd,
        master_key.data(),
        master_key.size()) == (ssize_t)master_key.size());fsync(kfd);close(kfd);
    if (!write_ok) { unlink(keyfile);
        return false; }

    char exe[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { unlink(keyfile);
        return false; }
    exe[n] = '\0';

    const char* env_lang = getenv("LANG");
    std::string cur_lang = env_lang ? env_lang : "en";

    pid_t pid = fork();
    if (pid < 0) { unlink(keyfile); 
        return false; }
    if (pid == 0) {
        setenv("LANG", cur_lang.c_str(), 1);
        execlp("sudo", "sudo", exe, "--unit-op",unit.device_path.c_str(),encrypt ? "encrypt" : "decrypt","--keyfile", keyfile, nullptr);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    unlink(keyfile);

    if (!WIFEXITED(status)) 
        return false;
    return WEXITSTATUS(status) == 0;
}

// ========================================================================
// WORKER CLI (El --unit-op, aquí se usa "sudo" y texto crudo)
// ========================================================================

int UnitEncryptor::tryRunAsWorker(int argc, char* argv[]) {
    if (argc < 2) return -1;
    if (std::string(argv[1]) != "--unit-op") return -1;

    if (geteuid() != 0) { std::cerr << "[-] --unit-op requiere sudo (root).\n"; return 1; }
    if (argc < 6) { std::cerr << "[-] Uso: sudo rubic-a --unit-op <device> <encrypt|decrypt> --keyfile <path>\n"; return 1; }
    
    std::string device = argv[2];
    std::string action = argv[3];
    if (device.rfind("/dev/", 0) != 0) { std::cerr << "[-] Dispositivo invalido.\n"; return 1; }
    
    bool encrypt = (action == "encrypt");
    if (!encrypt && action != "decrypt") { std::cerr << "[-] Accion invalida.\n"; return 1; }

    std::string keyfile;
    for (int i = 4; i + 1 < argc; ++i) {
    if (std::string(argv[i]) == "--keyfile") { keyfile = argv[i + 1]; break; }
    }
    if (keyfile.empty()) { std::cerr << "[-] --keyfile requerido.\n"; return 1; }
    if (keyfile.rfind("/dev/shm/.rubic_key_", 0) != 0) { std::cerr << "[-] Ruta de keyfile invalida.\n"; return 1; }

    int kfd = open(keyfile.c_str(), O_RDONLY);
    if (kfd < 0) { std::cerr << "[-] No se pudo abrir el keyfile.\n"; return 1; }
    unlink(keyfile.c_str());

    Botan::secure_vector<uint8_t> master_key(32);
    ssize_t r = read(kfd, master_key.data(), 32);
    close(kfd);
    if (r != 32) { std::cerr << "[-] Error leyendo master key.\n"; return 1; }

    StorUnit u;
    u.device_path = device;
    u.is_encrypted = !encrypt;
    u.is_mounted = false;
    u.is_system_disk = false;
    u.device_type = DevDetect::detect(device);

    UnitEncryptor enc;

    // Callbacks de UI movidos a UnitEvents
    enc.setLogCallback([](LogLevel level, LogEvent event,const std::string& data) {
        UnitEvents::print_cli(level, event, data);
    });

    enc.setProgressCallback([](uint64_t cur, uint64_t total, double speed) {
        UnitEvents::print_cli_progress(cur, total, speed);
    });

    bool ok = enc.processUnit(u, encrypt, master_key);
    std::cout << (ok ? "\033[32m  OK\n\033[0m" : "\033[31m  FAIL\n\033[0m");
    return ok ? 0 : 1;
}