// cipher/unit_encryptor.cpp - 0.1 alpha
#include "unit_encryptor.h"
#include "../keygest/key_manager.h"
#include "../rubic_core.h"

#include <limits.h>
#include <sys/wait.h>
#include <filesystem>
#include <fcntl.h>
#include <span>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <mntent.h>
#include <sys/mman.h>
#include <sys/statvfs.h>

#ifdef BLOCK_SIZE
#undef BLOCK_SIZE
#endif
#ifdef SECTOR_SIZE
#undef SECTOR_SIZE
#endif

#if defined(__x86_64__) || defined(__i386__)
  #include <immintrin.h>
#endif

// ============================================
// Helpers de proceso
// ============================================

static int safe_exec(const std::vector<std::string>& args) {
    if (args.empty()) return -1;
    pid_t pid = fork();
    if (pid == -1) return -1;
    if (pid == 0) {
        std::vector<char*> c_args;
        for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static std::string exec_cmd_output(const std::vector<std::string>& args) {
    if (args.empty()) return "";
    int pipefd[2];
    if (pipe(pipefd) == -1) return "";
    pid_t pid = fork();
    if (pid == -1) { close(pipefd[0]); close(pipefd[1]); return ""; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        std::vector<char*> c_args;
        for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(127);
    }
    close(pipefd[1]);
    std::string result;
    char buffer[256];
    ssize_t bytes_read;
    while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        result += buffer;
    }
    close(pipefd[0]);
    int status;
    waitpid(pid, &status, 0);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

// ============================================
// CustCfg
// ============================================

CustCfg::CustCfg()
    : buffer_size_mb(64), io_threads(2), crypto_threads(4),
      use_direct_io(true), custom_mode(false) {}

void CustCfg::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "buffer_size_mb") buffer_size_mb = std::stoul(value);
            else if (key == "io_threads") io_threads = std::stoi(value);
            else if (key == "crypto_threads") crypto_threads = std::stoi(value);
            else if (key == "use_direct_io") use_direct_io = (value == "true");
            else if (key == "custom_mode") custom_mode = (value == "true");
        }
    }
}

void CustCfg::saveToFile(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    file << "# Configuración personalizada de RUBI-C\n";
    file << "# Valores por defecto: buffer_size_mb=64, io_threads=2, crypto_threads=4\n\n";
    file << "buffer_size_mb=" << buffer_size_mb << "\n";
    file << "io_threads=" << io_threads << "\n";
    file << "crypto_threads=" << crypto_threads << "\n";
    file << "use_direct_io=" << (use_direct_io ? "true" : "false") << "\n";
    file << "custom_mode=" << (custom_mode ? "true" : "false") << "\n";
}

// ============================================
// AlignBuf — wipe SIEMPRE en destructor
// ============================================

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

uint8_t* AlignBuf::data() { return static_cast<uint8_t*>(data_ptr); }
const uint8_t* AlignBuf::data() const { return static_cast<const uint8_t*>(data_ptr); }
size_t AlignBuf::size() const { return size_bytes; }

// NOTA: DevDetect vive en devdetect.cpp
// NOTA: KeyDeriv, KMACProc y HdrBackup viven en unit_header.cpp
// NOTA: SIMDProc y AESXTSProc viven en unit_pipeline.cpp

// ============================================
// FixedThCfg
// ============================================

FixedThCfg FixedThCfg::getConfigForSystem() {
    FixedThCfg config;
    int sys = HardwareDetect::getCoreCount();
    int avail = sys > 1 ? sys - 1 : sys;
    if (avail <= 2)      { config.io_threads = 1; config.crypto_threads = 1;          config.reserved_os = 0; }
    else if (avail <= 4) { config.io_threads = 1; config.crypto_threads = 2;          config.reserved_os = 1; }
    else if (avail <= 8) { config.io_threads = 2; config.crypto_threads = 5;          config.reserved_os = 1; }
    else if (avail <= 16){ config.io_threads = 3; config.crypto_threads = 11;         config.reserved_os = 2; }
    else if (avail <= 32){ config.io_threads = 4; config.crypto_threads = 24;         config.reserved_os = 4; }
    else                 { config.io_threads = 6; config.crypto_threads = avail - 8;  config.reserved_os = 2; }
    return config;
}

// ============================================
// ThCfg
// ============================================

ThCfg::ThCfg()
    : num_threads(HardwareDetect::getCoreCount()), chunk_size_mb(64), use_direct_io(true) {}

void ThCfg::applyFixedConfig(const FixedThCfg& f, DevType t) {
    num_threads = f.io_threads + f.crypto_threads + f.reserved_os;
    chunk_size_mb = DevDetect::getOptimalChunkMB(t);
    use_direct_io = DevDetect::useDirectIO(t);
}
void ThCfg::applyCustomConfig(const CustCfg& c) {
    num_threads = c.io_threads + c.crypto_threads;
    chunk_size_mb = c.buffer_size_mb;
    use_direct_io = c.use_direct_io;
}
void ThCfg::validate() {
    if (num_threads < MIN_THREADS) num_threads = MIN_THREADS;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (chunk_size_mb < 1) chunk_size_mb = 1;
    if (chunk_size_mb > 1024) chunk_size_mb = 1024;
    size_t bytes = chunk_size_mb * MB;
    if (bytes % ALIGNMENT != 0)
        chunk_size_mb = ((bytes + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT / MB;
}
size_t ThCfg::getChunkSize() const {
    size_t size = chunk_size_mb * MB;
    if (size % ALIGNMENT != 0)
        size = ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
    return size;
}
std::string ThCfg::getDesc() const {
    std::stringstream ss;
    ss << num_threads << " hilos | Chunk: " << chunk_size_mb << "MB";
    if (use_direct_io) ss << " | I/O DIRECTO";
    return ss.str();
}

// ============================================
// SpeedMtr
// ============================================

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
double SpeedMtr::getPeakSpeed() { return peak_speed.load(); }
uint64_t SpeedMtr::getTotalBytes() { return total_bytes.load(); }
void SpeedMtr::reset() {
    start_time = last_time = std::chrono::steady_clock::now();
    total_bytes = last_bytes = 0;
    current_speed = peak_speed = 0;
}

// ============================================
// StorUnit
// ============================================

std::string StorUnit::formatBytes(uint64_t bytes) {
    const char* s[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0; double d = bytes;
    while (d >= 1024.0 && i < 4) { d /= 1024.0; i++; }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << d << " " << s[i];
    return ss.str();
}
std::string StorUnit::getSafeFSType() const {
    if (strlen(fs_info.fstype) == 0) return "";
    for (size_t i = 0; i < strlen(fs_info.fstype); i++)
        if (!isprint(fs_info.fstype[i])) return "";
    return std::string(fs_info.fstype);
}

// ============================================
// UnitEncryptor
// ============================================

UnitEncryptor::UnitEncryptor()
    : use_custom_config(false), last_refresh(0) {
    fixed_config = FixedThCfg::getConfigForSystem();
    std::string cfg = XDG::get_rubic_config_dir() + "/rubic_config.cfg";
    custom_config.loadFromFile(cfg);
    use_custom_config = custom_config.custom_mode;
    refreshUnits();
}

void UnitEncryptor::setDirectKeyHex(const std::string& hexKey) {
    try {
        Botan::secure_vector<uint8_t> k(32);
        for (size_t i = 0; i < 32 && i + 1 < hexKey.length(); i += 2)
            k[i/2] = static_cast<uint8_t>(std::stoul(hexKey.substr(i, 2), nullptr, 16));
        directKey = k;
        useDirectKey = true;
        keyManager = nullptr;
    } catch (const std::exception&) {
        useDirectKey = false;
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

bool UnitEncryptor::isSystemDisk(const std::string& path) {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev, mnt;
            iss >> dev >> mnt;
            if (mnt == "/") return path == dev;
        }
    }
    return false;
}

FSInfo UnitEncryptor::getFileSystemInfo(const std::string& path) {
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
    std::string out = exec_cmd_output({"blkid", "-o", "value", "-s", "TYPE", path});
    if (!out.empty()) strncpy(info.fstype, out.c_str(), sizeof(info.fstype) - 1);
    out = exec_cmd_output({"blkid", "-o", "value", "-s", "LABEL", path});
    if (!out.empty()) strncpy(info.label, out.c_str(), sizeof(info.label) - 1);
    return info;
}

bool UnitEncryptor::isUnitEncrypted(const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    EncUnitHdr hdr;
    ssize_t r = pread(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    close(fd);
    return r == sizeof(hdr) && hdr.isValid();
}

bool UnitEncryptor::readHeaderFromDevice(int fd, EncUnitHdr& hdr) {
    ssize_t r = pread(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    return r == sizeof(hdr) && hdr.isValid();
}

bool UnitEncryptor::writeHeaderToDevice(int fd, const EncUnitHdr& hdr) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) return false;
    bool direct = flags & O_DIRECT;
    if (direct) fcntl(fd, F_SETFL, flags & ~O_DIRECT);
    ssize_t w = pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    if (direct) fcntl(fd, F_SETFL, flags);
    return w == sizeof(hdr);
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
        std::string dev, mnt, fs;
        iss >> dev >> mnt >> fs;
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
            u.is_encrypted = isUnitEncrypted(dev);
            u.fs_info = getFileSystemInfo(dev);
            u.label = u.fs_info.label;
            close(fd);
        } else if (errno == EACCES || errno == EPERM) {
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
            if ((name.find("sd") == 0 || name.find("hd") == 0 ||
                 name.find("nvme") == 0 || name.find("mmcblk") == 0) &&
                !seen.count(dev) && isPhysicalDevice(dev)) {
                bool is_part = name.find_first_of("0123456789") != std::string::npos;
                if (!is_part) {
                    bool has_parts = false;
                    for (auto& p : uniq)
                        if (p.second.parent_device == dev) { has_parts = true; break; }
                    if (has_parts) continue;
                }
                StorUnit u;
                u.device_path = dev;
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
                        u.is_encrypted = isUnitEncrypted(dev);
                        u.fs_info = getFileSystemInfo(dev);
                        u.label = u.fs_info.label;
                        close(fd);
                    } else if (errno == EACCES || errno == EPERM) {
                        u.requires_elevation = true;
                    }
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
    std::sort(units.begin(), units.end(), [](const StorUnit& a, const StorUnit& b) {
        if (a.is_system_disk != b.is_system_disk) return a.is_system_disk > b.is_system_disk;
        return a.total_size > b.total_size;
    });
    return units;
}

bool UnitEncryptor::unmount(StorUnit& u) {
    if (!u.is_mounted) return true;
    log(LogLevel::Info, LogEvent::Unmounting, u.mount_point);
    safe_exec({"umount", "-l", u.mount_point});
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line))
        if (line.find(u.device_path) != std::string::npos) return false;
    u.is_mounted = false;
    u.mount_point.clear();
    log(LogLevel::Success, LogEvent::Unmounted, "");
    return true;
}

bool UnitEncryptor::mount(const StorUnit& u, const std::string& point) {
    log(LogLevel::Info, LogEvent::Mounting, point);
    safe_exec({"mkdir", "-p", point});
    std::string fs = u.filesystem;
    if (fs.empty() && strlen(u.fs_info.fstype) > 0) fs = u.getSafeFSType();
    int ret = fs.empty()
        ? safe_exec({"mount", u.device_path, point})
        : safe_exec({"mount", "-t", fs, u.device_path, point});
    if (ret == 0) { log(LogLevel::Success, LogEvent::Mounted, point); return true; }
    log(LogLevel::Error, LogEvent::MountFailed, std::to_string(ret));
    return false;
}

std::vector<StorUnit> UnitEncryptor::getUnits() { refreshUnits(); return cached_units; }
void UnitEncryptor::refresh() { cached_units = detectUnits(); last_refresh = time(nullptr); }

void UnitEncryptor::reloadCustomConfig() {
    custom_config.loadFromFile(XDG::get_rubic_config_dir() + "/rubic_config.cfg");
    use_custom_config = custom_config.custom_mode;
}

bool UnitEncryptor::tryElevatedProcess(const StorUnit& unit, bool encrypt,
                                        const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string("pipe: ") + strerror(errno));
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string("fork: ") + strerror(errno));
        return false;
    }
    if (pid == 0) {
        close(pipefd[1]);
        if (pipefd[0] != 3) { dup2(pipefd[0], 3); close(pipefd[0]); }
        int flags = fcntl(3, F_GETFD);
        if (flags >= 0) fcntl(3, F_SETFD, flags & ~FD_CLOEXEC);
        char exe[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n <= 0) _exit(127);
        exe[n] = '\0';
        execlp("sudo", "sudo", "--preserve-fds=1",
               exe, "--unit-op", unit.device_path.c_str(),
               encrypt ? "encrypt" : "decrypt", nullptr);
        _exit(127);
    }
    close(pipefd[0]);
    uint32_t len = static_cast<uint32_t>(master_key.size());
    bool ok = (write(pipefd[1], &len, sizeof(len)) == (ssize_t)sizeof(len))
           && (write(pipefd[1], master_key.data(), len) == (ssize_t)len);
    close(pipefd[1]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!ok) { log(LogLevel::Error, LogEvent::MasterKeyInvalid, "write pipe"); return false; }
    if (!WIFEXITED(status)) { log(LogLevel::Error, LogEvent::ProcessingFailed, "killed"); return false; }
    int rc = WEXITSTATUS(status);
    if (rc == 127) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, "sudo missing"); return false; }
    if (rc != 0) { log(LogLevel::Error, LogEvent::ProcessingFailed, "rc=" + std::to_string(rc)); return false; }
    return true;
}

bool UnitEncryptor::processUnit(StorUnit& unit, bool encrypt,
                                 const Botan::secure_vector<uint8_t>& master_key) {
    if (geteuid() != 0) {
        bool ok = tryElevatedProcess(unit, encrypt, master_key);
        if (ok) {
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            refreshUnits();
        }
        return ok;
    }
    if (encrypt && unit.is_encrypted)   { log(LogLevel::Warning, LogEvent::UnitAlreadyEncrypted, ""); return false; }
    if (!encrypt && !unit.is_encrypted) { log(LogLevel::Warning, LogEvent::UnitNotEncrypted, "");     return false; }
    if (unit.is_system_disk)            { log(LogLevel::Error, LogEvent::SystemDiskBlocked, "");      return false; }
    if (unit.is_mounted)                { log(LogLevel::Warning, LogEvent::UnitMounted, unit.mount_point); return false; }
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
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

bool UnitEncryptor::doProcess(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key, bool encrypt) {
    ThCfg cfg;
    if (use_custom_config && custom_config.custom_mode) cfg.applyCustomConfig(custom_config);
    else cfg.applyFixedConfig(fixed_config, unit.device_type);
    cfg.validate();

    log(LogLevel::Info, LogEvent::DeviceTypeDetected, unit.getDevTypeStr());
    log(LogLevel::Info,
        (use_custom_config && custom_config.custom_mode) ? LogEvent::ConfigCustom : LogEvent::ConfigAuto,
        std::to_string(cfg.num_threads) + " threads");
    log(LogLevel::Info, LogEvent::ChunkSizeInfo, std::to_string(cfg.chunk_size_mb));
    log(LogLevel::Info, LogEvent::IoModeInfo, cfg.use_direct_io ? "direct" : "normal");

    int flags = O_RDWR | O_SYNC;
    if (cfg.use_direct_io) flags |= O_DIRECT;
    int fd = open(unit.device_path.c_str(), flags);
    if (fd < 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));
        if (cfg.use_direct_io && errno == EINVAL) {
            log(LogLevel::Warning, LogEvent::DeviceOpenRetry, "sin O_DIRECT");
            flags &= ~O_DIRECT;
            fd = open(unit.device_path.c_str(), flags);
            if (fd < 0) return false;
            cfg.use_direct_io = false;
        } else return false;
    }

    uint64_t total_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) {
        log(LogLevel::Error, LogEvent::DeviceSizeFailed, strerror(errno));
        close(fd);
        return false;
    }
    uint64_t total_sectors = total_size / SECTOR_SIZE;
    uint64_t data_start_sector = DATA_OFFSET_SECTORS;
    uint64_t data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;

    Botan::secure_vector<uint8_t> kdf_salt, xts_key;
    FSInfo fs_info = unit.fs_info;

    if (encrypt) {
        log(LogLevel::Info, LogEvent::SaltGenerating, "");
        kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
        if (kdf_salt.empty()) { log(LogLevel::Error, LogEvent::SaltError, ""); close(fd); return false; }
        log(LogLevel::Info, LogEvent::KeyDeriving, "");
        xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
        if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); close(fd); return false; }
        log(LogLevel::Success, LogEvent::KeyDerived, "");
        if (strlen(fs_info.fstype) == 0) fs_info = getFileSystemInfo(unit.device_path);

        EncUnitHdr hdr{};
        memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
        hdr.version = HEADER_VERSION_CURRENT;
        hdr.data_start_sector = data_start_sector;
        hdr.total_sectors = total_sectors;
        hdr.fs_info = fs_info;

        log(LogLevel::Info, LogEvent::KmacCalculating, "");
        try {
            KMACProc Kmac(master_key);
            auto m = Kmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac));
            if (m.size() == KMAC_SIZE) memcpy(hdr.Kmac, m.data(), KMAC_SIZE);
            else { log(LogLevel::Error, LogEvent::KmacError, "size"); close(fd); return false; }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            close(fd);
            return false;
        }
        // Fix de seguridad: el backup se cifra con master_key
        if (backup_mgr.saveHeader(unit.device_path, hdr, master_key))
            log(LogLevel::Success, LogEvent::BackupSaved, "");
        else
            log(LogLevel::Warning, LogEvent::BackupSaveFailed, "");

        log(LogLevel::Info, LogEvent::HeaderWriting, "");
        if (!writeHeaderToDevice(fd, hdr)) {
            log(LogLevel::Error, LogEvent::HeaderWriting, strerror(errno));
            close(fd);
            return false;
        }
        fsync(fd);
        log(LogLevel::Success, LogEvent::HeaderWritten, "");
    } else {
        EncUnitHdr hdr;
        log(LogLevel::Info, LogEvent::HeaderVerified, "reading");
        if (!readHeaderFromDevice(fd, hdr)) {
            log(LogLevel::Warning, LogEvent::HeaderReadFailed, "intentando backup");
            // Fix de seguridad: el backup se descifra con master_key
            if (backup_mgr.loadHeader(unit.device_path, hdr, master_key))
                log(LogLevel::Success, LogEvent::BackupLoaded, "");
            else {
                log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
                close(fd);
                return false;
            }
        }
        if (hdr.version < 2) {
            log(LogLevel::Warning, LogEvent::KeyDerived, "version<2 sin KDF");
            xts_key.resize(64);
            memcpy(xts_key.data(), master_key.data(), 32);
            memcpy(xts_key.data() + 32, master_key.data(), 32);
        } else {
            log(LogLevel::Info, LogEvent::KeyDeriving, "");
            kdf_salt.resize(KDF_SALT_SIZE);
            memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
            xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
            if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); close(fd); return false; }
            log(LogLevel::Success, LogEvent::KeyDerived, "");
        }
        log(LogLevel::Info, LogEvent::KmacCalculating, "verificando");
        try {
            KMACProc Kmac(master_key);
            if (!Kmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac), hdr.Kmac, KMAC_SIZE)) {
                log(LogLevel::Error, LogEvent::KmacFailed, "");
                close(fd);
                return false;
            }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            close(fd);
            return false;
        }
        log(LogLevel::Success, LogEvent::KmacVerified, "");
        fs_info = hdr.fs_info;
        data_start_sector = hdr.data_start_sector;
        data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;
    }

    log(LogLevel::Info, LogEvent::DataSizeInfo, std::to_string(data_size));
    size_t chunk_size = cfg.getChunkSize();
    uint64_t total_chunks = (data_size + chunk_size - 1) / chunk_size;
    log(LogLevel::Info, LogEvent::ChunkCountInfo, std::to_string(total_chunks));

    LimQueue<PipeChunk> read_q(MAX_QUEUE_SIZE), write_q(MAX_QUEUE_SIZE);
    std::atomic<uint64_t> done{0}, bytes_done{0};
    std::atomic<bool> err{false};

    const bool scrub_chunks = !encrypt;

    std::thread reader([&]() {
        for (uint64_t c = 0; c < total_chunks && !err && !stop_requested; c++) {
            PipeChunk chunk(chunk_size, cfg.use_direct_io);
            chunk.data->set_scrub_on_destroy(scrub_chunks);
            chunk.index = c;
            chunk.offset = data_start_sector * SECTOR_SIZE + c * chunk_size;
            chunk.size = std::min<uint64_t>(chunk_size, total_size - chunk.offset);
            chunk.start_sector = chunk.offset / SECTOR_SIZE;
            if (pread(fd, chunk.data->data(), chunk.size, chunk.offset) != (ssize_t)chunk.size) {
                log(LogLevel::Error, LogEvent::ChunkReadError, std::to_string(c));
                err = true;
                break;
            }
            read_q.push(std::move(chunk));
        }
        read_q.close();
    });

    int ncpu = (use_custom_config && custom_config.custom_mode)
                   ? custom_config.crypto_threads
                   : fixed_config.crypto_threads;
    std::vector<std::thread> workers;
    workers.reserve(ncpu);
    for (int t = 0; t < ncpu; t++) {
        workers.emplace_back([&]() {
            AESXTSProc proc(xts_key, encrypt);
            if (!proc.used_avx512())
                log(LogLevel::Warning, LogEvent::XtsFallback, "Botan XTS (AVX-512 self-test failed)");
            PipeChunk chunk(chunk_size, cfg.use_direct_io);
            while (read_q.pop(chunk) && !err && !stop_requested) {
                if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                    log(LogLevel::Error, LogEvent::ChunkProcessError, std::to_string(chunk.index));
                    err = true;
                    break;
                }
                write_q.push(std::move(chunk));
                chunk = PipeChunk(chunk_size, cfg.use_direct_io);
            }
        });
    }

    // Cota defensiva del reorder buffer: ncpu workers + 2 colas de 2 + writer hand
    const size_t kMaxReorder = static_cast<size_t>(ncpu) * 4 + 64;

    std::thread writer([&]() {
        PipeChunk chunk(chunk_size, cfg.use_direct_io);
        uint64_t expected = 0;
        std::vector<PipeChunk> reorder;
        while (!err && !stop_requested && expected < total_chunks) {
            if (!write_q.pop(chunk)) break;
            if (chunk.index == expected) {
                if (pwrite(fd, chunk.data->data(), chunk.size, chunk.offset) != (ssize_t)chunk.size) {
                    log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(chunk.index));
                    err = true;
                    break;
                }
                done++;
                bytes_done += chunk.size;
                speed_meter.addBytes(chunk.size);
                progress(bytes_done.load(), data_size, speed_meter.getCurrentSpeed());
                expected++;
                int flush = (unit.device_type == DevType::HDD || unit.device_type == DevType::USB2) ? 2 : 1;
                if (chunk.index % flush == 0) fsync(fd);
                for (auto it = reorder.begin(); it != reorder.end(); ) {
                    if (it->index == expected) {
                        if (pwrite(fd, it->data->data(), it->size, it->offset) != (ssize_t)it->size) {
                            log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(it->index));
                            err = true;
                            break;
                        }
                        done++;
                        bytes_done += it->size;
                        speed_meter.addBytes(it->size);
                        progress(bytes_done.load(), data_size, speed_meter.getCurrentSpeed());
                        expected++;
                        it = reorder.erase(it);
                    } else ++it;
                }
            } else if (chunk.index > expected) {
                if (reorder.size() >= kMaxReorder) {
                    log(LogLevel::Error, LogEvent::ChunkWriteError, "reorder overflow");
                    err = true;
                    break;
                }
                reorder.push_back(std::move(chunk));
                chunk = PipeChunk(chunk_size, cfg.use_direct_io);
            }
        }
        write_q.close();
    });

    while (!err && !stop_requested && done < total_chunks)
        std::this_thread::sleep_for(std::chrono::milliseconds(PROGRESS_UPDATE_MS));

    read_q.close();
    write_q.close();
    if (reader.joinable()) reader.join();
    for (auto& t : workers) if (t.joinable()) t.join();
    if (writer.joinable()) writer.join();
    fsync(fd);

    if (!encrypt && !err && !stop_requested) {
        log(LogLevel::Info, LogEvent::CleanupHeader, "");
        size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(hsz, 0);
        if (pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE) == (ssize_t)hsz) {
            fsync(fd);
            log(LogLevel::Success, LogEvent::HeaderRemoved, "");
        }
        if (backup_mgr.removeBackup(unit.device_path))
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
    }
    close(fd);

    stats.total_bytes = bytes_done.load();
    if (err) log(LogLevel::Error, LogEvent::ProcessingFailed, "");
    else if (stop_requested) log(LogLevel::Warning, LogEvent::ProcessingStopped, "");
    else log(LogLevel::Success, LogEvent::ProcessingComplete, "");

    return !err && done == total_chunks && !stop_requested;
}

bool UnitEncryptor::cleanHeader(const StorUnit& unit) {
    log(LogLevel::Info, LogEvent::CleanupHeader, unit.device_path);
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); return false; }
    size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
    std::vector<uint8_t> zeros(hsz, 0);
    ssize_t w = pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    fsync(fd);
    close(fd);
    if (w != (ssize_t)hsz) { log(LogLevel::Error, LogEvent::HeaderCleanFailed, ""); return false; }
    log(LogLevel::Success, LogEvent::HeaderRemoved, "");
    if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
        log(LogLevel::Success, LogEvent::BackupRemoved, "");
    return true;
}

bool UnitEncryptor::restoreHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info, LogEvent::HeaderRestoring, "");
    EncUnitHdr hdr;
    // Fix de seguridad: el backup se descifra con master_key
    if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
        log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
        return false;
    }
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); return false; }
    if (!writeHeaderToDevice(fd, hdr)) {
        log(LogLevel::Error, LogEvent::HeaderRestoreFailed, "");
        close(fd);
        return false;
    }
    close(fd);
    log(LogLevel::Success, LogEvent::HeaderRestored, "");
    return true;
}

bool UnitEncryptor::formatUnit(const StorUnit& unit, const std::string& fstype) {
    log(LogLevel::Info, LogEvent::FormatStart, unit.device_path + ":" + fstype);
    int res = -1;
    if (fstype == "vfat" || fstype == "fat32")
        res = safe_exec({"mkfs.vfat", "-F", "32", unit.device_path});
    else if (fstype == "ntfs")
        res = safe_exec({"mkfs.ntfs", "-f", unit.device_path});
    else if (fstype == "ext4")
        res = safe_exec({"mkfs.ext4", "-F", unit.device_path});
    else
        res = safe_exec({"mkfs." + fstype, unit.device_path});
    if (res == 0) { log(LogLevel::Success, LogEvent::FormatOk, ""); return true; }
    log(LogLevel::Error, LogEvent::FormatFailed, std::to_string(res));
    return false;
}
