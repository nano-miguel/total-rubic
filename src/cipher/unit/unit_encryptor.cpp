// cipher/unit/unit_encryptor.cpp - 0.1 alpha
#include "../unit_encryptor.h"
#include "../../keygest/key_manager.h"
#include "../../rubic_core.h"

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
// Helpers de I/O Segura + RAII para O_DIRECT
// ============================================

namespace {

class DirectIOGuard {
    int  fd_;
    int  saved_;
    bool active_ = false;
    bool valid_  = false;
public:
    explicit DirectIOGuard(int fd) : fd_(fd), saved_(fcntl(fd, F_GETFL)) {
        if (saved_ == -1) return;
        valid_ = true;
        if (saved_ & O_DIRECT) {
            fcntl(fd_, F_SETFL, saved_ & ~O_DIRECT);
            active_ = true;
        }
    }
    ~DirectIOGuard() {
        if (active_) fcntl(fd_, F_SETFL, saved_);
    }
    bool valid() const { return valid_; }
    DirectIOGuard(const DirectIOGuard&)            = delete;
    DirectIOGuard& operator=(const DirectIOGuard&) = delete;
};

} // namespace

static bool safe_pread(int fd, void* buf, size_t count, off_t offset) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t total = 0;
    while (total < count) {
        ssize_t r = pread(fd, p + total, count - total, offset + total);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (r == 0) return false;
        total += r;
    }
    return true;
}

static bool safe_pwrite(int fd, const void* buf, size_t count, off_t offset) {
    const uint8_t* p = static_cast<const uint8_t*>(buf);
    size_t total = 0;
    while (total < count) {
        ssize_t r = pwrite(fd, p + total, count - total, offset + total);
        if (r < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        total += r;
    }
    return true;
}

static bool read_enc_header(int fd, EncUnitHdr& out) {
    return safe_pread(fd, &out, sizeof(out), HEADER_OFFSET_SECTORS * SECTOR_SIZE)
        && out.isValid();
}


// AlignBuf

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

// ============================================
// SpeedMtr

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


// StorUnit

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


// DataPipeline

namespace {

class DataPipeline {
public:
    struct Context {
        int fd;
        uint64_t total_size;
        uint64_t data_start_sector;
        const ThCfg& cfg;
        DevType device_type;
        const Botan::secure_vector<uint8_t>& xts_key;
        bool encrypt;
        SpeedMtr& speed_meter;
        std::atomic<bool>& stop_requested;
        std::function<void(LogLevel, LogEvent, const std::string&)> log;
        std::function<void(uint64_t, uint64_t, double)> progress;
    };

    explicit DataPipeline(Context ctx) : ctx_(ctx) {}

    bool run() {
        size_t chunk_size = ctx_.cfg.getChunkSize();
        uint64_t total_chunks = (ctx_.total_size + chunk_size - 1) / chunk_size;

        ctx_.log(LogLevel::Info, LogEvent::DataSizeInfo, std::to_string(ctx_.total_size));
        ctx_.log(LogLevel::Info, LogEvent::ChunkCountInfo, std::to_string(total_chunks));

        LimQueue<PipeChunk> read_q(MAX_QUEUE_SIZE), write_q(MAX_QUEUE_SIZE);
        std::atomic<uint64_t> done{0}, bytes_done{0};
        std::atomic<bool> err{false};

        auto reader = spawn_reader(read_q, chunk_size, total_chunks, err);
        auto workers = spawn_workers(read_q, write_q, chunk_size, err);
        auto writer = spawn_writer(write_q, chunk_size, total_chunks, done, bytes_done, err);

        while (!err && !ctx_.stop_requested && done < total_chunks) {
            std::this_thread::sleep_for(std::chrono::milliseconds(PROGRESS_UPDATE_MS));
            if (err || ctx_.stop_requested) { read_q.close(); write_q.close(); }
        }

        read_q.close();
        write_q.close();
        if (reader.joinable()) reader.join();
        for (auto& t : workers) if (t.joinable()) t.join();
        if (writer.joinable()) writer.join();

        if (fsync(ctx_.fd) != 0) {
            ctx_.log(LogLevel::Error, LogEvent::FinalFsyncFailed, "");
            err = true;
        }

        if (err) ctx_.log(LogLevel::Error, LogEvent::ProcessingFailed, "");
        else if (ctx_.stop_requested) ctx_.log(LogLevel::Warning, LogEvent::ProcessingStopped, "");
        else ctx_.log(LogLevel::Success, LogEvent::ProcessingComplete, "");

        return !err && done == total_chunks && !ctx_.stop_requested;
    }

private:
    Context ctx_;

    std::thread spawn_reader(LimQueue<PipeChunk>& read_q, size_t chunk_size, uint64_t total_chunks, std::atomic<bool>& err) {
        bool scrub = !ctx_.encrypt;
        return std::thread([this, &read_q, chunk_size, total_chunks, &err, scrub]() {
            for (uint64_t c = 0; c < total_chunks && !err && !ctx_.stop_requested; c++) {
                PipeChunk chunk(chunk_size, ctx_.cfg.use_direct_io);
                chunk.data->set_scrub_on_destroy(scrub);

                uint64_t rel_offset = c * chunk_size;
                chunk.offset = ctx_.data_start_sector * SECTOR_SIZE + rel_offset;
                chunk.size = std::min<uint64_t>(chunk_size, ctx_.total_size - rel_offset);
                chunk.start_sector = chunk.offset / SECTOR_SIZE;
                chunk.index = c;

                if (!safe_pread(ctx_.fd, chunk.data->data(), chunk.size, chunk.offset)) {
                    ctx_.log(LogLevel::Error, LogEvent::ChunkReadError, std::to_string(c));
                    err = true;
                    break;
                }

                if (err || ctx_.stop_requested) break;
                read_q.push(std::move(chunk));
            }
            read_q.close();
        });
    }

    std::vector<std::thread> spawn_workers(LimQueue<PipeChunk>& read_q, LimQueue<PipeChunk>& write_q, size_t chunk_size, std::atomic<bool>& err) {
        int ncpu = ctx_.cfg.num_threads > 0 ? ctx_.cfg.num_threads : 4;

        // El texto lo traduce la UI vía TR().t("log_unit_xts_fallback").
        // El data va vacío para no hardcodear español en el core.
        ctx_.log(LogLevel::Info, LogEvent::XtsFallback, "");

        std::vector<std::thread> workers;
        workers.reserve(ncpu);
        for (int t = 0; t < ncpu; t++) {
            workers.emplace_back([this, &read_q, &write_q, chunk_size, &err]() {
                AESXTSProc proc(ctx_.xts_key, ctx_.encrypt);
                PipeChunk chunk(chunk_size, ctx_.cfg.use_direct_io);
                while (read_q.pop(chunk) && !err && !ctx_.stop_requested) {
                    if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                        ctx_.log(LogLevel::Error, LogEvent::ChunkProcessError, std::to_string(chunk.index));
                        err = true;
                        break;
                    }
                    write_q.push(std::move(chunk));
                    chunk = PipeChunk(chunk_size, ctx_.cfg.use_direct_io);
                }
            });
        }
        return workers;
    }

    std::thread spawn_writer(LimQueue<PipeChunk>& write_q, size_t chunk_size, uint64_t total_chunks, std::atomic<uint64_t>& done, std::atomic<uint64_t>& bytes_done, std::atomic<bool>& err) {
        const size_t kMaxReorder = static_cast<size_t>(ctx_.cfg.num_threads) * 4 + 64;
        return std::thread([this, &write_q, chunk_size, total_chunks, &done, &bytes_done, &err, kMaxReorder]() {
            PipeChunk chunk(chunk_size, ctx_.cfg.use_direct_io);
            uint64_t expected = 0;
            std::vector<PipeChunk> reorder;
            while (!err && !ctx_.stop_requested && expected < total_chunks) {
                if (!write_q.pop(chunk)) break;
                if (chunk.index == expected) {
                    if (!safe_pwrite(ctx_.fd, chunk.data->data(), chunk.size, chunk.offset)) {
                        ctx_.log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(chunk.index));
                        err = true;
                        break;
                    }
                    done++;
                    bytes_done += chunk.size;
                    ctx_.speed_meter.addBytes(chunk.size);
                    ctx_.progress(bytes_done.load(), ctx_.total_size, ctx_.speed_meter.getCurrentSpeed());
                    expected++;

                    int flush = (ctx_.device_type == DevType::HDD || ctx_.device_type == DevType::USB2) ? 2 : 1;
                    if (chunk.index % flush == 0) {
                        if (fsync(ctx_.fd) != 0) {
                            ctx_.log(LogLevel::Error, LogEvent::ProcessingFsyncFailed, "");
                            err = true;
                            break;
                        }
                    }

                    for (auto it = reorder.begin(); it != reorder.end(); ) {
                        if (it->index == expected) {
                            if (!safe_pwrite(ctx_.fd, it->data->data(), it->size, it->offset)) {
                                ctx_.log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(it->index));
                                err = true;
                                break;
                            }
                            done++;
                            bytes_done += it->size;
                            ctx_.speed_meter.addBytes(it->size);
                            ctx_.progress(bytes_done.load(), ctx_.total_size, ctx_.speed_meter.getCurrentSpeed());
                            expected++;
                            it = reorder.erase(it);
                        } else ++it;
                    }
                } else if (chunk.index > expected) {
                    if (reorder.size() >= kMaxReorder) {
                        ctx_.log(LogLevel::Error, LogEvent::ReorderOverflow, "");
                        err = true;
                        break;
                    }
                    reorder.push_back(std::move(chunk));
                    chunk = PipeChunk(chunk_size, ctx_.cfg.use_direct_io);
                }
            }
            write_q.close();
        });
    }
};

class HeaderProcessor {
public:
    static bool prepEncrypt(
        int fd, const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key,
        uint64_t data_start_sector, uint64_t total_sectors, HdrBackup& backup_mgr,
        Botan::secure_vector<uint8_t>& xts_key, FSInfo& fs_info,
        std::function<void(LogLevel, LogEvent, const std::string&)> log)
    {
        log(LogLevel::Info, LogEvent::SaltGenerating, "");
        auto kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
        if (kdf_salt.empty()) { log(LogLevel::Error, LogEvent::SaltError, ""); return false; }

        log(LogLevel::Info, LogEvent::KeyDeriving, "");
        xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
        if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); return false; }
        log(LogLevel::Success, LogEvent::KeyDerived, "");

        EncUnitHdr hdr{};
        memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
        hdr.version = HEADER_VERSION_CURRENT;
        hdr.data_start_sector = data_start_sector;
        hdr.total_sectors = total_sectors;
        hdr.fs_info = fs_info;

        if (!safe_pread(fd, hdr.orig_sector0, sizeof(hdr.orig_sector0), 0)) {
            log(LogLevel::Error, LogEvent::Sector0ReadFailed, "");
            return false;
        }
        log(LogLevel::Info, LogEvent::Sector0BackedUp, "");

        log(LogLevel::Info, LogEvent::KmacCalculating, "");
        try {
            KMACProc Kmac(master_key);
            auto m = Kmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac));
            if (m.size() == KMAC_SIZE) memcpy(hdr.Kmac, m.data(), KMAC_SIZE);
            else { log(LogLevel::Error, LogEvent::KmacSizeError, ""); return false; }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            return false;
        }

        if (backup_mgr.saveHeader(unit.device_path, hdr, master_key)) {
            log(LogLevel::Success, LogEvent::BackupSaved, "");
        } else {
            log(LogLevel::Error, LogEvent::BackupSaveFailed, "");
            return false;
        }

        log(LogLevel::Info, LogEvent::HeaderWriting, "");
        {
            DirectIOGuard guard(fd);
            if (!guard.valid()) return false;
            if (!safe_pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE)) {
                log(LogLevel::Error, LogEvent::HeaderWriting, strerror(errno));
                return false;
            }
        }

        if (fsync(fd) != 0) {
            log(LogLevel::Error, LogEvent::HeaderWriting, strerror(errno));
            return false;
        }
        log(LogLevel::Success, LogEvent::HeaderWritten, "");
        return true;
    }

    static bool prepDecrypt(
        int fd, const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key,
        HdrBackup& backup_mgr, Botan::secure_vector<uint8_t>& xts_key,
        uint64_t& data_start_sector, FSInfo& fs_info,
        std::function<void(LogLevel, LogEvent, const std::string&)> log)
    {
        EncUnitHdr hdr;
        log(LogLevel::Info, LogEvent::HeaderVerified, "reading");

        bool valid_header = read_enc_header(fd, hdr);

        if (!valid_header) {
            log(LogLevel::Warning, LogEvent::HeaderReadFailed, "");
            log(LogLevel::Info, LogEvent::HeaderBackupAttempting, "");
            if (backup_mgr.loadHeader(unit.device_path, hdr, master_key))
                log(LogLevel::Success, LogEvent::BackupLoaded, "");
            else {
                log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
                return false;
            }
        }

        if (hdr.version < 2) {
            log(LogLevel::Warning, LogEvent::LegacyHeaderNoKdf, "");
            xts_key.resize(64);
            memcpy(xts_key.data(), master_key.data(), 32);
            memcpy(xts_key.data() + 32, master_key.data(), 32);
        } else {
            log(LogLevel::Info, LogEvent::KeyDeriving, "");
            Botan::secure_vector<uint8_t> kdf_salt(KDF_SALT_SIZE);
            memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
            xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
            if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); return false; }
            log(LogLevel::Success, LogEvent::KeyDerived, "");
        }

        log(LogLevel::Info, LogEvent::KmacCalculating, "verificando");
        try {
            KMACProc Kmac(master_key);
            if (!Kmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac), hdr.Kmac, KMAC_SIZE)) {
                log(LogLevel::Error, LogEvent::KmacFailed, "");
                return false;
            }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            return false;
        }
        log(LogLevel::Success, LogEvent::KmacVerified, "");

        if (hdr.version >= 4) {
            if (!safe_pwrite(fd, hdr.orig_sector0, sizeof(hdr.orig_sector0), 0)) {
                log(LogLevel::Warning, LogEvent::Sector0RestoreFailed, "");
            } else {
                log(LogLevel::Info, LogEvent::Sector0Restored, "");
            }
        }

        fs_info = hdr.fs_info;
        data_start_sector = hdr.data_start_sector;
        return true;
    }
};

} 

// UnitEncryptor

UnitEncryptor::UnitEncryptor() : last_refresh(0) {
    refreshUnits();
}

void UnitEncryptor::setDirectKeyHex(const std::string& hexKey) {
    if (hexKey.length() != 64) {
        useDirectKey = false;
        throw std::invalid_argument("La clave hexadecimal debe tener exactamente 64 caracteres.");
    }

    try {
        Botan::secure_vector<uint8_t> k(32);
        for (size_t i = 0; i < 64; i += 2) {
            k[i/2] = static_cast<uint8_t>(std::stoul(hexKey.substr(i, 2), nullptr, 16));
        }
        directKey = k;
        useDirectKey = true;
        keyManager = nullptr;
    } catch (const std::exception&) {
        useDirectKey = false;
        throw std::runtime_error("Clave hexadecimal inválida.");
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

bool UnitEncryptor::isUnitEncrypted(const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
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
        if (!guard.valid()) return false;
        w = pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    }
    if (w != sizeof(hdr)) return false;
    if (fsync(fd) != 0) return false;
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
            u.fs_info = getFSInfo(dev);
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

std::vector<StorUnit> UnitEncryptor::getUnits() { refreshUnits(); return cached_units; }
void UnitEncryptor::refresh() { cached_units = detectUnits(); last_refresh = time(nullptr); }
void UnitEncryptor::reloadCustomConfig() { settings_.load(); }

bool UnitEncryptor::validateUnitProcess(
        const StorUnit& unit, bool encrypt,
        const Botan::secure_vector<uint8_t>& master_key) {
    if (encrypt && unit.is_encrypted)   { log(LogLevel::Warning, LogEvent::UnitAlreadyEncrypted, ""); return false; }
    if (!encrypt && !unit.is_encrypted) { log(LogLevel::Warning, LogEvent::UnitNotEncrypted, "");     return false; }
    if (unit.is_system_disk)            { log(LogLevel::Error,   LogEvent::SystemDiskBlocked, "");    return false; }
    if (unit.is_mounted)                { log(LogLevel::Warning, LogEvent::UnitMounted, unit.mount_point); return false; }
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    if (geteuid() != 0) {
        // Antes: log(..., "requiere privilegios de root");
        log(LogLevel::Error, LogEvent::RequiresRoot, "");
        return false;
    }
    return true;
}

bool UnitEncryptor::processUnit(StorUnit& unit, bool encrypt,
                                 const Botan::secure_vector<uint8_t>& master_key) {
    if (!validateUnitProcess(unit, encrypt, master_key)) return false;

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
            flags &= ~O_DIRECT;
            fd = open(unit.device_path.c_str(), flags);
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

    auto log_cb = [this](LogLevel l, LogEvent e, const std::string& d) { this->log(l, e, d); };

    bool header_ok = false;
    if (encrypt) {
        if (strlen(fs_info.fstype) == 0) fs_info = getFSInfo(unit.device_path);
        header_ok = HeaderProcessor::prepEncrypt(fd, unit, master_key, data_start_sector, total_sectors, backup_mgr, xts_key, fs_info, log_cb);
    } else {
        header_ok = HeaderProcessor::prepDecrypt(fd, unit, master_key, backup_mgr, xts_key, data_start_sector, fs_info, log_cb);
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

    DataPipeline::Context pipe_ctx{
        fd, data_size, data_start_sector, cfg, unit.device_type, xts_key, encrypt,
        speed_meter, stop_requested,
        log_cb,
        [this](uint64_t c, uint64_t t, double s) { this->progress(c, t, s); }
    };

    DataPipeline pipeline(pipe_ctx);
    bool pipeline_ok = pipeline.run();

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
                log(LogLevel::Success, LogEvent::HeaderRemoved, "");
            } else {
                log(LogLevel::Error, LogEvent::HeaderCleanFsyncFailed, "");
                pipeline_ok = false;
            }
        } else {
            log(LogLevel::Error, LogEvent::HeaderCleanWriteFailed, "");
            pipeline_ok = false;
        }

        if (backup_mgr.removeBackup(unit.device_path))
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
    }

    close(fd);
    return pipeline_ok;
}

bool UnitEncryptor::cleanHeader(const StorUnit& unit) {
    log(LogLevel::Info, LogEvent::CleanupHeader, unit.device_path);
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); return false; }
    size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
    std::vector<uint8_t> zeros(hsz, 0);

    bool ok = safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    if (ok) {
        if (fsync(fd) != 0) ok = false;
    }
    close(fd);

    if (!ok) { log(LogLevel::Error, LogEvent::HeaderCleanFailed, ""); return false; }

    log(LogLevel::Success, LogEvent::HeaderRemoved, "");
    if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
        log(LogLevel::Success, LogEvent::BackupRemoved, "");
    return true;
}

bool UnitEncryptor::restoreHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info, LogEvent::HeaderRestoring, "");
    EncUnitHdr hdr;
    if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
        log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
        return false;
    }
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); return false; }

    if (!writeHdr(fd, hdr)) {
        log(LogLevel::Error, LogEvent::HeaderRestoreFailed, "");
        close(fd);
        return false;
    }

    close(fd);
    log(LogLevel::Success, LogEvent::HeaderRestored, "");
    return true;
}