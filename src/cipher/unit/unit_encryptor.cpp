// cipher/unit/unit_encryptor.cpp - 0.1 alpha
#include "../unit_encryptor.h"
#include "../../keygest/key_manager.h"

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

/* StorUnit */
    std::string StorUnit::formatBytes(uint64_t bytes) {
    const char* s[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0; 
    double d = bytes;
while (d >= 1024.0 && i < 4) { d /= 1024.0; i++; }
        std::stringstream ss;ss << 
        std::fixed << 
        std::setprecision(2) << d << " " << s[i];
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
    const std::string& hexKey,
        std::string& error_out) {
    if (hexKey.length() != 64) {
        useDirectKey = false; error_out = "err_hex_len_64"; 
        return false;
    }

    try {
        Botan::secure_vector<uint8_t> k(32);

    for (size_t i = 0; i < 64; i += 2) {
        k[i/2] = static_cast<uint8_t>(
        std::stoul(hexKey.substr(i, 2),
        nullptr, 16));
        }
        directKey = k;useDirectKey = true;keyManager = nullptr;
        return true;
    } 
    catch (
    const std::exception&) {
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

void UnitEncryptor::reloadCustomConfig() { 
    settings_.load(); 
}

bool UnitEncryptor::validateUnitProcess(
    const StorUnit& unit,
     bool encrypt,
    const Botan::secure_vector<uint8_t>& master_key) {
    if (encrypt && unit.is_encrypted){ 
        log(LogLevel::Warning,
            LogEvent::UnitAlreadyEncrypted, "");
        return false; }

    if (!encrypt && !unit.is_encrypted) { 
        log(LogLevel::Warning,
            LogEvent::UnitNotEncrypted, "");     
        return false; }

    if (unit.is_system_disk) { 
        log(LogLevel::Error,
            LogEvent::SystemDiskBlocked, "");
        return false; }

    if (unit.is_mounted)  { 
        log(LogLevel::Warning,
            LogEvent::UnitMounted, unit.mount_point);
        return false; }

    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error,
            LogEvent::MasterKeyInvalid, "");
        return false;
    }
    if (geteuid() != 0) {
        log(LogLevel::Error,
            LogEvent::RequiresRoot, "");
    return false;
    }
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

// NUEVO HELPER: Abre el dispositivo y maneja el fallback de O_DIRECT
int UnitEncryptor::open_device_with_retry(
    const std::string& path, ThCfg& cfg, uint64_t& total_size) {
    int flags = O_RDWR | O_SYNC;
    if (cfg.use_direct_io) flags |= O_DIRECT;
    
    int fd = open(path.c_str(), flags);
    if (fd < 0) {
        log(LogLevel::Error,
            LogEvent::DeviceOpenFailed, strerror(errno));
    
        if (cfg.use_direct_io && errno == EINVAL) {
            log(LogLevel::Warning,
                LogEvent::DeviceOpenRetry, strerror(errno));
            flags &= ~O_DIRECT;
            fd = open(path.c_str(), flags);
            if (fd < 0) return -1;
            cfg.use_direct_io = false;
        } else {
            return -1;
        }
    }

    if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) {
        log(LogLevel::Error,
            LogEvent::DeviceSizeFailed, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

// NUEVO HELPER: Borra el sector 0 o la cabecera al terminar
void UnitEncryptor::cleanup_device_after_process(
    int fd, bool encrypt, bool pipeline_ok, const StorUnit& unit) {
    
    if (encrypt && pipeline_ok) {
        uint8_t zeros[512] = {0};
        if (safe_pwrite(fd, zeros, sizeof(zeros), 0) && fsync(fd) == 0) {
            log(LogLevel::Info, LogEvent::Sector0Wiped, ""); } 
        else {
            log(LogLevel::Warning, LogEvent::Sector0WipeFailed, ""); }
    }

    if (!encrypt && pipeline_ok) {
        log(LogLevel::Info, LogEvent::CleanupHeader, "");
        size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(hsz, 0);

        if (safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE)) {
            if (fsync(fd) == 0) {
                log(LogLevel::Success, LogEvent::HeaderRemoved, ""); } 
            else {
                log(LogLevel::Error, LogEvent::HeaderCleanFsyncFailed, ""); }
        } 
        else {
            log(LogLevel::Error, LogEvent::HeaderCleanWriteFailed, "");
        }

        if (backup_mgr.removeBackup(unit.device_path))
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
    }
}

// EL DO_PROCESS REFACTORIZADO (Súper corto y legible)
bool UnitEncryptor::doProcess(
    const StorUnit& unit,
    const Botan::secure_vector<uint8_t>& master_key,
    bool encrypt) {
    ThCfg cfg = settings_.resolveConfig(unit.device_type);

    log(LogLevel::Info, LogEvent::DeviceTypeDetected, unit.getDevTypeStr());
    log(LogLevel::Info, settings_.isCustomMode() ? LogEvent::ConfigCustom : LogEvent::ConfigAuto,
        std::to_string(cfg.num_threads) + " threads");
    log(LogLevel::Info, LogEvent::ChunkSizeInfo, std::to_string(cfg.chunk_size_mb));
    log(LogLevel::Info, LogEvent::IoModeInfo, cfg.use_direct_io ? "direct" : "normal");

    uint64_t total_size = 0;
    int fd = open_device_with_retry(unit.device_path, cfg, total_size);
    if (fd < 0) 
        return false;

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
            fd, unit, master_key, data_start_sector, total_sectors, backup_mgr, xts_key,
            fs_info,log_cb);
    } 
    else {
        header_ok = unit_pipeline::HeaderProcessoDecrypt(
            fd, unit,master_key,backup_mgr,xts_key,data_start_sector,
            fs_info,log_cb);
    
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
        fd, data_size, data_start_sector, cfg,
        unit.device_type, xts_key, encrypt,
        speed_meter, stop_requested,log_cb,
        [this](uint64_t c, uint64_t t, double s)
            { this->progress(c, t, s); }
    };

    bool pipeline_ok = unit_pipeline::runDataPipeline(pipe_ctx);
    cleanup_device_after_process(fd, encrypt, pipeline_ok, unit);

    close(fd);
    return pipeline_ok;
}