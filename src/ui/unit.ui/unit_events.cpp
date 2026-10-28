// src/ui/unit.ui/unit_events.cpp
#include "../../cipher/unit_encryptor.h"
#include "../translator.h"
#include <iostream>
#include <string>
#include <unordered_map>

#ifndef UI_UNIT_COLORS_DEFINED
#define UI_UNIT_COLORS_DEFINED
#define RESET  "\033[0m"
#define RED  "\033[31m"
#define GREEN  "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE  "\033[34m"
#define BRIGHT_RED  "\033[91m"
#define BRIGHT_GREEN  "\033[92m"
#define BRIGHT_YELLOW  "\033[93m"
#endif

namespace UnitEvents {

struct EventData {
    const char* key;
    const char* color;
};

static const std::unordered_map<LogEvent, EventData>& getLogMap() {
    static const std::unordered_map<LogEvent, EventData> map = {
        { LogEvent::HeaderWriting, { "log_unit_header_writing", RESET } },
        { LogEvent::HeaderWritten, { "log_unit_header_written", GREEN } },
        { LogEvent::HeaderReadFailed, { "log_unit_header_read_failed", YELLOW } },
        { LogEvent::HeaderRemoved, { "log_unit_header_removed", GREEN } },
        { LogEvent::HeaderRestoring, { "log_unit_header_restoring", RESET } },
        { LogEvent::HeaderRestored, { "log_unit_header_restored", GREEN } },
        { LogEvent::HeaderRestoreFailed, { "log_unit_header_restore_failed", RED } },
        { LogEvent::HeaderCleanFailed, { "log_unit_header_clean_failed", RED } },
        { LogEvent::BackupSaved, { "log_unit_backup_saved", GREEN } },
        { LogEvent::BackupSaveFailed, { "log_unit_backup_save_failed", YELLOW } },
        { LogEvent::BackupLoaded, { "log_unit_backup_loaded", GREEN } },
        { LogEvent::BackupLoadFailed, { "log_unit_backup_load_failed", RED } },
        { LogEvent::BackupRemoved, { "log_unit_backup_removed", GREEN } },
        { LogEvent::HeaderBackupAttempting, { "log_unit_header_backup_attempting", YELLOW } },
        { LogEvent::HeaderCleanFsyncFailed, { "log_unit_header_clean_fsync_failed", RED } },
        { LogEvent::HeaderCleanWriteFailed, { "log_unit_header_clean_write_failed", RED } },
        { LogEvent::SaltGenerating, { "log_unit_salt_generating", RESET } },
        { LogEvent::SaltGenerated, { "log_unit_salt_generated", GREEN } },
        { LogEvent::SaltError, { "log_unit_salt_error", RED } },
        { LogEvent::KeyDeriving, { "log_unit_key_deriving", RESET } },
        { LogEvent::KeyDeriveError, { "log_unit_key_derive_error", RED } },
        { LogEvent::KmacError, { "log_unit_kmac_error", RED } },
        { LogEvent::KmacVerified, { "log_unit_kmac_verified", GREEN } },
        { LogEvent::KmacFailed, { "log_unit_kmac_failed", RED } },
        { LogEvent::KmacSizeError, { "log_unit_kmac_size_error", RED } },
        { LogEvent::LegacyHeaderNoKdf, { "log_unit_legacy_header_no_kdf", YELLOW } },
        { LogEvent::MasterKeyInvalid, { "log_unit_master_key_invalid", RED } },
        { LogEvent::SystemDiskBlocked, { "log_unit_sys_disk_blocked", BRIGHT_RED } },
        { LogEvent::UnitAlreadyEncrypted, { "log_unit_already_encrypted", YELLOW } },
        { LogEvent::UnitNotEncrypted, { "log_unit_not_encrypted", YELLOW } },
        { LogEvent::UnitMounted, { "log_unit_mounted", YELLOW } },
        { LogEvent::DeviceOpenFailed, { "log_unit_device_open_failed", RED } },
        { LogEvent::DeviceOpenRetry, { "log_unit_device_open_retry", YELLOW } },
        { LogEvent::DeviceSizeFailed, { "log_unit_device_size_failed", RED } },
        { LogEvent::DeviceTypeDetected, { "log_unit_device_type", RESET } },
        { LogEvent::RequiresRoot, { "log_unit_requires_root", RED } },
        { LogEvent::InvalidHeaderRegion, { "log_unit_invalid_header_region", RED } },
        { LogEvent::ConfigAuto, { "log_unit_config_auto", RESET } },
        { LogEvent::ConfigCustom, { "log_unit_config_custom", RESET } },
        { LogEvent::ChunkSizeInfo, { "log_unit_chunk_size", RESET } },
        { LogEvent::DataSizeInfo, { "log_unit_data_size", RESET } },
        { LogEvent::ChunkCountInfo, { "log_unit_chunk_count", RESET } },
        { LogEvent::Processing, { "log_unit_processing", RESET } },
        { LogEvent::ProcessingComplete, { "log_unit_processing_complete", GREEN } },
        { LogEvent::ProcessingStopped, { "log_unit_processing_stopped", YELLOW } },
        { LogEvent::ChunkReadError, { "log_unit_chunk_read_error", RED } },
        { LogEvent::ChunkProcessError, { "log_unit_chunk_process_error", RED } },
        { LogEvent::ChunkWriteError, { "log_unit_chunk_write_error", RED } },
        { LogEvent::FinalFsyncFailed, { "log_unit_final_fsync_failed", RED } },
        { LogEvent::ProcessingFsyncFailed, { "log_unit_processing_fsync_failed", RED } },
        { LogEvent::ReorderOverflow, { "log_unit_reorder_overflow", RED } },
        { LogEvent::Mounting, { "log_unit_mounting", RESET } },
        { LogEvent::Mounted, { "log_unit_mounted_ok", GREEN } },
        { LogEvent::MountFailed, { "log_unit_mount_failed", RED } },
        { LogEvent::Unmounting, { "log_unit_unmounting", RESET } },
        { LogEvent::Unmounted, { "log_unit_unmounted", GREEN } },
        { LogEvent::UnitMountedUnmounting, { "log_unit_unmounting", RESET } },
        { LogEvent::UnitUnmountFailed, { "log_unit_unmount_failed", RED } },
        { LogEvent::CleanupHeader, { "log_unit_cleanup_header", RESET } },
        { LogEvent::CleanupBackup, { "log_unit_cleanup_backup", RESET } },
        { LogEvent::FormatStart, { "log_unit_format_start", RESET } },
        { LogEvent::FormatOk, { "log_unit_format_ok", GREEN } },
        { LogEvent::FormatFailed, { "log_unit_format_failed", RED } },
        { LogEvent::Sector0BackedUp, { "log_unit_s0_backedup", RESET } },
        { LogEvent::Sector0Wiped, { "log_unit_s0_wiped", RESET } },
        { LogEvent::Sector0Restored, { "log_unit_s0_restored", RESET } },
        { LogEvent::Sector0WipeFailed, { "log_unit_sector0_wipe_failed", YELLOW } },
        { LogEvent::Sector0RestoreFailed, { "log_unit_sector0_restore_failed", YELLOW } },
        { LogEvent::Sector0ReadFailed, { "log_unit_sector0_read_failed", RED } },
    };
    return map;
}

void print(LogLevel level, LogEvent event, const std::string& data) {
    (void)level;

    if (event == LogEvent::KeyDerived && !data.empty()) {
        std::cout << YELLOW << "  ⚠ " << data << RESET << std::endl;
        return;
    }
    if (event == LogEvent::KmacCalculating) {
        std::cout << TR().t(data == "verificando" ? "log_unit_kmac_verify" : "log_unit_kmac_calc") << std::endl;
        return;
    }
    if (event == LogEvent::IoModeInfo) {
        std::cout << (data == "direct" ? TR().t("log_unit_io_direct") : TR().t("log_unit_io_normal")) << std::endl;
        return;
    }
    if (event == LogEvent::ProcessingFailed && !data.empty()) {
        std::cout << RED << TR().t("log_unit_processing_failed") << " (" << data << ")" << RESET << std::endl;
        return;
    }

    auto it = getLogMap().find(event);
    if (it != getLogMap().end()) {
        std::string msg = TR().t(it->second.key, {data});
        std::cout << it->second.color << msg << RESET << std::endl;
    }
}

} // namespace UnitEvents
