// ui/unit_encryptor_ui.h - 0.1 alpha
#ifndef UI_UNIT_ENCRYPTOR_UI_H
#define UI_UNIT_ENCRYPTOR_UI_H
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <termios.h>
#include <unistd.h>
#include <limits>
#include <csignal>
#include <cstdlib>
#include <algorithm>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include "../cipher/unit_encryptor.h"
#include "../keygest/key_manager.h"
#include "translator.h"

#ifndef UI_UNIT_COLORS_DEFINED
#define UI_UNIT_COLORS_DEFINED
#define RESET  "\033[0m"
#define RED  "\033[31m"
#define GREEN  "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE  "\033[34m"
#define MAGENTA  "\033[35m"
#define CYAN  "\033[36m"
#define WHITE  "\033[37m"
#define BOLD  "\033[1m"
#define BRIGHT_RED  "\033[91m"
#define BRIGHT_GREEN  "\033[92m"
#define BRIGHT_YELLOW  "\033[93m"
#define BRIGHT_BLUE  "\033[94m"
#define BRIGHT_MAGENTA  "\033[95m"
#define BRIGHT_CYAN  "\033[96m"
#define BRIGHT_WHITE  "\033[97m"
#endif

class ProgBar {
private:
    int width;
    std::string prefix;
    std::string suffix;
    std::chrono::steady_clock::time_point start_time;
    uint64_t total_bytes;
    uint64_t current_bytes;
    double last_speed;
public:
    ProgBar(int bar_width = 50, const std::string& pre = "", const std::string& suf = "")
        : width(bar_width), prefix(pre), suffix(suf), total_bytes(0), current_bytes(0), last_speed(0) {
        start_time = std::chrono::steady_clock::now();
    }
    void setTotal(uint64_t total) { total_bytes = total; }
    void update(uint64_t current) {
        current_bytes = current;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed > 0)
            last_speed = (current_bytes / 1048576.0) / (elapsed / 1000.0);
        render();
    }
    void render() {
        if (total_bytes == 0) return;
        double progress = (double)current_bytes / total_bytes;
        int pos = (int)(width * progress);
        double gb_done = current_bytes / (double)(1024ULL * 1024ULL * 1024ULL);
        double gb_total = total_bytes / (double)(1024ULL * 1024ULL * 1024ULL);
        int percent = (int)(progress * 100);
        std::string eta = TR().t("unit_eta_calculating");
        if (last_speed > 0 && current_bytes > 0) {
            uint64_t remaining_bytes = total_bytes - current_bytes;
            double remaining_secs = remaining_bytes / (last_speed * 1048576.0);
            if (remaining_secs < 3600) {
                int minutes = (int)remaining_secs / 60;
                int seconds = (int)remaining_secs % 60;
                std::stringstream ss; ss << minutes << "m " << seconds << "s"; eta = ss.str();
            } else {
                int hours = (int)remaining_secs / 3600;
                int minutes = ((int)remaining_secs % 3600) / 60;
                std::stringstream ss; ss << hours << "h " << minutes << "m"; eta = ss.str();
            }
        }
        std::cout << "\r" << prefix << " " << BLUE << "[" << RESET;
        for (int i = 0; i < width; ++i) {
            if (i < pos) std::cout << GREEN << "█" << RESET;
            else if (i == pos) std::cout << BLUE << "█" << RESET;
            else std::cout << "░";
        }
        std::cout << BLUE << "]" << RESET;
        std::cout << " " << GREEN << std::setw(3) << percent << "%" << RESET;
        std::cout << " " << BLUE << std::fixed << std::setprecision(2) << gb_done << "/" << gb_total << " GB" << RESET;
        std::cout << " " << GREEN << std::fixed << std::setprecision(2) << last_speed << " MB/s" << RESET;
        std::cout << " " << BLUE << "ETA: " << eta << RESET;
        std::cout << suffix;
        std::cout.flush();
    }
    void finish() { std::cout << std::endl; }
};

class UnitEncryptorUI {
private:
    UnitEncryptor& core_;
    KeyManager* keyManager_;
    std::string currentKeyName;
    inline static UnitEncryptorUI* instance = nullptr;

    static void signalHandler(int signal) { exit(signal); }
    static void setupSignalHandlers() {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP, signalHandler);
        signal(SIGQUIT, signalHandler);
    }

    std::string getInput(const std::string& prompt) {
        std::cout << prompt;
        std::string input;
        if (!std::getline(std::cin, input)) exit(0);
        return input;
    }
    void waitForEnter() {
        std::cout << "\n" << YELLOW << TR().t("press_enter") << RESET;
        std::string dummy;
        if (!std::getline(std::cin, dummy)) exit(0);
    }
    void menu_line(const std::string& marker, const std::string& label) {
        std::string plain = " " + marker + " " + label;
        std::cout << BLUE << "│" << GREEN << " " << marker << " " << MAGENTA << label << pad_to(plain, 68) << BLUE
                  << "│" << RESET << "\n";
    }

    void onCoreLog(LogLevel level, LogEvent event, const std::string& data) {
        (void)level;
        if (logHeaderEvents(event, data)) return;
        if (logCryptoEvents(event, data)) return;
        if (logDeviceEvents(event, data)) return;
        if (logProcessEvents(event, data)) return;
        if (logSectorEvents(event, data)) return;
        
        if (event == LogEvent::XtsFallback) {} 
        else if (event == LogEvent::HeaderVerified && data == "reading") {}
    }

    bool logHeaderEvents(LogEvent event, const std::string& data) {
        switch (event) {
            case LogEvent::HeaderWriting: std::cout << TR().t("log_unit_header_writing") << std::endl; return true;
            case LogEvent::HeaderWritten: std::cout << GREEN << TR().t("log_unit_header_written") << RESET << std::endl; return true;
            case LogEvent::HeaderReadFailed: std::cout << YELLOW << TR().t("log_unit_header_read_failed") << RESET << std::endl; return true;
            case LogEvent::HeaderVerified: if (data != "reading") std::cout << GREEN << TR().t("log_unit_header_verified", {data}) << RESET << std::endl; return true;
            case LogEvent::HeaderRemoved: std::cout << GREEN << TR().t("log_unit_header_removed") << RESET << std::endl; return true;
            case LogEvent::HeaderRestoring: std::cout << TR().t("log_unit_header_restoring") << std::endl; return true;
            case LogEvent::HeaderRestored: std::cout << GREEN << TR().t("log_unit_header_restored") << RESET << std::endl; return true;
            case LogEvent::HeaderRestoreFailed: std::cout << RED << TR().t("log_unit_header_restore_failed") << RESET << std::endl; return true;
            case LogEvent::HeaderCleanFailed: std::cout << RED << TR().t("log_unit_header_clean_failed") << RESET << std::endl; return true;
            case LogEvent::BackupSaved: std::cout << GREEN << TR().t("log_unit_backup_saved") << RESET << std::endl; return true;
            case LogEvent::BackupSaveFailed: std::cout << YELLOW << TR().t("log_unit_backup_save_failed") << RESET << std::endl; return true;
            case LogEvent::BackupLoaded: std::cout << GREEN << TR().t("log_unit_backup_loaded") << RESET << std::endl; return true;
            case LogEvent::BackupLoadFailed: std::cout << RED << TR().t("log_unit_backup_load_failed") << RESET << std::endl; return true;
            case LogEvent::BackupRemoved: std::cout << GREEN << TR().t("log_unit_backup_removed") << RESET << std::endl; return true;
            case LogEvent::HeaderBackupAttempting: std::cout << YELLOW << TR().t("log_unit_header_backup_attempting") << RESET << std::endl; return true;
            case LogEvent::HeaderCleanFsyncFailed: std::cout << RED << TR().t("log_unit_header_clean_fsync_failed") << RESET << std::endl; return true;
            case LogEvent::HeaderCleanWriteFailed: std::cout << RED << TR().t("log_unit_header_clean_write_failed") << RESET << std::endl; return true;
            default: return false;
        }
    }

    bool logCryptoEvents(LogEvent event, const std::string& data) {
        switch (event) {
            case LogEvent::SaltGenerating: std::cout << TR().t("log_unit_salt_generating") << std::endl; return true;
            case LogEvent::SaltGenerated: std::cout << GREEN << TR().t("log_unit_salt_generated") << RESET << std::endl; return true;
            case LogEvent::SaltError: std::cout << RED << TR().t("log_unit_salt_error") << RESET << std::endl; return true;
            case LogEvent::KeyDeriving: std::cout << TR().t("log_unit_key_deriving") << std::endl; return true;
            case LogEvent::KeyDerived: 
                if (data.empty()) std::cout << GREEN << TR().t("log_unit_key_derived") << RESET << std::endl;
                else std::cout << YELLOW << "  ⚠ " << data << RESET << std::endl; 
                return true;
            case LogEvent::KeyDeriveError: std::cout << RED << TR().t("log_unit_key_derive_error") << RESET << std::endl; return true;
            case LogEvent::KmacCalculating: 
                if (data == "verificando") std::cout << TR().t("log_unit_kmac_verify") << std::endl;
                else std::cout << TR().t("log_unit_kmac_calc") << std::endl; 
                return true;
            case LogEvent::KmacError: std::cout << RED << TR().t("log_unit_kmac_error", {data}) << RESET << std::endl; return true;
            case LogEvent::KmacVerified: std::cout << GREEN << TR().t("log_unit_kmac_verified") << RESET << std::endl; return true;
            case LogEvent::KmacFailed: std::cout << RED << TR().t("log_unit_kmac_failed") << RESET << std::endl; return true;
            case LogEvent::KmacSizeError: std::cout << RED << TR().t("log_unit_kmac_size_error") << RESET << std::endl; return true;
            case LogEvent::LegacyHeaderNoKdf: std::cout << YELLOW << "  ⚠ " << TR().t("log_unit_legacy_header_no_kdf") << RESET << std::endl; return true;
            case LogEvent::MasterKeyInvalid: std::cout << RED << TR().t("log_unit_master_key_invalid", {data}) << RESET << std::endl; return true;
            default: return false;
        }
    }

    bool logDeviceEvents(LogEvent event, const std::string& data) {
        switch (event) {
            case LogEvent::SystemDiskBlocked: std::cout << BRIGHT_RED << "\n" << TR().t("log_unit_sys_disk_blocked") << RESET << std::endl; return true;
            case LogEvent::UnitAlreadyEncrypted: std::cout << YELLOW << TR().t("log_unit_already_encrypted") << RESET << std::endl; return true;
            case LogEvent::UnitNotEncrypted: std::cout << YELLOW << TR().t("log_unit_not_encrypted") << RESET << std::endl; return true;
            case LogEvent::UnitMounted: std::cout << YELLOW << TR().t("log_unit_mounted", {data}) << RESET << std::endl; return true;
            case LogEvent::DeviceOpenFailed: std::cout << RED << TR().t("log_unit_device_open_failed", {data}) << RESET << std::endl; return true;
            case LogEvent::DeviceOpenRetry: std::cout << YELLOW << TR().t("log_unit_device_open_retry", {data}) << RESET << std::endl; return true;
            case LogEvent::DeviceSizeFailed: std::cout << RED << TR().t("log_unit_device_size_failed", {data}) << RESET << std::endl; return true;
            case LogEvent::DeviceTypeDetected: std::cout << TR().t("log_unit_device_type", {data}) << std::endl; return true;
            case LogEvent::RequiresRoot: std::cout << RED << TR().t("log_unit_requires_root") << RESET << std::endl; return true;
            case LogEvent::InvalidHeaderRegion: std::cout << RED << TR().t("log_unit_invalid_header_region") << RESET << std::endl; return true;
            default: return false;
        }
    }

    bool logProcessEvents(LogEvent event, const std::string& data) {
        switch (event) {
            case LogEvent::ConfigAuto: std::cout << TR().t("log_unit_config_auto", {data}) << std::endl; return true;
            case LogEvent::ConfigCustom: std::cout << TR().t("log_unit_config_custom", {data}) << std::endl; return true;
            case LogEvent::ChunkSizeInfo: std::cout << TR().t("log_unit_chunk_size", {data}) << std::endl; return true;
            case LogEvent::IoModeInfo: std::cout << (data == "direct" ? TR().t("log_unit_io_direct") : TR().t("log_unit_io_normal")) << std::endl; return true;
            case LogEvent::DataSizeInfo: std::cout << TR().t("log_unit_data_size", {StorUnit::formatBytes(std::stoull(data))}) << std::endl; return true;
            case LogEvent::ChunkCountInfo: std::cout << TR().t("log_unit_chunk_count", {data}) << std::endl; return true;
            case LogEvent::Processing: std::cout << TR().t("log_unit_processing") << std::endl; return true;
            case LogEvent::ProcessingComplete: std::cout << GREEN << TR().t("log_unit_processing_complete") << RESET << std::endl; return true;
            case LogEvent::ProcessingFailed: 
                std::cout << RED << TR().t("log_unit_processing_failed"); 
                if (!data.empty()) std::cout << " (" << data << ")"; 
                std::cout << RESET << std::endl; return true;
            case LogEvent::ProcessingStopped: std::cout << YELLOW << TR().t("log_unit_processing_stopped") << RESET << std::endl; return true;
            case LogEvent::ChunkReadError: std::cout << RED << TR().t("log_unit_chunk_read_error", {data}) << RESET << std::endl; return true;
            case LogEvent::ChunkProcessError: std::cout << RED << TR().t("log_unit_chunk_process_error", {data}) << RESET << std::endl; return true;
            case LogEvent::ChunkWriteError: std::cout << RED << TR().t("log_unit_chunk_write_error", {data}) << RESET << std::endl; return true;
            case LogEvent::FinalFsyncFailed: std::cout << RED << TR().t("log_unit_final_fsync_failed") << RESET << std::endl; return true;
            case LogEvent::ProcessingFsyncFailed: std::cout << RED << TR().t("log_unit_processing_fsync_failed") << RESET << std::endl; return true;
            case LogEvent::ReorderOverflow: std::cout << RED << TR().t("log_unit_reorder_overflow") << RESET << std::endl; return true;
            case LogEvent::Mounting: std::cout << TR().t("log_unit_mounting", {data}) << std::endl; return true;
            case LogEvent::Mounted: std::cout << GREEN << TR().t("log_unit_mounted_ok", {data}) << RESET << std::endl; return true;
            case LogEvent::MountFailed: std::cout << RED << TR().t("log_unit_mount_failed", {data}) << RESET << std::endl; return true;
            case LogEvent::Unmounting: std::cout << TR().t("log_unit_unmounting", {data}) << std::endl; return true;
            case LogEvent::Unmounted: std::cout << GREEN << TR().t("log_unit_unmounted") << RESET << std::endl; return true;
            case LogEvent::UnitMountedUnmounting: std::cout << TR().t("log_unit_unmounting", {data}) << std::endl; return true;
            case LogEvent::UnitUnmountFailed: std::cout << RED << TR().t("log_unit_unmount_failed") << RESET << std::endl; return true;
            case LogEvent::CleanupHeader: std::cout << TR().t("log_unit_cleanup_header") << std::endl; return true;
            case LogEvent::CleanupBackup: std::cout << TR().t("log_unit_cleanup_backup") << std::endl; return true;
            case LogEvent::FormatStart: std::cout << TR().t("log_unit_format_start", {data}) << std::endl; return true;
            case LogEvent::FormatOk: std::cout << GREEN << TR().t("log_unit_format_ok") << RESET << std::endl; return true;
            case LogEvent::FormatFailed: std::cout << RED << TR().t("log_unit_format_failed", {data}) << RESET << std::endl; return true;
            default: return false;
        }
    }

    bool logSectorEvents(LogEvent event, const std::string& data) {
        switch (event) {
            case LogEvent::Sector0BackedUp: std::cout << TR().t("log_unit_s0_backedup") << std::endl; return true;
            case LogEvent::Sector0Wiped: std::cout << TR().t("log_unit_s0_wiped") << RESET << std::endl; return true;
            case LogEvent::Sector0Restored: std::cout << TR().t("log_unit_s0_restored") << RESET << std::endl; return true;
            case LogEvent::Sector0WipeFailed: std::cout << YELLOW << "  ⚠ " << TR().t("log_unit_sector0_wipe_failed") << RESET << std::endl; return true;
            case LogEvent::Sector0RestoreFailed: std::cout << YELLOW << "  ⚠ " << TR().t("log_unit_sector0_restore_failed") << RESET << std::endl; return true;
            case LogEvent::Sector0ReadFailed: std::cout << RED << TR().t("log_unit_sector0_read_failed") << RESET << std::endl; return true;
            default: return false;
        }
    }

    void onCoreProgress(uint64_t current, uint64_t total, double speed) {
        (void)current; (void)total; (void)speed;
    }

    std::string selectKeyFromManager() {
        if (!keyManager_) return "";
        auto keys = keyManager_->getActiveKeys();
        if (keys.empty()) {
            std::cout << YELLOW << TR().t("univ_keys_none") << RESET << std::endl;
            return "";
        }
        std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("univ_keys_title") << BLUE
                  << "]──────────────────────────────────────────────┐\n";
        for (size_t i = 0; i < keys.size(); i++)
            std::cout << BLUE << "│ " << GREEN << " [" << i + 1 << "] " << MAGENTA << keys[i] << RESET << std::endl;
        std::cout << BLUE << "│ " << GREEN << " [0] " << MAGENTA << TR().t("univ_keys_cancel") << RESET << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::string prompt = std::string(BRIGHT_GREEN) + "\n" + TR().t("univ_keys_prompt", {std::to_string(keys.size())}) + " " + RESET;
        std::string c = getInput(prompt);
        if (c == "0") return "";
        try {
            int idx = std::stoi(c) - 1;
            if (idx >= 0 && idx < (int)keys.size()) return keys[idx];
        } catch (...) {}
        return "";
    }

    Botan::secure_vector<uint8_t> getMasterKey() {
        if (!keyManager_) return {};
        std::string keyName = currentKeyName;
        if (keyName.empty()) {
            keyName = selectKeyFromManager();
            if (keyName.empty()) return {};
            currentKeyName = keyName;
        }
        Botan::secure_vector<uint8_t> keyBytes = keyManager_->getKeyValue(keyName);
        if (keyBytes.empty()) return {};
        if (keyBytes.size() != 32) {
            std::cout << RED << TR().t("unit_no_key") << " (32 bytes, " << keyBytes.size() << ")" << RESET << std::endl;
            return {};
        }
        return keyBytes;
    }

    void showConfigMenu() {
        while (true) {
            UnitSettings& settings = core_.getSettings();
            CustCfg& custom = settings.getCustom();
            const SystemCfg& fixed = settings.getFixed();
            bool use_custom = settings.isCustomMode();
            std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("unit_config_title") << BLUE
                      << "]──────────────────────────────────────────┐\n";
            std::cout << BLUE << "│ " << MAGENTA << TR().t("unit_config_default") << RESET << std::endl;
            {
                std::string line = " " + TR().t("unit_config_cores") + std::to_string(HardwareDetect::getCoreCount());
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("unit_config_cores") << GREEN
                          << HardwareDetect::getCoreCount() << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line = " " + TR().t("unit_config_io_threads") + std::to_string(fixed.io_threads);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("unit_config_io_threads") << GREEN
                          << fixed.io_threads << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line = " " + TR().t("unit_config_crypto_threads") + std::to_string(fixed.crypto_threads);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("unit_config_crypto_threads") << GREEN
                          << fixed.crypto_threads << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line = " " + TR().t("unit_config_reserved_os") + std::to_string(fixed.reserved_os);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("unit_config_reserved_os") << GREEN
                          << fixed.reserved_os << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            if (use_custom && custom.custom_mode) {
                std::cout << BLUE << "\n│ " << MAGENTA << "  " << TR().t("unit_config_custom") << RESET << std::endl;
                {
                    std::string line = "  " + TR().t("unit_config_buffer") + std::to_string(custom.buffer_size_mb) + " MB";
                    std::cout << BLUE << "│ " << RESET << "  " << GREEN << TR().t("unit_config_buffer") << RESET
                              << custom.buffer_size_mb << " MB" << pad_to(line, 68) << BLUE << "│\n";
                }
                {
                    std::string line = "  " + TR().t("unit_config_io_threads") + std::to_string(custom.io_threads);
                    std::cout << BLUE << "│ " << RESET << "  " << GREEN << TR().t("unit_config_io_threads") << RESET
                              << custom.io_threads << pad_to(line, 68) << BLUE << "│\n";
                }
                {
                    std::string line = "  " + TR().t("unit_config_crypto_threads") + std::to_string(custom.crypto_threads);
                    std::cout << BLUE << "│ " << RESET << "  " << GREEN << TR().t("unit_config_crypto_threads") << RESET
                              << custom.crypto_threads << pad_to(line, 68) << BLUE << "│\n";
                }
                {
                    std::string di = custom.use_direct_io ? TR().t("unit_config_yes") : TR().t("unit_config_no");
                    std::string line = "  " + TR().t("unit_config_direct_io") + di;
                    std::cout << BLUE << "│ " << RESET << "  " << GREEN << TR().t("unit_config_direct_io") << RESET
                              << di << pad_to(line, 68) << BLUE << "│\n";
                }
            } else {
                std::cout << BLUE << "│ " << YELLOW << "  " << TR().t("unit_config_inactive") << RESET << std::endl;
            }
            std::cout << BLUE << "│ " << RESET << "\n";
            menu_line("[1]", TR().t("unit_config_menu_custom"));
            menu_line("[2]", TR().t("unit_config_menu_toggle"));
            menu_line("[0]", TR().t("unit_config_menu_back"));
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
            
            std::string prompt = std::string(BRIGHT_GREEN) + "\n" + TR().t("unit_config_menu_prompt") + " " + RESET;
            std::string c = getInput(prompt);
            if (c == "0") break;
            else if (c == "1") {
                std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("unit_config_custom_title") << BLUE
                          << "]────────────────────────────────────┐\n";
                std::string input;
                std::cout << BLUE << "│ " << RESET << TR().t("unit_config_custom_buffer", {std::to_string(custom.buffer_size_mb)}) << " ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.buffer_size_mb = std::stoul(input);
                std::cout << BLUE << "│ " << RESET << TR().t("unit_config_custom_io", {std::to_string(custom.io_threads)}) << " ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.io_threads = std::stoi(input);
                std::cout << BLUE << "│ " << RESET << TR().t("unit_config_custom_crypto", {std::to_string(custom.crypto_threads)}) << " ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.crypto_threads = std::stoi(input);
                std::cout << BLUE << "│ " << RESET << TR().t("unit_config_custom_direct", {custom.use_direct_io ? "s" : "n"}) << " ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.use_direct_io = (input == "s" || input == "S");
                std::cout << BLUE << "│ " << RESET << TR().t("unit_config_custom_mode_prompt", {custom.custom_mode ? "s" : "n"}) << " ";
                std::getline(std::cin, input);
                if (!input.empty()) custom.custom_mode = (input == "s" || input == "S");
                std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << std::endl;
                settings.save();
                std::cout << GREEN << "\n" << TR().t("unit_config_saved") << RESET << std::endl;
            } else if (c == "2") {
                settings.setCustomMode(!settings.isCustomMode());
                settings.save();
                std::cout << GREEN << "\n"
                          << (settings.isCustomMode() ? TR().t("unit_config_mode_on") : TR().t("unit_config_mode_off")) << RESET << std::endl;
            }
        }
    }

    void renderProcessConfirmation(const StorUnit& unit, bool encrypt, const std::string& keyword) {
        std::cout << BLUE << "\n┌─[" << MAGENTA
                  << (encrypt ? TR().t("unit_process_title_cifrar") : TR().t("unit_process_title_descifrar")) << BLUE
                  << "]─────────────────────────────────────────┐\n";
        {
            std::string line = " " + TR().t("unit_detail_size") + unit.getSizeStr();
            std::cout << BLUE << "│ " << RESET << TR().t("unit_detail_size") << YELLOW << unit.getSizeStr() << RESET
                      << pad_to(line, 68) << BLUE << "│\n";
        }
        {
            std::string line = " " + TR().t("unit_detail_type") + unit.getDevTypeStr();
            std::cout << BLUE << "│ " << RESET << TR().t("unit_detail_type") << getDevTypeColor(unit.device_type)
                      << unit.getDevTypeStr() << RESET << pad_to(line, 68) << BLUE << "│\n";
        }
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        (void)keyword;
    }

    void printStats(const UnitEncryptor::Stats& stats) {
        std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("unit_stats_title") << BLUE
                  << "]─────────────────────────────────────────┐\n";
        {
            std::string line = " " + TR().t("unit_stats_total") + StorUnit::formatBytes(stats.total_bytes);
            std::cout << BLUE << "│ " << RESET << TR().t("unit_stats_total") << GREEN
                      << StorUnit::formatBytes(stats.total_bytes) << RESET << pad_to(line, 68) << BLUE << "│\n";
        }
        {
            std::string line = " " + TR().t("unit_stats_time") + std::to_string(stats.total_time_ms / 1000) + " s";
            std::cout << BLUE << "│ " << RESET << TR().t("unit_stats_time") << GREEN
                      << (stats.total_time_ms / 1000) << " s" << RESET << pad_to(line, 68) << BLUE << "│\n";
        }
        {
            std::stringstream ss;
            ss << std::fixed << std::setprecision(2) << stats.avg_speed_mbps;
            std::string line = " " + TR().t("unit_stats_speed") + ss.str() + " MB/s";
            std::cout << BLUE << "│ " << RESET << TR().t("unit_stats_speed") << GREEN << ss.str() << " MB/s"
                      << RESET << pad_to(line, 68) << BLUE << "│\n";
        }
        std::cout << BLUE << "└─────────────────────────────────────────────────────────┘" << RESET << std::endl;
    }

    bool processUnit(StorUnit& unit, bool encrypt) {
        if (encrypt && unit.is_encrypted) { std::cout << YELLOW << TR().t("unit_units_encrypted") << RESET << std::endl; return false; }
        if (!encrypt && !unit.is_encrypted) { std::cout << YELLOW << TR().t("unit_units_normal") << RESET << std::endl; return false; }
        if (unit.is_system_disk) { std::cout << BRIGHT_RED << "\n" << TR().t("unit_detail_system") << RESET << std::endl; return false; }
        
        if (unit.is_mounted) {
            std::cout << YELLOW << TR().t("log_unit_mounted", {unit.mount_point}) << RESET << std::endl;
            std::cout << TR().t("unit_process_unmount_prompt") << " (S/n): ";
            std::string resp = getInput("");
            if (resp.empty() || resp == "S" || resp == "s") {
                if (!core_.unmountDevice(unit)) { std::cout << RED << TR().t("log_unit_unmount_failed") << RESET << std::endl; return false; }
            } else return false;
        }

        Botan::secure_vector<uint8_t> master_key = getMasterKey();
        if (master_key.empty() || master_key.size() != 32) {
            std::cout << RED << TR().t("unit_no_key_short") << RESET << std::endl;
            return false;
        }

        std::string keyword = encrypt ? TR().t("unit_process_keyword_encrypt") : TR().t("unit_process_keyword_decrypt");
        renderProcessConfirmation(unit, encrypt, keyword);

        std::string confirm = getInput("\n" + TR().t("unit_process_confirm_prompt", {keyword}) + " ");
        if (confirm != keyword) return false;

        bool delegating = (geteuid() != 0);
        if (delegating) {
            std::cout << BRIGHT_YELLOW << "\n" << TR().t("unit_process_root_warning") << "\n"
                      << "  " << TR().t("unit_process_root_hint1") << "\n"
                      << "  " << TR().t("unit_process_root_hint2") << "\n" << RESET << "\n";
        }

        ProgBar progress_bar(50, "", "");
        progress_bar.setTotal(unit.total_size);

        bool ok;
        if (delegating) {
            ok = core_.executeElevatedOp(unit, encrypt, master_key);
        } else {
            core_.setProgressCallback([&progress_bar](uint64_t cur, uint64_t total, double speed) {
                progress_bar.update(cur); (void)total; (void)speed;
            });
            ok = core_.processUnit(unit, encrypt, master_key);
            progress_bar.finish();
        }

        if (ok) {
            if (!delegating) printStats(core_.getLastStats());
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            if (!encrypt && !delegating) {
                std::cout << "\n" << TR().t("unit_process_mount_after") << " (s/N): ";
                std::string resp;
                std::getline(std::cin, resp);
                if (resp == "s" || resp == "S") {
                    std::string mp = "/mnt/usb_" + std::to_string(time(nullptr));
                    core_.mountDevice(unit, mp);
                }
            }
            core_.refresh();
        }
        return ok;
    }

    static const char* getDevTypeColor(DevType type) {
        switch (type) {
            case DevType::NVME: return BRIGHT_GREEN;
            case DevType::USB3: return BRIGHT_CYAN;
            case DevType::SSD_SATA: return BRIGHT_BLUE;
            case DevType::USB2: return YELLOW;
            case DevType::HDD: return BRIGHT_YELLOW;
            case DevType::SD_CARD: return MAGENTA;
            default: return RESET;
        }
    }

    void showFormatMenu(StorUnit& unit) {
        std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("unit_format_title") << BLUE
                  << "]────────────────────────────────────────┐\n";
        if (unit.is_encrypted) {
            std::cout << BLUE << "│ " << YELLOW << TR().t("unit_format_warn_encrypted") << RESET << std::endl;
            menu_line("[1]", TR().t("unit_format_clean"));
        }
        std::cout << BLUE << "│ " << RESET << "\n";
        std::cout << BLUE << "│ " << MAGENTA << TR().t("unit_format_fs_title") << RESET << std::endl;
        menu_line("[2]", TR().t("unit_format_fat32"));
        menu_line("[3]", TR().t("unit_format_ntfs"));
        menu_line("[4]", TR().t("unit_format_ext4"));
        menu_line("[5]", TR().t("unit_format_exfat"));
        menu_line("[0]", TR().t("unit_format_cancel"));
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        std::cout << BRIGHT_GREEN << "\n" << TR().t("unit_format_prompt") << " " << RESET;
        std::string c;
        std::getline(std::cin, c);
        if (c == "0") return;
        
        if (c == "1" && unit.is_encrypted) {
            if (core_.cleanHeader(unit)) {
                unit.is_encrypted = false;
                unit.has_header_backup = false;
                std::cout << GREEN << "\n" << TR().t("unit_format_clean_ok") << RESET << std::endl;
            }
            return;
        }
        
        std::string fstype;
        if (c == "2") fstype = "vfat";
        else if (c == "3") fstype = "ntfs";
        else if (c == "4") fstype = "ext4";
        else if (c == "5") fstype = "exfat";
        else return;

        if (core_.formatDevice(unit, fstype)) {
            unit.is_encrypted = false;
            unit.has_header_backup = false;
            unit.filesystem = fstype;
            std::cout << GREEN << "\n" << TR().t("unit_format_ok") << RESET << std::endl;
        }
    }

    void renderUnitMenu(const StorUnit& u) {
        std::cout << BLUE << "\n┌─[" << MAGENTA << u.device_path << BLUE
                  << "]────────────────────────────────────────────┐\n";
        {
            std::string line = " " + TR().t("unit_detail_size") + u.getSizeStr();
            std::cout << BLUE << "│ " << RESET << TR().t("unit_detail_size") << GREEN << u.getSizeStr() << RESET
                      << pad_to(line, 68) << BLUE << "│\n";
        }
        {
            std::string line = " " + TR().t("unit_detail_type") + u.getDevTypeStr();
            std::cout << BLUE << "│ " << RESET << TR().t("unit_detail_type") << getDevTypeColor(u.device_type)
                      << u.getDevTypeStr() << RESET << pad_to(line, 68) << BLUE << "│\n";
        }
        {
            std::string state = u.is_encrypted ? TR().t("unit_units_encrypted") : TR().t("unit_units_normal");
            std::string line = " " + TR().t("unit_detail_state") + state;
            std::cout << BLUE << "│ " << RESET << TR().t("unit_detail_state")
                      << (u.is_encrypted ? BRIGHT_RED : GREEN) << state << RESET << pad_to(line, 68) << BLUE << "│\n";
        }
        if (!u.is_encrypted && u.has_header_backup) {
            std::string warn = " " + TR().t("unit_header_corrupt_warn");
            std::cout << BLUE << "│ " << BRIGHT_RED << "  " << TR().t("unit_header_corrupt_warn") << pad_to(warn, 68) << BLUE << "│\n";
        }
        if (u.has_header_backup && u.is_encrypted) {
            std::string line = " " + TR().t("unit_detail_backup");
            std::cout << BLUE << "│ " << GREEN << "  " << TR().t("unit_detail_backup") << pad_to(line, 68) << BLUE << "│\n";
        }
        if (!u.mount_point.empty()) {
            std::string line = " " + TR().t("unit_detail_mounted") + u.mount_point;
            std::cout << BLUE << "│ " << RESET << TR().t("unit_detail_mounted") << YELLOW << u.mount_point << RESET
                      << pad_to(line, 68) << BLUE << "│\n";
        }
        if (u.is_system_disk) {
            std::string line = " " + TR().t("unit_detail_system");
            std::cout << BLUE << "│ " << BRIGHT_RED << "  " << TR().t("unit_detail_system") << pad_to(line, 68) << BLUE << "│\n";
        }
        std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
        if (!u.is_system_disk) menu_line("[1]", u.is_encrypted ? TR().t("unit_action_decrypt") : TR().t("unit_action_encrypt"));
        menu_line("[2]", TR().t("unit_action_mount"));
        menu_line("[3]", TR().t("unit_action_unmount"));
        if (!u.is_system_disk) menu_line("[4]", TR().t("unit_action_format"));
        if (u.has_header_backup) menu_line("[5]", TR().t("unit_action_restore"));
        menu_line("[0]", TR().t("unit_action_back"));
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }

    void handleUnitMenuChoice(const std::string& c, StorUnit& u) {
        if (c == "1" && !u.is_system_disk) {
            if (processUnit(u, !u.is_encrypted)) getInput("\n" + TR().t("press_enter_short") + " ");
            core_.refresh();
        } else if (c == "2") {
            if (!u.is_mounted) {
                std::string mp = "/mnt/usb_" + std::to_string(time(nullptr));
                std::string input = getInput(TR().t("unit_mount_prompt", {mp}) + " ");
                if (!input.empty()) mp = input;
                if (core_.mountDevice(u, mp)) { u.is_mounted = true; u.mount_point = mp; }
            } else {
                std::cout << YELLOW << TR().t("unit_mount_already", {u.mount_point}) << RESET << std::endl;
            }
            getInput("\n" + TR().t("press_enter_short") + " ");
        } else if (c == "3") {
            if (u.is_mounted) core_.unmountDevice(u);
            else std::cout << YELLOW << TR().t("unit_mount_not") << RESET << std::endl;
            getInput("\n" + TR().t("press_enter_short") + " ");
        } else if (c == "4" && !u.is_system_disk) {
            if (u.is_mounted) core_.unmountDevice(u);
            showFormatMenu(u);
            getInput("\n" + TR().t("press_enter_short") + " ");
            core_.refresh();
        } else if (c == "5" && u.has_header_backup) {
            Botan::secure_vector<uint8_t> master_key = getMasterKey();
            if (master_key.empty()) {
                std::cout << RED << TR().t("unit_no_key_short") << RESET << std::endl;
                return;
            }
            core_.restoreHeader(u, master_key);
            getInput("\n" + TR().t("press_enter_short") + " ");
            core_.refresh();
        }
    }

    void unitMenu(StorUnit& u) {
        while (true) {
            renderUnitMenu(u);
            std::string prompt = std::string(BRIGHT_GREEN) + "\n" + TR().t("unit_action_prompt") + " " + RESET;
            std::string c = getInput(prompt);
            if (c == "0") break;
            handleUnitMenuChoice(c, u);
        }
    }

    void renderMainMenu(const std::vector<StorUnit>& units) {
        std::cout << BLUE;
        std::cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        std::cout << "│" << GREEN << BOLD << "                       " << TR().t("unit_title")
                  << pad_to("                       " + TR().t("unit_title"), 69) << BLUE << "│\n";
        std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        {
            std::string hw = "  " + HardwareDetect::getCPUInfo();
            std::cout << "│" << MAGENTA << hw << pad_to(hw, 69) << BLUE << "│\n";
        }
        bool use_custom = core_.getSettings().isCustomMode();
        if (use_custom) {
            std::string line = "  " + TR().t("unit_mode_custom");
            std::cout << "│" << YELLOW << line << pad_to(line, 69) << BLUE << "│\n";
        }
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
        
        if (units.empty()) {
            std::cout << YELLOW << "\n" << TR().t("unit_units_none") << RESET << std::endl;
        } else {
            std::cout << GREEN << "\n" << TR().t("unit_units_title") << RESET << std::endl;
            for (size_t i = 0; i < units.size(); i++) {
                auto& u = units[i];
                std::string icon = u.is_system_disk ? "S" : (u.is_encrypted ? "E" : "N");
                if (u.has_header_backup && u.is_encrypted) icon += "B";
                std::cout << "  [" << GREEN << i + 1 << RESET << "] " << icon << " ";
                std::cout << (u.is_encrypted ? BRIGHT_RED : GREEN) << std::setw(7)
                          << (u.is_system_disk ? TR().t("unit_units_system") : (u.is_encrypted ? TR().t("unit_units_encrypted") : TR().t("unit_units_normal")))
                          << RESET;
                std::cout << " " << CYAN << u.device_path << RESET;
                if (!u.label.empty()) std::cout << " (" << u.label << ")";
                std::cout << " - " << u.getSizeStr();
                std::cout << " " << getDevTypeColor(u.device_type) << "[" << u.getDevTypeStr() << "]" << RESET;
                if (u.is_mounted) std::cout << " " << TR().t("unit_units_mounted_flag");
                if (u.has_header_backup) std::cout << " " << TR().t("unit_units_backup_flag");
                std::string safe_fs = u.getSafeFSType();
                if (u.is_encrypted && !safe_fs.empty()) std::cout << " → " << GREEN << safe_fs << RESET;
                else if (!u.is_encrypted && !u.filesystem.empty()) std::cout << " → " << GREEN << u.filesystem << RESET;
                std::cout << std::endl;
            }
        }
        std::cout << BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        menu_line("[1-" + std::to_string(units.size()) + "]", TR().t("unit_menu_select", {std::to_string(units.size())}));
        menu_line("[C]", TR().t("unit_menu_config"));
        menu_line("[R]", TR().t("unit_menu_refresh"));
        menu_line("[0]", TR().t("unit_menu_exit"));
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }

    void handleMainMenuChoice(const std::string& c, std::vector<StorUnit>& units) {
        if (c == "0") exit(0); 
        else if (c == "R" || c == "r") { core_.refresh(); }
        else if (c == "C" || c == "c") { showConfigMenu(); }
        else {
            try {
                int idx = std::stoi(c) - 1;
                if (idx >= 0 && idx < (int)units.size()) {
                    unitMenu(units[idx]);
                    core_.refresh();
                }
            } catch (...) {}
        }
    }

public:
    UnitEncryptorUI(UnitEncryptor& core, KeyManager* km) : core_(core), keyManager_(km) {
        instance = this;
        setupSignalHandlers();
        core_.setLogCallback([this](LogLevel level, LogEvent event, const std::string& data) { this->onCoreLog(level, event, data); });
        core_.setProgressCallback([this](uint64_t cur, uint64_t total, double speed) { this->onCoreProgress(cur, total, speed); });
    }
    ~UnitEncryptorUI() { instance = nullptr; }

    void showMenu() {
        while (true) {
            core_.refresh();
            auto units = core_.getUnits();
            renderMainMenu(units);
            std::string prompt = std::string(BRIGHT_GREEN) + "\n" + TR().t("unit_menu_prompt", {std::to_string(units.size())}) + " " + RESET;
            std::string c = getInput(prompt);
            if (c == "0") break;
            handleMainMenuChoice(c, units);
        }
    }

    // ========================================================================
    // WORKER ROOT (Ahora en la UI porque maneja TR() y prints)
    // ========================================================================
    static void setupWorkerLogCallback(UnitEncryptor& enc) {
        enc.setLogCallback([](LogLevel level, LogEvent event, const std::string& data) {
            std::string prefix;
            switch (level) {
                case LogLevel::Error:   prefix = RED "  ! " RESET; break;
                case LogLevel::Warning: prefix = YELLOW "  ~ " RESET; break;
                case LogLevel::Success: prefix = GREEN "  + " RESET; break;
                default:                prefix = "  · "; break;
            }
            std::cout << prefix;
            switch (event) {
                case LogEvent::HeaderWritten:      std::cout << TR().t("worker_header_written"); break;
                case LogEvent::HeaderVerified:     std::cout << TR().t("worker_header_verified"); break;
                case LogEvent::BackupSaved:        std::cout << TR().t("worker_backup_saved"); break;
                case LogEvent::SaltGenerating:     std::cout << TR().t("worker_salt_generating"); break;
                case LogEvent::KeyDerived:         std::cout << TR().t("worker_key_derived"); break;
                case LogEvent::DeviceTypeDetected: std::cout << TR().t("worker_device_type", {data}); break;
                case LogEvent::ChunkCountInfo:     std::cout << TR().t("worker_chunk_count", {data}); break;
                case LogEvent::ProcessingComplete: std::cout << TR().t("worker_completed"); break;
                case LogEvent::ProcessingFailed:   std::cout << TR().t("worker_failed"); break;
                case LogEvent::XtsFallback:        break;
                case LogEvent::ConfigAuto:         std::cout << TR().t("worker_config_auto", {data}); break;
                case LogEvent::ConfigCustom:       std::cout << TR().t("worker_config_custom", {data}); break;
                case LogEvent::ChunkSizeInfo:      std::cout << TR().t("worker_chunk_size", {data}); break;
                case LogEvent::IoModeInfo:         std::cout << TR().t("worker_io_mode", {data}); break;
                case LogEvent::DataSizeInfo:       std::cout << TR().t("worker_data_size", {data}); break;
                case LogEvent::Sector0BackedUp:    std::cout << TR().t("worker_sector0_backedup"); break;
                case LogEvent::Sector0Wiped:       std::cout << TR().t("worker_sector0_wiped"); break;
                case LogEvent::Sector0Restored:    std::cout << TR().t("worker_sector0_restored"); break;
                case LogEvent::RequiresRoot:            std::cout << TR().t("log_unit_requires_root"); break;
                case LogEvent::LegacyHeaderNoKdf:       std::cout << TR().t("log_unit_legacy_header_no_kdf"); break;
                case LogEvent::InvalidHeaderRegion:     std::cout << TR().t("log_unit_invalid_header_region"); break;
                case LogEvent::Sector0WipeFailed:       std::cout << TR().t("log_unit_sector0_wipe_failed"); break;
                case LogEvent::Sector0RestoreFailed:    std::cout << TR().t("log_unit_sector0_restore_failed"); break;
                case LogEvent::HeaderCleanFsyncFailed:  std::cout << TR().t("log_unit_header_clean_fsync_failed"); break;
                case LogEvent::HeaderCleanWriteFailed:  std::cout << TR().t("log_unit_header_clean_write_failed"); break;
                case LogEvent::FinalFsyncFailed:        std::cout << TR().t("log_unit_final_fsync_failed"); break;
                case LogEvent::ProcessingFsyncFailed:   std::cout << TR().t("log_unit_processing_fsync_failed"); break;
                case LogEvent::ReorderOverflow:         std::cout << TR().t("log_unit_reorder_overflow"); break;
                case LogEvent::Sector0ReadFailed:       std::cout << TR().t("log_unit_sector0_read_failed"); break;
                case LogEvent::KmacSizeError:           std::cout << TR().t("log_unit_kmac_size_error"); break;
                case LogEvent::HeaderBackupAttempting:  std::cout << TR().t("log_unit_header_backup_attempting"); break;
                default:                                std::cout << data; break;
            }
            std::cout << '\n';
        });
    }

    static void setupWorkerProgressCallback(UnitEncryptor& enc) {
        uint64_t last_pct = UINT64_MAX;
        enc.setProgressCallback([&last_pct](uint64_t cur, uint64_t total, double speed) {
            if (total == 0) return;
            uint64_t pct = (cur * 100) / total;
            if (pct == last_pct && cur != total) return;
            last_pct = pct;

            const int bar_w = 40;
            int pos = (int)((pct * bar_w) / 100);

            std::cout << "\r[" << GREEN;
            for (int i = 0; i < bar_w; ++i)
                std::cout << (i < pos ? '=' : (i == pos ? '>' : ' '));
            std::cout << RESET << "] " << std::setw(3) << pct << "% "
                      << (cur / 1048576) << "/" << (total / 1048576) << " MB "
                      << std::fixed << std::setprecision(2) << speed << " MB/s   " << std::flush;

            if (cur >= total) std::cout << "\n";
        });
    }

    static int tryRunAsWorker(int argc, char* argv[]) {
        if (argc < 2) return -1;
        if (std::string(argv[1]) != "--unit-op") return -1;

        std::string sys_lang = Translator::detectSystemLanguage();
        if (!TR().load(sys_lang)) TR().load("en");

        if (geteuid() != 0) { std::cerr << "✗ " << TR().t("worker_need_root") << "\n"; return 1; }
        if (argc < 6) { std::cerr << "✗ " << TR().t("worker_usage") << "\n"; return 1; }
        
        std::string device = argv[2];
        std::string action = argv[3];
        if (device.rfind("/dev/", 0) != 0) { std::cerr << "✗ " << TR().t("worker_invalid_device") << "\n"; return 1; }
        
        bool encrypt;
        if (action == "encrypt") encrypt = true;
        else if (action == "decrypt") encrypt = false;
        else { std::cerr << "✗ " << TR().t("worker_invalid_action") << "\n"; return 1; }

        std::string keyfile;
        for (int i = 4; i + 1 < argc; ++i) {
            if (std::string(argv[i]) == "--keyfile") { keyfile = argv[i + 1]; break; }
        }
        if (keyfile.empty()) { std::cerr << "✗ " << TR().t("worker_need_keyfile") << "\n"; return 1; }
        if (keyfile.rfind("/dev/shm/.rubic_key_", 0) != 0) { std::cerr << "✗ " << TR().t("worker_invalid_keyfile_path") << "\n"; return 1; }

        int kfd = open(keyfile.c_str(), O_RDONLY);
        if (kfd < 0) { std::cerr << "✗ " << TR().t("worker_open_keyfile_fail") << "\n"; return 1; }
        unlink(keyfile.c_str());

        Botan::secure_vector<uint8_t> master_key(32);
        ssize_t r = read(kfd, master_key.data(), 32);
        close(kfd);
        if (r != 32) { std::cerr << "✗ " << TR().t("worker_master_key_read_fail") << "\n"; return 1; }

        StorUnit u;
        u.device_path = device;
        u.is_encrypted = !encrypt;
        u.is_mounted = false;
        u.is_system_disk = false;
        u.device_type = DevDetect::detect(device);

        UnitEncryptor enc;
        setupWorkerLogCallback(enc);
        setupWorkerProgressCallback(enc);

        bool ok = enc.processUnit(u, encrypt, master_key);
        std::cout << (ok ? GREEN "  OK\n" RESET : RED "  FAIL\n" RESET);
        return ok ? 0 : 1;
    }
};

#endif // UI_UNIT_ENCRYPTOR_UI_H