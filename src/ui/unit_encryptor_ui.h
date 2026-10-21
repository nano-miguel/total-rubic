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
#include <unordered_map>
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

    // =========================================================
    // LA SOLUCIÓN SONARQUBE: Diccionario de Eventos (Map)
    // =========================================================
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

    // Busca en el diccionario. Cero switch.
    void onCoreLog(LogLevel level, LogEvent event, const std::string& data) {
        (void)level;
        
        // Excepciones (casos especiales que tienen lógica propia)
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

        // Búsqueda en el diccionario
        auto it = getLogMap().find(event);
        if (it != getLogMap().end()) {
            std::string msg = TR().t(it->second.key, {data});
            std::cout << it->second.color << msg << RESET << std::endl;
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
            // El Core hace el sudo y maneja /dev/shm. La UI solo espera.
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
};

#endif // UI_UNIT_ENCRYPTOR_UI_H
