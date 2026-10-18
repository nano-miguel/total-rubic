// ui/universal_cipher_ui.h - 0.1 alpha
// Toda la UI de UniversalCipher: menús, prompts, lectura de teclado.

#ifndef UI_UNIVERSAL_CIPHER_UI_H
#define UI_UNIVERSAL_CIPHER_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <memory>
#include <termios.h>
#include <unistd.h>
#include <limits>
#include <csignal>
#include <cstdlib>
#include <algorithm>

#include "../cipher/universal_cipher.h"
#include "../keygest/key_manager.h"
#include "translator.h"

#ifndef UI_CIPHER_COLORS_DEFINED
#define UI_CIPHER_COLORS_DEFINED
#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"
#define BOLD "\033[1m"
#define BRIGHT_RED "\033[91m"
#define BRIGHT_GREEN "\033[92m"
#define BRIGHT_YELLOW "\033[93m"
#define BRIGHT_BLUE "\033[94m"
#define BRIGHT_MAGENTA "\033[95m"
#define BRIGHT_CYAN "\033[96m"
#define BRIGHT_WHITE "\033[97m"
#endif

class UniversalCipherUI {
  private:
    UniversalCipher& core_;
    KeyManager* keyManager_;

    inline static UniversalCipherUI* instance = nullptr;

    static void signalHandler(int signal) {
        if (instance && instance->core_.getNameObfuscator()) {
            instance->core_.getNameObfuscator()->force_save_counters();
        }
        exit(signal);
    }

    static void setupSignalHandlers() {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP, signalHandler);
        signal(SIGQUIT, signalHandler);
    }

    struct termios oldt, newt;

    void disable_echo() {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }

    void enable_echo() {
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }

    std::string get_secure_input(const std::string& prompt) {
        std::cout << prompt;
        disable_echo();
        std::string input;
        std::getline(std::cin, input);
        enable_echo();
        std::cout << std::endl;
        return input;
    }

    std::string getInput(const std::string& prompt) {
        std::cout << prompt;
        std::string input;
        if (!std::getline(std::cin, input)) {
            exit(0); // Salir limpiamente si se cierra el stdin (Ctrl+D)
        }
        return input;
    }

    void waitForEnter() {
        std::cout << "\n" << YELLOW << TR().t("press_enter") << RESET;
        std::string dummy;
        if (!std::getline(std::cin, dummy))
            exit(0);
    }

    void onCoreLog(univ_log::LogLevel level, univ_log::LogEvent event, const std::string& data) {
        (void)level;
        switch (event) {
        case univ_log::LogEvent::PathInvalid:
            std::cout << RED << TR().t("log_univ_path_invalid", {data}) << RESET << std::endl;
            break;
        case univ_log::LogEvent::NoFilesFound:
            std::cout << YELLOW << TR().t("log_univ_no_files") << RESET << std::endl;
            break;
        case univ_log::LogEvent::NoFilesToProcess:
            std::cout << YELLOW << TR().t("log_univ_no_files_process") << RESET << std::endl;
            break;
        case univ_log::LogEvent::ProcessingSingle:
            std::cout << TR().t("log_univ_processing_single") << std::endl;
            break;
        case univ_log::LogEvent::FileDone:
            std::cout << GREEN << TR().t("log_univ_file_done") << RESET << std::endl;
            break;
        case univ_log::LogEvent::FileError:
            std::cout << RED << TR().t("log_univ_file_error") << RESET << std::endl;
            break;
        case univ_log::LogEvent::FileMoveError:
            std::cout << RED << TR().t("log_univ_file_move_error") << RESET << std::endl;
            break;
        case univ_log::LogEvent::ScanError:
            std::cout << RED << "Error escaneando: " << data << RESET << std::endl;
            break;

        case univ_log::LogEvent::NoKeyManager:
            std::cout << RED << TR().t("log_univ_no_keymgr") << RESET << std::endl;
            break;
        case univ_log::LogEvent::KeyNotFound:
            std::cout << RED << TR().t("log_univ_key_not_found", {data}) << RESET << std::endl;
            break;
        case univ_log::LogEvent::KeyNotActive:
            std::cout << RED << TR().t("log_univ_key_not_active", {data}) << RESET << std::endl;
            break;
        case univ_log::LogEvent::KeyValueError:
            std::cout << RED << TR().t("log_univ_key_value_error") << RESET << std::endl;
            break;
        case univ_log::LogEvent::KeyLengthError:
            std::cout << RED << TR().t("log_univ_key_length_error") << RESET << std::endl;
            break;

        case univ_log::LogEvent::CountersError:
            std::cout << RED << "Error guardando contadores: " << data << RESET << std::endl;
            break;
        }
    }

    void onCoreProgress(size_t current, size_t total, const std::string& file) {
        std::cout << "\n[" << current << "/" << total << "] " << BRIGHT_WHITE << file << RESET << std::endl;
    }

    void menu_line(const std::string& marker, const std::string& label) {
        std::string plain = " " + marker + " " + label;
        std::cout << BLUE << "│" << GREEN << " " << marker << " " << MAGENTA << label << pad_to(plain, 68) << BLUE
                  << "│" << RESET << "\n";
    }

  public:
    UniversalCipherUI(UniversalCipher& core, KeyManager* km) : core_(core), keyManager_(km) {
        instance = this;
        setupSignalHandlers();

        core_.setLogCallback([this](univ_log::LogLevel level, univ_log::LogEvent event, const std::string& data) {
            this->onCoreLog(level, event, data);
        });
        core_.setProgressCallback(
            [this](size_t cur, size_t total, const std::string& file) { this->onCoreProgress(cur, total, file); });
    }

    ~UniversalCipherUI() {
        if (core_.getNameObfuscator()) {
            core_.getNameObfuscator()->force_save_counters();
        }
        instance = nullptr;
    }

    std::string selectKey() {
        if (!keyManager_) {
            std::cout << RED << TR().t("univ_keys_no_manager") << RESET << std::endl;
            return "";
        }

        std::vector<std::string> activeKeys = keyManager_->getActiveKeys();
        if (activeKeys.empty()) {
            std::cout << YELLOW << "\n" << TR().t("univ_keys_none") << RESET << std::endl;
            return "";
        }

        std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("univ_keys_title") << BLUE
                  << "]──────────────────────────────────────┐\n";
        std::cout << BLUE << "│" << RESET << "\n";
        std::cout << BLUE << "│ " << GREEN << TR().t("univ_keys_active") << RESET << std::endl;
        for (size_t i = 0; i < activeKeys.size(); i++) {
            std::cout << BLUE << "│   [" << GREEN << i + 1 << BLUE << "] " << CYAN << activeKeys[i] << RESET
                      << std::endl;
        }
        std::cout << BLUE << "│   [" << GREEN << "0" << BLUE << "] " << MAGENTA << TR().t("univ_keys_cancel") << RESET
                  << std::endl;
        std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        std::string prompt = std::string(BRIGHT_GREEN) + "\n" +
                             TR().t("univ_keys_prompt", {std::to_string(activeKeys.size())}) + " " + RESET;
        std::string choiceStr = getInput(prompt);
        if (choiceStr == "0")
            return "";

        try {
            int choice = std::stoi(choiceStr) - 1;
            if (choice >= 0 && choice < static_cast<int>(activeKeys.size())) {
                return activeKeys[choice];
            }
        } catch (...) {
        }

        std::cout << RED << TR().t("univ_keys_invalid") << RESET << std::endl;
        return "";
    }

    void showMenu() {
        while (true) {
            std::cout << BLUE;
            std::cout << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            std::cout << "│" << GREEN << BOLD << "                       " << TR().t("univ_title")
                      << pad_to("                       " + TR().t("univ_title"), 69) << BLUE << "│\n";
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";

            {
                std::string hwInfo = "  AES-256-GCM | " + HardwareDetect::getCPUInfo();
                std::cout << "│" << MAGENTA << hwInfo << pad_to(hwInfo, 69) << BLUE << "│\n";
            }
            {
                std::string thInfo = "  " + TR().t("univ_config_threads_crypto") +
                                     std::to_string(core_.getConfig().thread_config.crypto_threads) + " | " +
                                     std::to_string(core_.getConfig().max_parallel_files) + " files";
                std::cout << "│" << CYAN << thInfo << pad_to(thInfo, 69) << BLUE << "│\n";
            }
            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

            std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("univ_menu_title") << BLUE
                      << "]───────────────────────────────────────────┐\n";
            menu_line("[1]", TR().t("univ_menu_encrypt"));
            menu_line("[2]", TR().t("univ_menu_decrypt"));
            menu_line("[3]", TR().t("univ_menu_config"));
            menu_line("[0]", TR().t("univ_menu_exit"));
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
                      << "\n";

            std::string prompt = std::string(BRIGHT_GREEN) + "\n" + TR().t("univ_menu_prompt") + " " + RESET;
            std::string choice = getInput(prompt);

            if (choice == "1" || choice == "2") {
                std::string keyName = selectKey();
                if (keyName.empty()) {
                    waitForEnter();
                    continue;
                }

                if (keyManager_ && !keyManager_->isKeyActive(keyName) && keyManager_->keyRequiresActivation(keyName)) {
                    std::string activationCode = get_secure_input(TR().t("univ_activation_prompt"));
                    Botan::secure_vector<uint8_t> code(activationCode.begin(), activationCode.end());
                    if (!keyManager_->activateKey(keyName, code)) {
                        std::cout << RED << TR().t("univ_activation_fail") << RESET << std::endl;
                        waitForEnter();
                        continue;
                    }
                }

                if (!core_.setCipherKey(keyName)) {
                    waitForEnter();
                    continue;
                }

                std::string path = getInput("\n" + TR().t("univ_path_prompt"));

                bool result;
                if (choice == "1") {
                    result = core_.encryptPath(path);
                } else {
                    result = core_.decryptPath(path);
                }

                core_.getNameObfuscator()->force_save_counters();

                if (result) {
                    std::cout << GREEN << "\n" << TR().t("univ_ok") << RESET << std::endl;
                }

                const auto& st = core_.getLastStats();
                if (st.total_files > 0) {
                    std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("univ_stats_title") << BLUE
                              << "]─────────────────────────────────────────┐\n";
                    {
                        std::string line = " " + TR().t("univ_stats_files") + std::to_string(st.total_files);
                        std::cout << BLUE << "│ " << RESET << TR().t("univ_stats_files") << GREEN << st.total_files
                                  << RESET << pad_to(line, 68) << BLUE << "│\n";
                    }
                    {
                        std::string line = " " + TR().t("univ_stats_success") + std::to_string(st.success);
                        std::cout << BLUE << "│ " << RESET << TR().t("univ_stats_success") << GREEN << st.success
                                  << RESET << pad_to(line, 68) << BLUE << "│\n";
                    }
                    {
                        std::string line = " " + TR().t("univ_stats_fail") + std::to_string(st.fail);
                        std::cout << BLUE << "│ " << RESET << TR().t("univ_stats_fail") << (st.fail > 0 ? RED : GREEN)
                                  << st.fail << RESET << pad_to(line, 68) << BLUE << "│\n";
                    }
                    {
                        std::string line = " " + TR().t("univ_stats_time") + std::to_string(st.total_time_ms) + " ms";
                        std::cout << BLUE << "│ " << RESET << TR().t("univ_stats_time") << GREEN << st.total_time_ms
                                  << " ms" << RESET << pad_to(line, 68) << BLUE << "│\n";
                    }
                    std::cout << BLUE << "└─────────────────────────────────────────────────────────┘" << RESET
                              << std::endl;
                }

                waitForEnter();
            } else if (choice == "3") {
                showConfigMenu();
            } else if (choice == "0") {
                core_.getNameObfuscator()->force_save_counters();
                break;
            }
        }
    }

    void showConfigMenu() {
        while (true) {
            SystemConfig& config = core_.getConfig();

            std::cout << BLUE << "\n┌─[" << MAGENTA << TR().t("univ_config_title") << BLUE
                      << "]──────────────────────────────────────────┐\n";
            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            std::cout << BLUE << "│ " << MAGENTA << TR().t("univ_config_current") << RESET << std::endl;
            {
                std::string line = " " + TR().t("univ_config_threads_system") +
                                   std::to_string(config.thread_config.total_system_threads);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("univ_config_threads_system") << GREEN
                          << config.thread_config.total_system_threads << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line =
                    " " + TR().t("univ_config_threads_crypto") + std::to_string(config.thread_config.crypto_threads);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("univ_config_threads_crypto") << GREEN
                          << config.thread_config.crypto_threads << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line =
                    " " + TR().t("univ_config_threads_io") + std::to_string(config.thread_config.io_threads);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("univ_config_threads_io") << GREEN
                          << config.thread_config.io_threads << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line =
                    " " + TR().t("univ_config_threads_reserved") + std::to_string(config.thread_config.reserved_os);
                std::cout << BLUE << "│ " << RESET << "  " << TR().t("univ_config_threads_reserved") << YELLOW
                          << config.thread_config.reserved_os << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string buf = std::to_string(config.min_buffer_size / 1024) + "KB - " +
                                  std::to_string(config.max_buffer_size / (1024 * 1024)) + "MB";
                std::string line = " " + TR().t("univ_config_buffer") + buf;
                std::cout << BLUE << "│ " << RESET << TR().t("univ_config_buffer") << GREEN << buf << RESET
                          << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string retr =
                    std::to_string(config.max_retries) + " (" + std::to_string(config.retry_delay_ms) + "ms)";
                std::string line = " " + TR().t("univ_config_retries") + retr;
                std::cout << BLUE << "│ " << RESET << TR().t("univ_config_retries") << GREEN << retr << RESET
                          << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string mmap_info = std::to_string(config.mmap_threshold / (1024 * 1024)) + "MB: " +
                                        (config.should_use_mmap(config.mmap_threshold) ? TR().t("univ_config_yes")
                                                                                       : TR().t("univ_config_no"));
                std::string line = " " +
                                   TR().t("univ_config_mmap", {std::to_string(config.mmap_threshold / (1024 * 1024))}) +
                                   mmap_info;
                std::cout << BLUE << "│ " << RESET
                          << TR().t("univ_config_mmap", {std::to_string(config.mmap_threshold / (1024 * 1024))})
                          << GREEN << mmap_info << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string line = " " + TR().t("univ_config_parallel") + std::to_string(config.max_parallel_files);
                std::cout << BLUE << "│ " << RESET << TR().t("univ_config_parallel") << GREEN
                          << config.max_parallel_files << RESET << pad_to(line, 68) << BLUE << "│\n";
            }
            {
                std::string hmac_v =
                    config.use_header_mac ? TR().t("univ_config_yes_full") : TR().t("univ_config_no_full");
                std::string line = " " + TR().t("univ_config_hmac") + hmac_v;
                std::cout << BLUE << "│ " << RESET << TR().t("univ_config_hmac") << GREEN << hmac_v << RESET
                          << pad_to(line, 68) << BLUE << "│\n";
            }
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
                      << std::endl;

            std::cout << BLUE << "├─────────────────────────────────────────────────────────────────────┤\n";
            menu_line("[1]", TR().t("univ_config_buf_max", {std::to_string(config.max_buffer_size / (1024 * 1024))}));
            menu_line("[2]", TR().t("univ_config_rate", {std::to_string(config.max_bytes_per_second / (1024 * 1024))}));
            menu_line("[3]",
                      TR().t("univ_config_hmac_toggle",
                             {config.use_header_mac ? TR().t("univ_config_yes_full") : TR().t("univ_config_no_full")}));
            menu_line("[4]", TR().t("univ_config_parallel_toggle", {std::to_string(config.max_parallel_files)}));
            menu_line("[5]", TR().t("univ_config_retries_toggle", {std::to_string(config.max_retries)}));
            menu_line("[6]", TR().t("univ_config_clear_counters"));
            menu_line("[0]", TR().t("univ_config_back"));
            std::cout << BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
                      << "\n";

            std::string prompt = std::string(BRIGHT_GREEN) + "\n" + TR().t("univ_config_prompt") + " " + RESET;
            std::string choice = getInput(prompt);

            if (choice == "0")
                break;
            else if (choice == "1") {
                std::string size = getInput(TR().t("univ_config_buf_prompt"));
                try {
                    size_t s = std::stoul(size);
                    if (s >= 2 && s <= 32) {
                        config.max_buffer_size = s * 1024 * 1024;
                        config.optimal_buffer_size = config.max_buffer_size / 2;
                    }
                } catch (...) {
                }
            } else if (choice == "2") {
                std::string mb = getInput(TR().t("univ_config_rate_prompt"));
                try {
                    size_t m = std::stoul(mb);
                    if (m >= 10 && m <= 1000) {
                        config.max_bytes_per_second = m * 1024 * 1024;
                    }
                } catch (...) {
                }
            } else if (choice == "3") {
                config.use_header_mac = !config.use_header_mac;
            } else if (choice == "4") {
                std::string num = getInput(TR().t("univ_config_parallel_prompt"));
                try {
                    size_t n = std::stoul(num);
                    if (n >= 1 && n <= 16) {
                        config.max_parallel_files = n;
                    }
                } catch (...) {
                }
            } else if (choice == "5") {
                std::string num = getInput(TR().t("univ_config_retries_prompt"));
                try {
                    size_t n = std::stoul(num);
                    if (n <= 5) {
                        config.max_retries = n;
                    }
                } catch (...) {
                }
            } else if (choice == "6") {
                std::string confirm = getInput(TR().t("univ_config_clear_prompt") + " ");
                if (confirm == "s" || confirm == "S") {
                    std::remove(config.counter_file_path.c_str());
                    std::remove(config.name_key_file_path.c_str());
                    std::cout << YELLOW << TR().t("univ_config_cleared") << RESET << std::endl;
                }
            }

            waitForEnter();
        }
    }
};

#endif // UI_UNIVERSAL_CIPHER_UI_H