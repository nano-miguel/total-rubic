// ui/share_manager_ui.h - 0.1 alpha
// Toda la UI del gestor de compartir archivos: menús, prompts, TOFU, colores.
// La lógica vive en share/share_manager.h

#ifndef UI_SHARE_MANAGER_UI_H
#define UI_SHARE_MANAGER_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <memory>
#include <limits>
#include <algorithm>
#include <csignal>
#include <unistd.h>
#include <termios.h>
#include <filesystem>

#include "../share/share_manager.h"
#include "translator.h"

// ============================================
// COLORES (propios, con guard)
// ============================================
#ifndef UI_SHARE_COLORS_DEFINED
#define UI_SHARE_COLORS_DEFINED
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

// *******************************************
// SHARE MANAGER UI - CLASE PRINCIPAL

class ShareManagerUI {
  private:
    ShareManager& core_;

    inline static ShareManagerUI* instance = nullptr;

    static void signalHandler(int signal) {
        if (instance) {
            instance->core_.stopReceiving();
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
        std::getline(std::cin, input);
        return input;
    }

    void waitForEnter() {
        std::cout << "\n" << YELLOW << TR().t("press_enter") << RESET;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::string dummy;
        std::getline(std::cin, dummy);
    }

    // Línea de menú con padding real (utf8_width)
    void menu_line(const std::string& marker, const std::string& label) {
        std::string plain = " " + marker + " " + label;
        std::cout << BRIGHT_BLUE << "│" << BRIGHT_GREEN << " " << marker << " " << BRIGHT_MAGENTA << label
                  << pad_to(plain, 68) << BRIGHT_BLUE << "│" << RESET << "\n";
    }

    // ============================================================
    // Traducción de eventos estructurados
    // ============================================================
    void onCoreLog(share_log::LogLevel level, share_log::LogEvent event, const std::string& data) {
        (void)level;
        switch (event) {
        // Conexión
        case share_log::LogEvent::Connecting:
            std::cout << TR().t("log_share_connecting", {data}) << std::endl;
            break;
        case share_log::LogEvent::ConnectFailed:
            std::cout << RED << TR().t("log_share_connect_failed", {data}) << RESET << std::endl;
            break;
        case share_log::LogEvent::ExchangeKeysFailed:
            std::cout << RED << TR().t("log_share_exchange_failed", {data}) << RESET << std::endl;
            break;
        case share_log::LogEvent::MitmDetected:
            std::cout << BRIGHT_RED << BOLD << "\n"
                      << TR().t("mitm_title") << "\n"
                      << TR().t("mitm_detail", {data}) << "\n"
                      << TR().t("mitm_abort") << "\n"
                      << RESET << std::endl;
            break;
        case share_log::LogEvent::SessionEstablished:
            std::cout << GREEN << TR().t("log_share_session_established", {data}) << RESET << std::endl;
            break;

        // Recepción
        case share_log::LogEvent::ReceivingFrom:
            std::cout << MAGENTA << TR().t("log_share_receiving_from", {data}) << RESET << std::endl;
            break;
        case share_log::LogEvent::ServerStartFailed:
            std::cout << RED << TR().t("log_share_server_start_failed") << RESET << std::endl;
            break;
        case share_log::LogEvent::KyberGenFailed:
            std::cout << RED << TR().t("log_share_kyber_gen_failed") << RESET << std::endl;
            break;
        case share_log::LogEvent::ServerStarted:
            std::cout << GREEN << TR().t("log_share_server_started") << RESET << std::endl;
            break;
        case share_log::LogEvent::ServerStopped:
            std::cout << GREEN << TR().t("log_share_server_stopped") << RESET << std::endl;
            break;

        // Envío
        case share_log::LogEvent::NoFilesToSend:
            std::cout << YELLOW << TR().t("log_share_no_files") << RESET << std::endl;
            break;
        case share_log::LogEvent::SendingFiles:
            std::cout << MAGENTA << TR().t("log_share_sending_files", {data}) << RESET << std::endl;
            break;
        case share_log::LogEvent::SendComplete:
            std::cout << GREEN << TR().t("log_share_send_complete", {data}) << RESET << std::endl;
            break;
        case share_log::LogEvent::SendFailed:
            std::cout << RED << TR().t("log_share_send_failed", {data}) << RESET << std::endl;
            break;

        // Identidad
        case share_log::LogEvent::IdentityLoadError:
            std::cout << RED << TR().t("log_share_identity_load_error") << RESET << std::endl;
            break;

        // TOFU
        case share_log::LogEvent::TrustPromptShown:
            // El prompt real lo maneja askTrust()
            break;
        case share_log::LogEvent::TrustAccepted:
            std::cout << GREEN << TR().t("log_share_trust_accepted", {data}) << RESET << std::endl;
            break;
        case share_log::LogEvent::TrustRejected:
            std::cout << RED << TR().t("log_share_trust_rejected", {data}) << RESET << std::endl;
            break;
        }
    }

    // ============================================================
    // Callbacks
    // ============================================================

    bool askTrust(const std::string& rem_user, const std::string& fprint, bool is_srv) {
        std::cout << BRIGHT_YELLOW << "\n\n" << TR().t("tofu_title") << RESET << std::endl;
        if (is_srv) {
            std::cout << TR().t("tofu_new_incoming") << std::endl;
        } else {
            std::cout << TR().t("tofu_new_outgoing") << std::endl;
        }

        {
            std::string line = TR().t("tofu_user") + rem_user;
            std::cout << TR().t("tofu_user") << BRIGHT_MAGENTA << rem_user << RESET << std::endl;
        }
        {
            std::string line = TR().t("tofu_fingerprint") + fprint;
            std::cout << TR().t("tofu_fingerprint") << BRIGHT_CYAN << fprint << RESET << std::endl;
        }
        std::cout << TR().t("tofu_prompt");

        std::string ans;
        std::getline(std::cin, ans);
        if (ans == "s" || ans == "S" || ans == "y" || ans == "Y") {
            std::cout << GREEN << TR().t("tofu_accepted") << RESET << "\n\n";
            return true;
        }
        std::cout << RED << TR().t("tofu_rejected") << RESET << "\n\n";
        return false;
    }

    void onNewSession(const std::string& rem_user, const std::string& rem_ip) {
        std::cout << GREEN << "\n"
                  << TR().t("log_share_session_established", {rem_user + " (" + rem_ip + ")"}) << RESET << std::endl;
    }

    void onFileRecv(const std::string& filename, size_t bytes, bool ok) {
        if (ok) {
            std::cout << GREEN << "  ✓ " << filename << " (" << (bytes / 1024.0 / 1024.0) << " MB)" << RESET
                      << std::endl;
        } else {
            std::cout << RED << "  ✗ " << filename << RESET << std::endl;
        }
    }

    void onFileSend(const std::string& filename, size_t current, size_t total, bool ok) {
        std::string short_name = std::filesystem::path(filename).filename().string();
        if (!ok && current == 0) {
            std::cout << "  [" << current << "/" << total << "] " << short_name << " " << std::flush;
        } else {
            if (ok)
                std::cout << GREEN << "✓" << RESET << std::endl;
            else
                std::cout << RED << "✗" << RESET << std::endl;
        }
    }

    // ============================================================
    // Submenús
    // ============================================================

    void manageTrust() {
        std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
        std::cout << "│      " << BRIGHT_GREEN << TR().t("share_trust_title") << BRIGHT_BLUE << "         │\n";
        std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";

        auto fps = core_.getTrustedFingerprints();

        if (fps.empty()) {
            std::cout << YELLOW << "  " << TR().t("share_trust_empty") << RESET << std::endl;
        } else {
            int i = 1;
            for (const auto& fp : fps) {
                std::cout << "  " << i++ << ". " << BRIGHT_CYAN << fp << RESET << std::endl;
            }
        }

        std::string add = getInput("\n" + TR().t("share_trust_add_prompt") + " ");
        if (add == "s" || add == "S" || add == "y" || add == "Y") {
            std::string fp = getInput(TR().t("share_trust_fp_prompt"));
            if (!fp.empty()) {
                if (core_.addTrustedFingerprint(fp)) {
                    std::cout << GREEN << " " << TR().t("share_trust_saved") << RESET << std::endl;
                } else {
                    std::cout << RED << TR().t("share_trust_save_fail") << RESET << std::endl;
                }
            }
        }
    }

    void cfgNet() {
        {
            std::string line = TR().t("share_net_current_ip") + core_.getCurrentIP();
            std::cout << "\n  " << TR().t("share_net_current_ip") << BRIGHT_YELLOW << core_.getCurrentIP() << RESET
                      << "\n";
        }
        {
            std::string line = TR().t("share_net_kem_port") + std::to_string(core_.getKemPort());
            std::cout << "  " << TR().t("share_net_kem_port") << BRIGHT_YELLOW << core_.getKemPort() << RESET << "\n";
        }
        {
            std::string line = TR().t("share_net_xfer_port") + std::to_string(core_.getXferPort());
            std::cout << "  " << TR().t("share_net_xfer_port") << BRIGHT_YELLOW << core_.getXferPort() << RESET << "\n";
        }

        std::string ans = getInput("\n" + TR().t("share_net_change_prompt") + " ");
        if (ans == "s" || ans == "S" || ans == "y" || ans == "Y") {
            std::string p1 = getInput(TR().t("share_net_kem_new"));
            std::string p2 = getInput(TR().t("share_net_xfer_new"));
            try {
                if (!p1.empty())
                    core_.setKemPort(std::stoi(p1));
                if (!p2.empty())
                    core_.setXferPort(std::stoi(p2));
                std::cout << GREEN << TR().t("share_net_updated") << RESET << std::endl;
            } catch (...) {
                std::cout << RED << TR().t("share_net_invalid") << RESET << std::endl;
            }
        }
    }

    void sendFiles() {
        std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
        std::cout << "│         " << BRIGHT_GREEN << TR().t("share_send_title") << BRIGHT_BLUE
                  << "                    │\n";
        std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";

        std::cout << YELLOW << TR().t("share_send_format", {std::to_string(core_.getKemPort())}) << RESET << "\n";
        std::string addr = getInput(TR().t("share_send_addr_prompt"));
        if (addr.empty())
            return;

        std::string rem_addr;
        int rem_port;
        if (!ShareManager::parseAddress(addr, rem_addr, rem_port)) {
            std::cout << RED << TR().t("share_send_addr_invalid") << RESET << std::endl;
            return;
        }

        std::string path = getInput(TR().t("share_send_path_prompt"));
        if (path.empty())
            return;
        if (path.front() == '"' && path.back() == '"')
            path = path.substr(1, path.size() - 2);

        std::vector<std::string> files = ShareManager::expandFiles(path);
        if (files.empty()) {
            std::cout << RED << TR().t("share_send_no_files") << RESET << std::endl;
            return;
        }

        size_t total = 0;
        for (const auto& f : files) {
            struct stat st;
            if (stat(f.c_str(), &st) == 0)
                total += st.st_size;
        }
        std::cout << "  "
                  << TR().t("share_send_files_info",
                            {std::to_string(files.size()), std::to_string(total / 1024 / 1024)})
                  << "\n";

        std::string conf = getInput(YELLOW + TR().t("share_send_confirm") + " " + RESET);
        if (conf != "s" && conf != "S" && conf != "y" && conf != "Y")
            return;

        std::cout << MAGENTA << "\n"
                  << TR().t("share_send_sending", {std::to_string(files.size())}) << RESET << std::endl;

        bool ok = core_.sendFiles(files, rem_addr, rem_port);

        if (ok) {
            std::cout << GREEN << "\n" << TR().t("share_send_ok") << RESET << std::endl;
        } else {
            std::cout << RED << "\n" << TR().t("share_send_fail") << RESET << std::endl;
        }

        getInput("\n" + TR().t("share_send_enter"));
    }

    void recvFiles() {
        std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
        std::cout << "│        " << BRIGHT_GREEN << TR().t("share_recv_title") << BRIGHT_BLUE
                  << "                     │\n";
        std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";

        if (!core_.startReceiving()) {
            std::cout << RED << TR().t("share_recv_start_fail") << RESET << std::endl;
            getInput("");
            return;
        }

        std::string ip = core_.getCurrentIP();
        std::cout << GREEN << TR().t("share_recv_waiting", {ip, std::to_string(core_.getKemPort())}) << RESET << "\n";
        if (core_.hasIdentity()) {
            std::cout << GREEN << TR().t("share_recv_your_id") << BRIGHT_CYAN << core_.getFingerprint() << RESET
                      << "\n";
        }
        std::cout << "  " << TR().t("share_recv_folder") << BRIGHT_CYAN << core_.getRecvDir() << RESET << "\n";
        std::cout << BRIGHT_RED << "\n" << TR().t("share_recv_stop_hint") << RESET << std::endl;

        std::string wait;
        while (core_.isReceiving()) {
            std::getline(std::cin, wait);
            if (wait == "q" || wait == "Q" || wait == "salir" || wait == "quit" || wait == "exit") {
                break;
            }
        }

        core_.stopReceiving();
        std::cout << GREEN << "\n" << TR().t("share_recv_stopped") << RESET << std::endl;
        getInput("\n" + TR().t("share_recv_enter"));
    }

  public:
    ShareManagerUI(ShareManager& core) : core_(core) {
        instance = this;
        setupSignalHandlers();

        core_.setLogCallback([this](share_log::LogLevel level, share_log::LogEvent event, const std::string& data) {
            this->onCoreLog(level, event, data);
        });
        core_.setTrustPromptCallback(
            [this](const std::string& u, const std::string& fp, bool srv) { return this->askTrust(u, fp, srv); });
        core_.setSessionCallback([this](const std::string& u, const std::string& ip) { this->onNewSession(u, ip); });
        core_.setFileRecvCallback([this](const std::string& f, size_t b, bool ok) { this->onFileRecv(f, b, ok); });
        core_.setFileSendCallback(
            [this](const std::string& f, size_t c, size_t t, bool ok) { this->onFileSend(f, c, t, ok); });
    }

    ~ShareManagerUI() {
        core_.stopReceiving();
        instance = nullptr;
    }

    // ============================================================
    // MENÚ PRINCIPAL
    // ============================================================
    void showMenu() {
        while (true) {
            std::cout << BRIGHT_BLUE << "\n┌──────────────────────────────────────────┐\n";
            std::cout << "│     " << BRIGHT_GREEN << TR().t("share_title") << BRIGHT_BLUE
                      << pad_to("     " + TR().t("share_title"), 41) << "│\n";
            std::cout << "├──────────────────────────────────────────┤\n";

            if (core_.hasIdentity()) {
                std::string fp = core_.getFingerprint();
                if (fp.length() > 16)
                    fp = fp.substr(0, 16);
                std::string line = " ID: " + fp;
                std::cout << "│" << BRIGHT_CYAN << " ID: " << fp << RESET << BRIGHT_BLUE << pad_to(line, 42) << "│\n";
            }

            menu_line_short("[1]", TR().t("share_send"));
            menu_line_short("[2]", TR().t("share_recv"));
            menu_line_short("[3]", TR().t("share_trust"));
            menu_line_short("[4]", TR().t("share_net"));
            menu_line_short("[5]", TR().t("share_back"));
            std::cout << "└──────────────────────────────────────────┘" << RESET << "\n";

            std::string opt = getInput(BRIGHT_GREEN + TR().t("share_prompt") + RESET);

            if (opt == "1")
                sendFiles();
            else if (opt == "2")
                recvFiles();
            else if (opt == "3")
                manageTrust();
            else if (opt == "4")
                cfgNet();
            else if (opt == "5")
                break;
        }
    }

  private:
    // Menú corto (caja de 42 columnas del share, no 69)
    void menu_line_short(const std::string& marker, const std::string& label) {
        std::string plain = "  " + marker + " " + label;
        std::cout << BRIGHT_BLUE << "│" << BRIGHT_GREEN << "  " << marker << " " << BRIGHT_MAGENTA << label
                  << pad_to(plain, 41) << BRIGHT_BLUE << "│" << RESET << "\n";
    }
};

#endif // UI_SHARE_MANAGER_UI_H