// ui/rubic_core_ui.h - 0.1 alpha
#ifndef UI_RUBIC_CORE_UI_H
#define UI_RUBIC_CORE_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <limits>
#include <chrono>
#include <thread>
#include <csignal>
#include <unistd.h>
#include <termios.h>
#include <memory>

#include "../rubic_core.h"
#include "translator.h"

#include "key_manager_ui.h"
#include "share_manager_ui.h"
#include "universal_cipher_ui.h"
#include "unit_encryptor_ui.h"

#ifndef UI_RUBIC_CORE_COLORS_DEFINED
#define UI_RUBIC_CORE_COLORS_DEFINED
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

class PwdReader {
  private:
    inline static struct termios old_termios;
    inline static bool termios_saved = false;

    static void raw_mode(bool enable) {
        if (enable) {
            if (!termios_saved) {
                tcgetattr(STDIN_FILENO, &old_termios);
                termios_saved = true;
            }
            struct termios raw = old_termios;
            raw.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        } else if (termios_saved) {
            tcsetattr(STDIN_FILENO, TCSANOW, &old_termios);
        }
    }

  public:
    static Botan::secure_vector<uint8_t> readPassword(const string& prompt = "Contraseña: ") {
        raw_mode(true);
        Botan::secure_vector<uint8_t> pass;

        cout << prompt << flush;
        char c;
        while (::read(STDIN_FILENO, &c, 1) == 1) {
            if (c == '\n' || c == '\r') break;
            if (c == 127 || c == '\b') {
                if (!pass.empty()) {
                    pass.pop_back();
                    cout << "\b \b" << flush;
                }
                continue;
            }
            pass.push_back(static_cast<uint8_t>(c));
            cout << c << flush;
            this_thread::sleep_for(chrono::milliseconds(50));
            cout << "\b*" << flush;
        }

        raw_mode(false);
        cout << endl;
        return pass;
    }

    static Botan::secure_vector<uint8_t> readWithConfirm() {
        for (int i = 0; i < 3; i++) {
            auto p1 = readPassword(TR().t("chpwd_new"));
            if (p1.size() < 8) {
                cout << RED << TR().t("register_pw_too_short") << RESET << endl;
                secure_c_container(p1);
                continue;
            }

            auto p2 = readPassword(TR().t("chpwd_confirm"));
            if (secure_compare(p1, p2)) {
                secure_c_container(p2);
                return p1;
            }

            cout << RED << TR().t("register_pw_mismatch", {std::to_string(i + 1)}) << RESET << endl;
            secure_c_container(p1);
            secure_c_container(p2);
        }
        return {};
    }
};

class RubicCoreUI {
  private:
    UserMgr& core_;

    std::unique_ptr<KeyManagerUI> key_mgr_ui;
    std::unique_ptr<ShareManagerUI> share_mgr_ui;
    std::unique_ptr<UniversalCipherUI> univ_ciph_ui;
    std::unique_ptr<UnitEncryptorUI> unit_enc_ui;

    inline static RubicCoreUI* instance = nullptr;

    static void signalHandler(int signal) {
        if (instance) instance->core_.shutdown();
        exit(signal);
    }

    static void setupSignalHandlers() {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGHUP, signalHandler);
        signal(SIGQUIT, signalHandler);
    }

    string getInput(const string& prompt) {
        cout << prompt;
        string input;
        getline(cin, input);
        return input;
    }

    void menu_line(const std::string& marker, const std::string& label) {
        std::string plain = marker + " " + label;
        std::cout << BRIGHT_BLUE << "│" << BRIGHT_GREEN << marker << BRIGHT_MAGENTA << " " << label << pad_to(plain, 69)
                  << BRIGHT_BLUE << "│" << RESET << "\n";
    }

    void title_line(const std::string& title, const std::string& color) {
        std::cout << BRIGHT_BLUE << "│ " << color << title << pad_to(" " + title, 69) << BRIGHT_BLUE << "│" << RESET << "\n";
    }

    void printBanner() {
        const std::string B = BRIGHT_BLUE;
        const std::string G = BRIGHT_GREEN;
        const std::string MG = BRIGHT_MAGENTA;
        const std::string R = RESET;
        const size_t W = 69;

        auto line = [&](const std::string& plain, const std::string& color) {
            std::cout << B << "│" << color << plain;
            size_t w = utf8_width(plain);
            if (w < W) std::cout << std::string(W - w, ' ');
            std::cout << R << B << "│" << R << "\n";
        };

        std::cout << B << "┌─────────────────────────────────────────────────────────────────────┐" << R << "\n";
        line("    ██████╗ ██╗   ██╗██████╗ ██╗ ██████╗", G);
        line("    ██╔══██╗██║   ██║██╔══██╗██║██╔════╝", G);
        line("    ██████╔╝██║   ██║██████╔╝██║██║     ", G);
        line("    ██╔══██╗██║   ██║██╔══██╗██║██║     ", G);
        line("    ██║  ██║╚██████╔╝██████╔╝██║╚██████╗", G);
        line("    ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝ ╚═════╝", G);
        line("", B);
        line("    v0.1", MG);
        std::cout << B << "└─────────────────────────────────────────────────────────────────────┘" << R << "\n";
    }

    void init_ui_modules() {
        if (core_.getKeyManager() && !key_mgr_ui) {
            key_mgr_ui = std::make_unique<KeyManagerUI>(*core_.getKeyManager());
            share_mgr_ui = std::make_unique<ShareManagerUI>(*core_.getShareManager());
            univ_ciph_ui = std::make_unique<UniversalCipherUI>(*core_.getUniversalCipher(), core_.getKeyManager());
            unit_enc_ui = std::make_unique<UnitEncryptorUI>(*core_.getUnitEncryptor(), core_.getKeyManager());
        }
    }

    void cleanup_ui_modules() {
        key_mgr_ui.reset();
        share_mgr_ui.reset();
        univ_ciph_ui.reset();
        unit_enc_ui.reset();
    }

    void showUserInfo() {
        auto info = core_.getUserInfo();
        if (info.username.empty()) {
            cout << RED << TR().t("userinfo_load_error") << RESET << endl;
            return;
        }

        std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        std::cout << "│ " << BRIGHT_GREEN << TR().t("userinfo_title") << BRIGHT_BLUE;
        std::cout << pad_to(" " + TR().t("userinfo_title"), 69) << "│\n";
        std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";

        {
            std::string line = TR().t("userinfo_user") + info.username;
            std::cout << "│ " << TR().t("userinfo_user") << BRIGHT_MAGENTA << info.username << RESET
                      << pad_to(" " + line, 69) << BRIGHT_BLUE << "│\n";
        }
        {
            std::string line = TR().t("userinfo_algo") + info.algo;
            std::cout << "│ " << TR().t("userinfo_algo") << BRIGHT_CYAN << info.algo << RESET << pad_to(" " + line, 69)
                      << BRIGHT_BLUE << "│\n";
        }

        char buf[30];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M", localtime(&info.created));
        std::string line_created = TR().t("userinfo_created") + buf;
        std::cout << "│ " << TR().t("userinfo_created") << buf << pad_to(" " + line_created, 69) << BRIGHT_BLUE << "│\n";

        {
            std::string state_str = info.has_id ? TR().t("userinfo_identity_active") : TR().t("userinfo_identity_pending");
            std::string plain = " " + TR().t("userinfo_identity") + state_str;
            std::cout << "│ " << TR().t("userinfo_identity") << (info.has_id ? BRIGHT_GREEN : BRIGHT_RED) << state_str
                      << RESET << pad_to(plain, 69) << BRIGHT_BLUE << "│\n";
        }

        if (info.has_id && !info.id_fprint.empty()) {
            std::string line = TR().t("userinfo_fingerprint") + info.id_fprint;
            std::cout << "│ " << TR().t("userinfo_fingerprint") << BRIGHT_GREEN << info.id_fprint << RESET
                      << pad_to(" " + line, 69) << BRIGHT_BLUE << "│\n";
        }
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }

    void changePassword() {
        std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        std::cout << "│ " << BRIGHT_GREEN << TR().t("chpwd_title") << BRIGHT_BLUE;
        std::cout << pad_to(" " + TR().t("chpwd_title"), 69) << "│\n";
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        auto current = PwdReader::readPassword(TR().t("chpwd_current"));
        auto new_pass = PwdReader::readWithConfirm();
        if (new_pass.empty()) {
            secure_c_container(current);
            return;
        }

        string error;
        bool ok = core_.changePassword(current, new_pass, error);

        if (ok) {
            cout << GREEN << "\n" << TR().t("chpwd_ok") << RESET << endl;
        } else {
            cout << RED << "\n" << TR().t("chpwd_fail", {error}) << RESET << endl;
        }

        secure_c_container(current);
        secure_c_container(new_pass);
    }

    void generateIdentity() {
        std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        std::cout << "│ " << BRIGHT_GREEN << TR().t("ident_title") << BRIGHT_BLUE;
        std::cout << pad_to(" " + TR().t("ident_title"), 69) << "│\n";
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        cout << MAGENTA << "\n" << TR().t("ident_generating") << RESET << endl;

        string fingerprint, error;
        if (core_.generateIdentity(fingerprint, error)) {
            cout << GREEN << "\n" << TR().t("ident_ok") << RESET << endl;
            cout << GREEN << "  " << TR().t("ident_fingerprint") << BRIGHT_CYAN << fingerprint << RESET << endl;
        } else {
            cout << RED << "\n" << TR().t("ident_fail", {error}) << RESET << endl;
        }
    }

    void showConfigMenu() {
        while (true) {
            std::string cur_lang = TR().currentLang();

            std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            title_line(TR().t("config_title"), BRIGHT_GREEN);
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";

            menu_line("[1]", TR().t("config_change_pwd"));
            menu_line("[2]", TR().t("config_user_info"));
            menu_line("[3]", TR().t("config_gen_identity"));

            {
                std::string word = TR().t("config_lang_word");
                std::string plain = "[4] " + word + " (" + cur_lang + ")";
                std::cout << "│ " << BRIGHT_GREEN << "[4]" << BRIGHT_MAGENTA << " " << word << " (" << BRIGHT_CYAN
                          << cur_lang << BRIGHT_MAGENTA << ")" << pad_to(" " + plain, 69) << BRIGHT_BLUE << "│" << RESET
                          << "\n";
            }

            menu_line("[5]", TR().t("config_back"));

            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

            string opt = getInput(BRIGHT_GREEN + TR().t("config_prompt") + RESET);

            if (opt == "1") changePassword();
            else if (opt == "2") showUserInfo();
            else if (opt == "3") generateIdentity();
            else if (opt == "4") {
                auto langs = TR().availableLangs();
                if (langs.empty()) {
                    std::cout << RED << "\n" << TR().t("config_lang_none") << RESET << "\n";
                } else {
                    std::cout << "\n" << BRIGHT_MAGENTA << TR().t("config_lang_title") << RESET << "\n";
                    for (size_t i = 0; i < langs.size(); ++i) {
                        std::cout << "  [" << BRIGHT_GREEN << (i + 1) << RESET << "] " 
                                  << BRIGHT_CYAN << TR().getNativeLanguageName(langs[i]) << RESET;
                        if (langs[i] == TR().currentLang())
                            std::cout << " " << BRIGHT_YELLOW << TR().t("config_lang_current") << RESET;
                        std::cout << "\n";
                    }
                    string sel = getInput("\n" + TR().t("config_lang_select") + " ");
                    try {
                        int idx = stoi(sel) - 1;
                        if (idx >= 0 && idx < (int)langs.size()) {
                            if (core_.setPreferredLang(langs[idx])) {
                                TR().load(langs[idx]);
                                std::cout << GREEN << "\n"
                                          << TR().t("config_lang_changed", {TR().getNativeLanguageName(langs[idx])}) << RESET << "\n";
                            } else {
                                std::cout << RED << "\n" << TR().t("config_lang_save_fail") << RESET << "\n";
                            }
                        }
                    } catch (...) {}
                }
            } else if (opt == "5") break;
        }
    }

    bool doLogin() {
        std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        std::cout << "│ " << BRIGHT_GREEN << TR().t("login_title") << BRIGHT_BLUE;
        std::cout << pad_to(" " + TR().t("login_title"), 69) << "│\n";
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        string user = getInput(TR().t("login_user_prompt"));
        auto pass = PwdReader::readPassword(TR().t("login_password_prompt"));

        auto result = core_.authenticate(user, pass);
        secure_c_container(pass);

        if (result.throttled) {
            cout << RED << TR().t("login_throttled", {std::to_string(result.seconds_left)}) << RESET << endl;
            return false;
        }

        if (!result.ok) {
            cout << RED << "✗ " << TR().t("login_fail") << RESET << endl;
            return false;
        }

        std::string lang = result.preferred_lang.empty() ? Translator::detectSystemLanguage() : result.preferred_lang;
        if (!TR().load(lang)) TR().load("en");
        
        init_ui_modules();

        cout << GREEN << "\n" << TR().t("login_ok", {user}) << RESET << endl;
        return true;
    }

    bool doRegister() {
        std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        std::cout << "│ " << BRIGHT_GREEN << TR().t("register_title") << BRIGHT_BLUE;
        std::cout << pad_to(" " + TR().t("register_title"), 69) << "│\n";
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        string user = getInput(TR().t("register_user_prompt"));

        auto pass = PwdReader::readWithConfirm();
        if (pass.empty()) return false;

        cout << MAGENTA << "\n" << TR().t("register_argon") << RESET << endl;

        auto result = core_.createAccount(user, pass);
        secure_c_container(pass);

        if (!result.ok) {
            cout << RED << "✗ " << result.error << RESET << endl;
            return false;
        }

        if (result.id_generated) {
            cout << MAGENTA << "\n" << TR().t("register_id_generating") << RESET << endl;
            cout << GREEN << TR().t("register_id_generated") << RESET << endl;
            cout << CYAN << "  " << TR().t("ident_fingerprint") << BRIGHT_GREEN << result.id_fingerprint << RESET << endl;
        } else {
            cout << YELLOW << TR().t("register_id_fail") << RESET << endl;
            cout << YELLOW << TR().t("register_id_fail_hint") << RESET << endl;
        }

        std::string lang = result.preferred_lang.empty() ? Translator::detectSystemLanguage() : result.preferred_lang;
        if (!TR().load(lang)) TR().load("en");
        
        init_ui_modules();

        cout << GREEN << "\n" << TR().t("register_ok") << RESET << endl;
        cout << GREEN << TR().t("register_identity_linked") << RESET << endl;
        return true;
    }

    enum class MainAction { Continue, Logout, Exit };

    MainAction showMainMenu() {
        printBanner();

        string user = core_.getCurrentUser();

        std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
        {
            std::string title = TR().t("main_menu_title", {user});
            std::cout << "│ " << BRIGHT_MAGENTA << title << pad_to(" " + title, 69) << BRIGHT_BLUE << "│\n";
        }
        std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        {
            std::string hdr = TR().t("main_menu_tools");
            std::cout << "│" << BRIGHT_CYAN << hdr << pad_to(hdr, 69) << BRIGHT_BLUE << "│\n";
        }
        menu_line("[1]", TR().t("main_menu_encrypt_unit"));
        menu_line("[2]", TR().t("main_menu_universal"));
        {
            std::string hdr = TR().t("main_menu_security");
            std::cout << "│" << BRIGHT_CYAN << hdr << pad_to(hdr, 69) << BRIGHT_BLUE << "│\n";
        }
        menu_line("[3]", TR().t("main_menu_keys"));
        {
            std::string hdr = TR().t("main_menu_share");
            std::cout << "│" << BRIGHT_CYAN << hdr << pad_to(hdr, 69) << BRIGHT_BLUE << "│\n";
        }
        menu_line("[4]", TR().t("main_menu_share_files"));
        {
            std::string hdr = TR().t("main_menu_admin");
            std::cout << "│" << BRIGHT_CYAN << hdr << pad_to(hdr, 69) << BRIGHT_BLUE << "│\n";
        }
        menu_line("[5]", TR().t("main_menu_config"));
        menu_line("[6]", TR().t("main_menu_logout"));
        menu_line("[0]", TR().t("main_menu_exit"));
        std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        string opt = getInput(BRIGHT_GREEN + TR().t("main_menu_prompt") + RESET);

        if (opt == "1") {
            if (unit_enc_ui) unit_enc_ui->showMenu();
        } else if (opt == "2") {
            if (univ_ciph_ui) univ_ciph_ui->showMenu();
        } else if (opt == "3") {
            if (key_mgr_ui) key_mgr_ui->showMenu();
        } else if (opt == "4") {
            if (share_mgr_ui) share_mgr_ui->showMenu();
        } else if (opt == "5") {
            showConfigMenu();
        } else if (opt == "6") {
            cout << MAGENTA << "\n" << TR().t("logout_msg") << RESET << endl;
            return MainAction::Logout;
        } else if (opt == "0") {
            cout << MAGENTA << "\n" << TR().t("exit_msg") << RESET << endl;
            return MainAction::Exit;
        }

        return MainAction::Continue;
    }

  public:
    explicit RubicCoreUI(UserMgr& core) : core_(core) {
        instance = this;
        setupSignalHandlers();
    }

    ~RubicCoreUI() {
        instance = nullptr;
    }

    void run() {
        while (true) {
            printBanner();

            std::cout << BRIGHT_BLUE << "\n┌─────────────────────────────────────────────────────────────────────┐\n";
            {
                std::string t = TR().t("access_system");
                std::cout << "│ " << BRIGHT_GREEN << t << pad_to(" " + t, 69) << BRIGHT_BLUE << "│\n";
            }
            std::cout << "├─────────────────────────────────────────────────────────────────────┤\n";
            menu_line("[1]", TR().t("login_title"));
            menu_line("[2]", TR().t("register_title"));
            {
                std::string t = TR().t("menu_exit_short");
                std::cout << "│" << BRIGHT_GREEN << "[3]" << BRIGHT_MAGENTA << " " << t << pad_to("[3] " + t, 69)
                          << BRIGHT_BLUE << "│" << RESET << "\n";
            }
            std::cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

            string opt = getInput(BRIGHT_GREEN + TR().t("access_prompt") + RESET);

            bool logged_in = false;
            if (opt == "1") {
                logged_in = doLogin();
            } else if (opt == "2") {
                logged_in = doRegister();
            } else if (opt == "3") {
                cout << MAGENTA << "\n" << TR().t("exit_msg") << RESET << endl;
                core_.shutdown();
                return;
            }

            if (!logged_in) continue;

            while (core_.isAuthenticated()) {
                auto action = showMainMenu();
                if (action == MainAction::Exit) {
                    // FIX VALGRIND: Destruir las UIs antes que el Core
                    cleanup_ui_modules();
                    core_.shutdown();
                    return;
                } else if (action == MainAction::Logout) {
                    // FIX VALGRIND: Destruir las UIs antes que el Core
                    cleanup_ui_modules();
                    core_.logout();
                    break;
                }
            }
        }
    }
};

#endif // UI_RUBIC_CORE_UI_H