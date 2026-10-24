// ui/key_manager_ui.h - 0.1 alpha

#ifndef UI_KEY_MANAGER_UI_H
#define UI_KEY_MANAGER_UI_H

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <memory>
#include <termios.h>
#include <unistd.h>
#include <limits>
#include <csignal>
#include <cstdlib>
#include <algorithm>

#include "../keygest/key_manager.h"
#include "translator.h"

/*colores*/
#ifndef UI_KEYMGR_COLORS_DEFINED
#define UI_KEYMGR_COLORS_DEFINED
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

// ============================================
// INPUT SEGURO
// ============================================
class KeySecureInput {
  private:
    static void setRawMode(bool enable) {
        static struct termios oldt;
        static bool initialized = false;
        struct termios tty;

        if (enable) {
            if (!initialized) {
                tcgetattr(STDIN_FILENO, &oldt);
                initialized = true;
            }
            tty = oldt;
            tty.c_lflag &= ~(ICANON | ECHO);
            tcsetattr(STDIN_FILENO, TCSANOW, &tty);
        } else {
            if (initialized) {
                tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            }
        }
    }

  public:
    static Botan::secure_vector<uint8_t> readAccessCode(const string& prompt = "Clave de acceso: ",
                                                        const string& prefix = "") {
        setRawMode(true);
        Botan::secure_vector<uint8_t> code;
        char c;
        const int SHOW_TIME_MS = 50;

        cout << "\r" << prefix << prompt << flush;

        while (true) {
            ssize_t result = read(STDIN_FILENO, &c, 1);
            if (result != 1)
                break;
            if (c == '\n' || c == '\r')
                break;

            if (c == 127 || c == '\b') {
                if (!code.empty()) {
                    code.pop_back();
                    cout << "\r" << prefix << prompt << string(code.size(), '*') << "\033[K" << flush;
                }
                continue;
            }

            cout << c << flush;
            this_thread::sleep_for(chrono::milliseconds(SHOW_TIME_MS));

            code.push_back(static_cast<uint8_t>(c));
            cout << "\r" << prefix << prompt << string(code.size(), '*') << "\033[K" << flush;
        }

        setRawMode(false);
        cout << "\n";
        return code;
    }

    static Botan::secure_vector<uint8_t>
    readAccessCodeWithConfirm(const string& prompt = "Clave de acceso: ",
                              const string& confirmPrompt = "Confirmar clave de acceso: ",
                              const string& prefix = "") {
        Botan::secure_vector<uint8_t> code1, code2;
        int attempts = 0;
        const int MAX_ATTEMPTS = 3;

        while (attempts < MAX_ATTEMPTS) {
            code1 = readAccessCode(prompt, prefix);

            if (code1.empty()) {
                cout << RED << "✗ " << TR().t("err_key_pwd_empty") << RESET << endl;
                attempts++;
                continue;
            }

            if (code1.size() < 4) {
                cout << RED << "✗ " << TR().t("err_key_pwd_short") << RESET << endl;
                code1.clear();
                attempts++;
                continue;
            }

            code2 = readAccessCode(confirmPrompt, prefix);

            bool match = (code1.size() == code2.size() && secure_memcmp(code1.data(), code2.data(), code1.size()));

            if (match) {
                code2.clear();
                return code1;
            } else {
                cout << RED << "✗ "
                     << TR().t("err_key_pwd_mismatch", {std::to_string(attempts + 1), std::to_string(MAX_ATTEMPTS)})
                     << RESET << endl;
                code1.clear();
                code2.clear();
                attempts++;
            }
        }

        cout << RED << "✗ " << TR().t("err_key_pwd_max_attempts") << RESET << endl;
        return Botan::secure_vector<uint8_t>();
    }

    static string readStringNormal(const string& prompt, const string& prefix = "") {
        cout << prefix << prompt;
        string input;
        if (!std::getline(cin, input)) {
            exit(0);
        }
        return input;
    }
};

// ============================================
// CLASE PRINCIPAL KeyManagerUI
// ============================================

class KeyManagerUI {
  private:
    KeyManager& core_;

    void onCoreLog(key_log::LogLevel level, key_log::LogEvent event, const std::string& data) {
        (void)level;
        switch (event) {
        case key_log::LogEvent::UsersDirCreateFailed:
            cout << RED << TR().t("log_keymgr_usersdir_fail") << RESET << endl;
            break;
        case key_log::LogEvent::KeysFileCreateFailed:
            cout << RED << TR().t("log_keymgr_file_create_fail");
            if (!data.empty())
                cout << ": " << data;
            cout << RESET << endl;
            break;
        case key_log::LogEvent::KeysFileOpenFailed:
            cout << RED << TR().t("log_keymgr_file_open_fail");
            if (!data.empty())
                cout << ": " << data;
            cout << RESET << endl;
            break;
        case key_log::LogEvent::UserPasswordNotSet:
            cout << RED << TR().t("log_keymgr_pwd_not_set") << RESET << endl;
            break;
        case key_log::LogEvent::EncryptKeysFailed:
            cout << RED << TR().t("log_keymgr_encrypt_fail") << RESET << endl;
            break;
        case key_log::LogEvent::KeysDecryptFailed:
            cout << RED << TR().t("log_keymgr_decrypt_fail") << RESET << endl;
            break;
        }
    }

    bool verifyUserPasswordOnce() {
        if (core_.isPasswordVerified()) {
            return true;
        }

        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << TR().t("keymgr_verify_title") << BRIGHT_BLUE
             << "]─────────────────────────────────────────┐\n";

        Botan::secure_vector<uint8_t> inputPass =
            KeySecureInput::readAccessCode(TR().t("keymgr_verify_prompt"), string(BRIGHT_BLUE) + "│ " + string(RESET));

        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << endl;

        if (inputPass.empty()) {
            cout << RED << TR().t("keymgr_verify_empty") << RESET << endl;
            return false;
        }

        bool ok = core_.verifyPassword(inputPass);
        inputPass.clear();

        if (!ok) {
            cout << RED << TR().t("keymgr_verify_fail") << RESET << endl;
            return false;
        }

        cout << GREEN << TR().t("keymgr_verify_ok") << RESET << endl;
        return true;
    }

    void printKeyManagerHeader() const {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    " << TR().t("keymgr_title") << "                      "
             << BRIGHT_BLUE << "│\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";

        {
            std::string line = "  " + TR().t("keymgr_user") + core_.getUsername();
            cout << "│" << RESET << "  " << TR().t("keymgr_user") << BRIGHT_MAGENTA << core_.getUsername()
                 << pad_to(" " + line, 69) << BRIGHT_BLUE << "│\n";
        }

        {
            std::string cnt = std::to_string(core_.keyCount());
            std::string line = "  " + TR().t("keymgr_count") + cnt;
            cout << "│" << RESET << "  " << TR().t("keymgr_count") << BRIGHT_CYAN << cnt << pad_to(" " + line, 69)
                 << BRIGHT_BLUE << "│\n";
        }

        if (KeyCryptoUtils::isArgon2Available()) {
            {
                std::string line = "  " + TR().t("keymgr_protection");
                cout << "│" << BRIGHT_GREEN << "  " << TR().t("keymgr_protection") << pad_to(" " + line, 69)
                     << BRIGHT_BLUE << "│\n";
            }
        }

        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << "\n";
    }

    void displayKeyInfo(const KeyInfo& key, int index = -1) const {
        if (index != -1) {
            cout << BRIGHT_BLUE << "[" << index + 1 << "] " << RESET;
        }

        cout << BRIGHT_GREEN << key.key_name << RESET;

        if (!key.is_active) {
            cout << RED << " " << TR().t("keymgr_list_status_inactive") << RESET;
        }

        cout << "\n";
        cout << "   " << TR().t("keymgr_keyinfo_type") << BRIGHT_CYAN << key.key_type << RESET << " (" << key.strength
             << " bits)\n";
        cout << "   " << TR().t("keymgr_keyinfo_usage") << BRIGHT_MAGENTA << key.key_usage << RESET << "\n";

        char timeStr[100];
        if (key.created_at > 0) {
            struct tm* timeinfo = localtime(&key.created_at);
            strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
            cout << "   " << TR().t("keymgr_keyinfo_created") << BRIGHT_WHITE << timeStr << RESET << "\n";
        }

        if (key.last_used > 0) {
            struct tm* timeinfo = localtime(&key.last_used);
            strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", timeinfo);
            cout << "   " << TR().t("keymgr_keyinfo_last_used") << BRIGHT_YELLOW << timeStr << RESET << "\n";
        }

        cout << "   " << TR().t("keymgr_keyinfo_state") << (key.is_active ? BRIGHT_GREEN : RED)
             << TR().t(key.is_active ? "key_status_active" : "key_status_inactive") << RESET << "\n";
        cout << "\n";
    }

    void createKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                   " << TR().t("keymgr_create_title") << "                     "
             << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        string keyName;
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << TR().t("keymgr_create_name_section") << BRIGHT_BLUE
             << "]────────────────────────────────────────────────┐\n";
        keyName = KeySecureInput::readStringNormal(TR().t("keymgr_create_name_prompt"),
                                                   string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << endl;

        if (keyName.empty()) {
            cout << RED << "\n" << TR().t("keymgr_create_name_empty") << RESET << endl;
            return;
        }

        if (core_.hasKey(keyName)) {
            cout << RED << "\n" << TR().t("keymgr_create_name_exists") << RESET << endl;
            return;
        }

        string keyUsage;
        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << TR().t("keymgr_create_usage_section") << BRIGHT_BLUE
             << "]───────────────────────────────────────────────────┐\n";
        keyUsage = KeySecureInput::readStringNormal(TR().t("keymgr_create_usage_prompt"),
                                                    string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << endl;

        if (keyUsage.empty()) {
            keyUsage = TR().t("keymgr_create_usage_default");
        }

        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << TR().t("keymgr_create_access_section") << BRIGHT_BLUE
             << "]───────────────────────────────────────────────────┐\n";
        {
            std::string line = "  " + TR().t("keymgr_create_access_hint");
            cout << "│" << RESET << "  " << TR().t("keymgr_create_access_hint") << pad_to(" " + line, 69) << BRIGHT_BLUE
                 << "│\n";
        }

        Botan::secure_vector<uint8_t> accessCode =
            KeySecureInput::readAccessCodeWithConfirm(TR().t("keymgr_create_access_prompt"),
                                                      TR().t("keymgr_create_access_confirm"),
                                                      string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << "\n";

        if (accessCode.empty()) {
            cout << RED << "\n" << TR().t("keymgr_create_access_empty") << RESET << endl;
            return;
        }

        cout << MAGENTA << "\n" << TR().t("keymgr_create_generating") << RESET << endl;

        string error_out;
        string created = core_.createKey(keyName, keyUsage, accessCode, error_out);
        accessCode.clear();

        if (created.empty()) {
            cout << RED << "\n" << TR().t("chpwd_fail", {TR().t(error_out)}) << RESET << endl;
            return;
        }

        cout << GREEN << TR().t("keymgr_create_ok") << RESET << endl;

        cout << GREEN;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                   " << TR().t("keymgr_create_created")
             << "                     " << GREEN << "│\n";
        cout << "├─────────────────────────────────────────────────────────────────────┤\n";
        {
            std::string line = "  " + TR().t("keymgr_create_info_name") + keyName;
            cout << "│" << RESET << "  " << TR().t("keymgr_create_info_name") << BRIGHT_MAGENTA << keyName
                 << pad_to(" " + line, 69) << GREEN << "│\n";
        }
        {
            std::string line = "  " + TR().t("keymgr_create_info_type");
            cout << "│" << RESET << "  " << TR().t("keymgr_create_info_type") << pad_to(" " + line, 69) << GREEN
                 << "│\n";
        }
        {
            std::string line = "  " + TR().t("keymgr_create_info_usage") + keyUsage;
            cout << "│" << RESET << "  " << TR().t("keymgr_create_info_usage") << BRIGHT_GREEN << keyUsage
                 << pad_to(" " + line, 69) << GREEN << "│\n";
        }
        {
            std::string state = TR().t("keymgr_create_state_inactive");
            std::string line = "  " + TR().t("keymgr_create_info_state") + state;
            cout << "│" << RESET << "  " << TR().t("keymgr_create_info_state") << RED << state << pad_to(" " + line, 69)
                 << GREEN << "│\n";
        }
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";
    }

    void toggleKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                  " << TR().t("keymgr_toggle_title")
             << "                       " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        if (core_.getKeys().empty()) {
            cout << YELLOW << "\n" << TR().t("keymgr_toggle_no_keys") << RESET << endl;
            return;
        }

        cout << "\n" << TR().t("keymgr_list_count", {std::to_string(core_.keyCount())}) << "\n" << endl;
        int index = 0;
        vector<string> keyNames;
        for (const auto& pair : core_.getKeys()) {
            displayKeyInfo(pair.second, index);
            keyNames.push_back(pair.first);
            index++;
        }

        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << TR().t("keymgr_toggle_select") << BRIGHT_BLUE
             << "]─────────────────────────────────────────────────┐\n";
        string choiceStr = KeySecureInput::readStringNormal(TR().t("keymgr_toggle_select_prompt"),
                                                            string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << endl;

        try {
            int choice = stoi(choiceStr) - 1;
            if (choice < 0 || choice >= static_cast<int>(keyNames.size())) {
                cout << RED << "\n" << TR().t("error_invalid_selection") << RESET << endl;
                return;
            }

            string selectedKey = keyNames[choice];
            const KeyInfo* keyInfo = core_.getKeyInfo(selectedKey);
            if (!keyInfo)
                return;
            bool wasActive = keyInfo->is_active;

            if (wasActive) {
                string confirm =
                    KeySecureInput::readStringNormal(TR().t("keymgr_toggle_deactivate_prompt", {selectedKey}) + " ");

                if (confirm != "s" && confirm != "S") {
                    cout << TR().t("error_cancelled") << endl;
                    return;
                }

                string error_out;
                Botan::secure_vector<uint8_t> emptyCode;
                if (core_.toggleKey(selectedKey, emptyCode, error_out)) {
                    cout << GREEN << "\n" << TR().t("keymgr_toggle_ok_deactivate") << RESET << endl;
                } else {
                    cout << RED << "\n" << TR().t(error_out) << RESET << endl;
                }
                return;
            }

            Botan::secure_vector<uint8_t> inputCode;
            if (keyInfo->requires_access) {
                inputCode = KeySecureInput::readAccessCode(TR().t("keymgr_toggle_access_prompt", {selectedKey}),
                                                           string(BRIGHT_BLUE) + "│ " + string(RESET));
            }

            string confirm =
                KeySecureInput::readStringNormal(TR().t("keymgr_toggle_activate_prompt", {selectedKey}) + " ");

            if (confirm != "s" && confirm != "S") {
                cout << TR().t("error_cancelled") << endl;
                inputCode.clear();
                return;
            }

            string error_out;
            if (core_.toggleKey(selectedKey, inputCode, error_out)) {
                cout << GREEN << "\n" << TR().t("keymgr_toggle_ok_activate") << RESET << endl;
                cout << TR().t("keymgr_toggle_activated_name") << BRIGHT_MAGENTA << selectedKey << RESET << endl;
                cout << TR().t("keymgr_toggle_activated_state") << BRIGHT_GREEN << TR().t("keymgr_toggle_state_active")
                     << RESET << endl;
            } else {
                cout << RED << "\n" << TR().t(error_out) << RESET << endl;
            }

            inputCode.clear();
        } catch (...) {
            cout << RED << "\n" << TR().t("error_invalid_selection") << RESET << endl;
        }
    }

    void listKeysMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    " << TR().t("keymgr_list_title") << "                      "
             << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        if (core_.getKeys().empty()) {
            cout << YELLOW << "\n" << TR().t("keymgr_list_empty") << RESET << endl;
            cout << "\n" << TR().t("press_enter_short");
            cin.get();
            return;
        }

        cout << "\n" << TR().t("keymgr_list_count", {std::to_string(core_.keyCount())}) << "\n" << endl;

        int index = 0;
        for (const auto& pair : core_.getKeys()) {
            displayKeyInfo(pair.second, index);
            index++;
        }

        int total = core_.keyCount();
        int activeCount = core_.activeCount();
        int inactiveCount = total - activeCount;

        std::string summary =
            TR().t("keymgr_list_summary",
                   {std::to_string(total), std::to_string(activeCount), std::to_string(inactiveCount)});

        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << RESET << "  " << summary << pad_to("  " + summary, 69) << BRIGHT_BLUE << "│\n";
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << "\n";

        cout << "\n" << TR().t("press_enter_short");
        cin.get();
    }

    void deleteKeyMenu() {
        cout << BRIGHT_BLUE;
        cout << "┌─────────────────────────────────────────────────────────────────────┐\n";
        cout << "│" << BRIGHT_GREEN << "                    " << TR().t("keymgr_delete_title")
             << "                              " << BRIGHT_BLUE << "│\n";
        cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

        if (core_.getKeys().empty()) {
            cout << YELLOW << "\n" << TR().t("keymgr_delete_empty") << RESET << endl;
            return;
        }

        cout << "\n" << TR().t("keymgr_list_count", {std::to_string(core_.keyCount())}) << "\n" << endl;
        int index = 0;
        vector<string> keyNames;
        for (const auto& pair : core_.getKeys()) {
            displayKeyInfo(pair.second, index);
            keyNames.push_back(pair.first);
            index++;
        }

        cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << TR().t("keymgr_delete_select") << BRIGHT_BLUE
             << "]──────────────────────────────────────┐\n";
        string choiceStr = KeySecureInput::readStringNormal(TR().t("keymgr_delete_prompt"),
                                                            string(BRIGHT_BLUE) + "│ " + string(RESET));
        cout << BRIGHT_BLUE << "└─────────────────────────────────────────────────────────────────────┘" << RESET
             << endl;

        try {
            int choice = stoi(choiceStr) - 1;
            if (choice < 0 || choice >= static_cast<int>(keyNames.size())) {
                cout << RED << "\n" << TR().t("error_invalid_selection") << RESET << endl;
                return;
            }

            string selectedKey = keyNames[choice];

            cout << RED << "\n" << TR().t("keymgr_delete_warning") << RESET << endl;
            string confirm = KeySecureInput::readStringNormal(TR().t("keymgr_delete_confirm", {selectedKey}) + " ");

            if (confirm != "s" && confirm != "S") {
                cout << TR().t("error_cancelled") << endl;
                return;
            }

            Botan::secure_vector<uint8_t> inputCode;
            const KeyInfo* keyInfo = core_.getKeyInfo(selectedKey);
            if (keyInfo && keyInfo->requires_access && !keyInfo->access_code.empty()) {
                inputCode = KeySecureInput::readAccessCode(TR().t("keymgr_delete_access_prompt"),
                                                           string(BRIGHT_BLUE) + "│ " + string(RESET));
            }

            string error_out;
            if (core_.deleteKey(selectedKey, inputCode, error_out)) {
                cout << GREEN << "\n" << TR().t("keymgr_delete_ok") << RESET << endl;
            } else {
                cout << RED << "\n" << TR().t(error_out) << RESET << endl;
            }

            inputCode.clear();
        } catch (...) {
            cout << RED << "\n" << TR().t("error_invalid_selection") << RESET << endl;
        }
    }

  public:
    KeyManagerUI(KeyManager& core) : core_(core) {
        core_.setLogCallback([this](key_log::LogLevel level, key_log::LogEvent event, const std::string& data) {
            this->onCoreLog(level, event, data);
        });
    }

    void showMenu() {
        if (!verifyUserPasswordOnce()) {
            return;
        }

        while (true) {
            printKeyManagerHeader();

            cout << BRIGHT_BLUE << "\n┌─[" << BRIGHT_MAGENTA << "OPCIONES" << BRIGHT_BLUE
                 << "]──────────────────────────────────────────────────────────┐\n";

            {
                std::string t = TR().t("keymgr_menu_create");
                cout << "│" << BRIGHT_GREEN << " [1] " << BRIGHT_MAGENTA << " " << t
                     << pad_to(" [1] " + t, 68) << BRIGHT_BLUE << "│\n";
            }
            {
                std::string t = TR().t("keymgr_menu_toggle");
                cout << "│" << BRIGHT_GREEN << " [2] " << BRIGHT_MAGENTA << " " << t
                     << pad_to(" [2] " + t, 68) << BRIGHT_BLUE << "│\n";
            }
            {
                std::string t = TR().t("keymgr_menu_list");
                cout << "│" << BRIGHT_GREEN << " [3] " << BRIGHT_MAGENTA << " " << t
                     << pad_to(" [3] " + t, 68) << BRIGHT_BLUE << "│\n";
            }
            {
                std::string t = TR().t("keymgr_menu_delete");
                cout << "│" << BRIGHT_GREEN << " [4] " << BRIGHT_MAGENTA << " " << t
                     << pad_to(" [4] " + t, 68) << BRIGHT_BLUE << "│\n";
            }
            {
                std::string t = TR().t("keymgr_menu_back");
                cout << "│" << BRIGHT_GREEN << " [5] " << BRIGHT_MAGENTA << " " << t
                     << pad_to(" [5] " + t, 68) << BRIGHT_BLUE << "│\n";
            }
            cout << "└─────────────────────────────────────────────────────────────────────┘" << RESET << "\n";

            string choice = KeySecureInput::readStringNormal(BRIGHT_GREEN + TR().t("keymgr_menu_prompt") + RESET);

            if (choice == "1") {
                createKeyMenu();
            } else if (choice == "2") {
                toggleKeyMenu();
            } else if (choice == "3") {
                listKeysMenu();
            } else if (choice == "4") {
                deleteKeyMenu();
            } else if (choice == "5") {
                core_.saveKeys();
                break;
            } else {
                cout << RED << "\n" << TR().t("error_invalid_input") << RESET << endl;
            }
        }
    }
};

#endif // UI_KEY_MANAGER_UI_H