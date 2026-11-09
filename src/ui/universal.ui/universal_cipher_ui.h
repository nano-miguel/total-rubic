// ui/universal.ui/universal_cipher_ui.h - 0.1 alpha
// Toda la UI de UniversalCipher: menús, prompts, lectura de teclado.
#ifndef UI_UNIVERSAL_CIPHER_UI_H
#define UI_UNIVERSAL_CIPHER_UI_H

#include "unit_encryptor_ui.h"
#include "../translator.h"
#include "../../cipher/universal_cipher.h" // <-- La línea que salva el día

#include <iostream>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <unistd.h>
#include <algorithm>
#include <sys/wait.h>
#include <limits.h>
#include <cstdlib>
#include <cstring>

#ifndef UI_CIPHER_COLORS_DEFINED
#define UI_CIPHER_COLORS_DEFINED
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

class UniversalCipherUI {
private:
    UniversalCipher& core_;
    KeyManager* keyManager_;
    inline static UniversalCipherUI* instance = nullptr;

    static void signalHandler(int signal);
    static void setupSignalHandlers();

    struct termios oldt, newt;
    void disable_echo();
    void enable_echo();
    Botan::secure_vector<uint8_t> get_secure_bytes(const std::string& prompt);
    std::string getInput(const std::string& prompt);
    void waitForEnter();
    
    void onCoreLog(univ_log::LogLevel level, univ_log::LogEvent event, const std::string& data);
    void onCoreProgress(size_t current, size_t total, const std::string& file);
    void menu_line(const std::string& marker, const std::string& label);
 
public:
    UniversalCipherUI(UniversalCipher& core, KeyManager* km);
    ~UniversalCipherUI();
    
    std::string selectKey();
    void showMenu();
    void showConfigMenu();
};

#endif // UI_UNIVERSAL_CIPHER_UI_H