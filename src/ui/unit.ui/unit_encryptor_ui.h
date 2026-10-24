// src/ui/unit.ui/unit_encryptor_ui.h
#ifndef UI_UNIT_ENCRYPTOR_UI_H
#define UI_UNIT_ENCRYPTOR_UI_H

#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <functional>
#include "../../cipher/unit_encryptor.h"
#include "../../keygest/key_manager.h"

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
    ProgBar(int bar_width = 50, const std::string& pre = "", const std::string& suf = "");
    void setTotal(uint64_t total);
    void update(uint64_t current);
    void render();
    void finish();
};

class UnitEncryptorUI {
private:
    UnitEncryptor& core_;
    KeyManager* keyManager_;
    std::string currentKeyName;
    inline static UnitEncryptorUI* instance = nullptr;

    static void signalHandler(int signal);
    static void setupSignalHandlers();

    std::string getInput(const std::string& prompt);
    void waitForEnter();
    void menu_line(const std::string& marker, const std::string& label);
    void onCoreLog(LogLevel level, LogEvent event, const std::string& data);
    void onCoreProgress(uint64_t current, uint64_t total, double speed);

    std::string selectKeyFromManager();
    Botan::secure_vector<uint8_t> getMasterKey();
    void showConfigMenu();
    void renderProcessConfirmation(const StorUnit& unit, bool encrypt, const std::string& keyword);
    void printStats(const UnitEncryptor::Stats& stats);
    bool processUnit(StorUnit& unit, bool encrypt);
    static const char* getDevTypeColor(DevType type);
    void showFormatMenu(StorUnit& unit);
    void renderUnitMenu(const StorUnit& u);
    void handleUnitMenuChoice(const std::string& c, StorUnit& u);
    void unitMenu(StorUnit& u);
    void renderMainMenu(const std::vector<StorUnit>& units);
    void handleMainMenuChoice(const std::string& c, std::vector<StorUnit>& units);

public:
    UnitEncryptorUI(UnitEncryptor& core, KeyManager* km);
    ~UnitEncryptorUI();
    void showMenu();
};

#endif // UI_UNIT_ENCRYPTOR_UI_H