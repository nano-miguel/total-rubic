// src/ui/translator.h

#ifndef UI_TRANSLATOR_H
#define UI_TRANSLATOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <initializer_list>

/* 
 * Calcula cuántas columnas reales ocupa un string UTF-8 en la terminal.
 */
size_t utf8_width(const std::string& s);

/* 
 * Quita las secuencias de escape ANSI (colores) del string.
 */
std::string strip_ansi(const std::string& s);

/* 
 * Devuelve el ancho visible de una línea que TIENE colores ANSI.
 */
size_t visible_width(const std::string& with_ansi);

/* 
 * Rellena con espacios a la derecha para llegar a target_cols.
 */
std::string pad_to(const std::string& text_plain, size_t target_cols);

/* 
 * Trunca un string a max_cols sin cortar un carácter UTF-8 al medio.
 */
std::string truncate_utf8(const std::string& s, size_t max_cols);

// ============================================================
// TRANSLATOR — SINGLETON
// ============================================================

class Translator {
  public:
    static Translator& instance();

    bool load(const std::string& lang_code);
    std::string t(const std::string& key) const;
    std::string t(const std::string& key, std::initializer_list<std::string> args) const;
    const std::string& currentLang() const;
    std::vector<std::string> availableLangs() const;
    
    static std::string detectSystemLanguage();
    static std::string getNativeLanguageName(const std::string& code);
    static std::string translationsDir();

  private:
    Translator() = default;
    Translator(const Translator&) = delete;
    Translator& operator=(const Translator&) = delete;

    std::unordered_map<std::string, std::string> strings_;
    std::string current_ = "es";
    mutable std::shared_mutex mtx_;
};

// Atajo global para no escribir Translator::instance() cada vez.
inline Translator& TR() {
    return Translator::instance();
}

#endif // UI_TRANSLATOR_H