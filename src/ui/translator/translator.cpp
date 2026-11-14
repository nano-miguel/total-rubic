// src/ui/translator/translator.cpp
#include "../translator.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstdlib>
#include <cctype>
#include <cstdint>
#include <mutex>

// ============================================================
// HELPERS INTERNOS (Ocultos del resto del mundo)
// ============================================================
namespace {

    // Decodifica 1 carácter UTF-8. Devuelve true si es válido.
    bool decode_utf8(const std::string& s, size_t i, uint32_t& cp, size_t& len) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        
        if (c < 0x80) { cp = c; len = 1; return true; }
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; len = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; len = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; len = 4; }
        else { return false; } // Byte de inicio inválido

        if (i + len > s.size()) return false;

        // Validar bytes de continuación
        for (size_t k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        return true;
    }

    // ¿Es un carácter de ancho cero? (acentos combinados, ZWJ, etc.)
    bool is_zero_width(uint32_t cp) {
        return (cp >= 0x0300 && cp <= 0x036F) || cp == 0x200B || cp == 0x200C || cp == 0x200D ||
               (cp >= 0xFE00 && cp <= 0xFE0F);
    }

    // ¿Es un carácter de doble ancho? (CJK, Hangul, Emojis anchos)
    bool is_wide_char(uint32_t cp) {
        return cp >= 0x1100 &&
               (cp <= 0x115F || cp == 0x2329 || cp == 0x232A || (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
                (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE6F) ||
                (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x1F000 && cp <= 0x1F02F) ||
                (cp >= 0x1F300 && cp <= 0x1F9FF));
    }

} // namespace

// ============================================================
// FUNCIONES PÚBLICAS DE TEXTO
// ============================================================

size_t utf8_width(const std::string& s) {
    size_t cols = 0;
    size_t i = 0;
    
    while (i < s.size()) {
        uint32_t cp = 0;
        size_t len = 1;
        
        if (!decode_utf8(s, i, cp, len)) {
            i++; // Byte inválido, saltar
            continue;
        }
        i += len;
        
        if (is_zero_width(cp)) 
            continue;
            
        cols += is_wide_char(cp) ? 2 : 1;
    }
    return cols;
}

std::string strip_ansi(const std::string& s) {
    // Si no hay secuencias de escape, nos ahorramos el bucle
    if (s.find('\033') == std::string::npos) 
        return s;

    std::string out;
    out.reserve(s.size());
    size_t i = 0;
    
    while (i < s.size()) {
        if (s[i] == '\033' && i + 1 < s.size() && s[i + 1] == '[') {
            i += 2;
            while (i < s.size() && !std::isalpha(static_cast<unsigned char>(s[i])))
                i++;
            if (i < s.size())
                i++; // consumir la letra final (m, K, etc.)
        } else {
            out += s[i++];
        }
    }
    return out;
}

size_t visible_width(const std::string& with_ansi) {
    return utf8_width(strip_ansi(with_ansi));
}

std::string pad_to(const std::string& text_plain, size_t target_cols) {
    size_t w = utf8_width(text_plain);
    if (w >= target_cols)
        return "";
    return std::string(target_cols - w, ' ');
}

std::string truncate_utf8(const std::string& s, size_t max_cols) {
    if (utf8_width(s) <= max_cols)
        return s;
    if (max_cols == 0)
        return "";

    std::string out;
    size_t cols = 0;
    size_t i = 0;
    size_t limit = max_cols - 1; // Reservar 1 columna para "…"

    while (i < s.size()) {
        uint32_t cp = 0;
        size_t len = 1;
        
        if (!decode_utf8(s, i, cp, len)) {
            i++;
            continue;
        }

        size_t w = is_wide_char(cp) ? 2 : 1;
        
        if (cols + w > limit)
            break;

        out.append(s, i, len);
        cols += w;
        i += len;
    }

    out += "…";
    return out;
}

// ============================================================
// TRANSLATOR — IMPLEMENTACIÓN
// ============================================================

Translator& Translator::instance() {
    static Translator t;
    return t;
}

bool Translator::load(const std::string& lang_code) {
    std::string path = translationsDir() + "/" + lang_code + ".lang";
    std::ifstream f(path);
    if (!f)
        return false;

    std::unordered_map<std::string, std::string> fresh;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.empty() || line[0] == '#')
            continue;

        auto eq = line.find('=');
        if (eq == std::string::npos)
            continue;

        std::string key = line.substr(0, eq);
        while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back())))
            key.pop_back();
        while (!key.empty() && std::isspace(static_cast<unsigned char>(key.front())))
            key.erase(key.begin());

        std::string val = line.substr(eq + 1);

        fresh[std::move(key)] = std::move(val);
    }

    {
        std::unique_lock lock(mtx_);
        strings_ = std::move(fresh);
        current_ = lang_code;
    }
    return true;
}

std::string Translator::t(const std::string& key) const {
    std::shared_lock lock(mtx_);
    auto it = strings_.find(key);
    if (it == strings_.end())
        return key;
    return it->second;
}

std::string Translator::t(const std::string& key, std::initializer_list<std::string> args) const {
    std::string s = t(key);
    size_t i = 0;
    for (const auto& a : args) {
        std::string token = "{" + std::to_string(i) + "}";
        size_t pos = 0;
        while ((pos = s.find(token, pos)) != std::string::npos) {
            s.replace(pos, token.size(), a);
            pos += a.size();
        }
        ++i;
    }
    return s;
}

const std::string& Translator::currentLang() const {
    return current_;
}

std::vector<std::string> Translator::availableLangs() const {
    std::vector<std::string> langs;
    std::error_code ec;
    auto dir = translationsDir();
    for (const auto& e : std::filesystem::directory_iterator(dir, ec)) {
        if (!e.is_regular_file())
            continue;
        auto p = e.path();
        if (p.extension() != ".lang")
            continue;
        langs.push_back(p.stem().string());
    }
    std::sort(langs.begin(), langs.end());
    return langs;
}

std::string Translator::detectSystemLanguage() {
    const char* lang_env = getenv("LANG");
    if (!lang_env) lang_env = getenv("LC_ALL");
    if (!lang_env) lang_env = getenv("LC_MESSAGES");
    
    if (lang_env) {
        std::string lang(lang_env);
        if (lang.length() >= 2) {
            return lang.substr(0, 2);
        }
    }
    return "en";
}

std::string Translator::getNativeLanguageName(const std::string& code) {
    if (code == "es") return "Español";
    if (code == "en") return "English";
    if (code == "pt") return "Português";
    if (code == "fr") return "Français";
    if (code == "de") return "Deutsch";
    if (code == "ru") return "Русский";
    if (code == "ja") return "日本語";
    if (code == "zh") return "中文";
    return code;
}

std::string Translator::translationsDir() {
    if (const char* p = getenv("RUBIC_TRANSLATIONS"))
        return p;
    if (std::filesystem::exists("./translations"))
        return "./translations";
    if (std::filesystem::exists("../share/rubic-a/translations"))
        return "../share/rubic-a/translations";
    if (std::filesystem::exists("../translations"))
        return "../translations";
    return "translations";
}
