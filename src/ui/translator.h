// src/ui/translator.h
// Header-only. Sin .cpp. Sin gettext. Sin JSON.
// Formato .lang: key=value, # comentarios, {0} {1} placeholders.

#ifndef UI_TRANSLATOR_H
#define UI_TRANSLATOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <initializer_list>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstdlib>
#include <cctype>
#include <cstdint>

// ============================================================
// UTF-8 — ancho REAL de columna en terminal
// ============================================================
inline size_t utf8_width(const std::string& s) {
    size_t cols = 0;
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp = 0;
        size_t len = 1;

        if (c < 0x80) {
            cp = c;
            len = 1;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            len = 3;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07;
            len = 4;
        } else {
            i++;
            continue;
        } // byte UTF-8 inválido → skip

        if (i + len > s.size())
            break;

        bool bad = false;
        for (size_t k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) {
                bad = true;
                break;
            }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (bad) {
            i++;
            continue;
        }
        i += len;

        // Combinantes y zero-width → 0 columnas
        if ((cp >= 0x0300 && cp <= 0x036F) || cp == 0x200B || cp == 0x200C || cp == 0x200D ||
            (cp >= 0xFE00 && cp <= 0xFE0F)) {
            continue;
        }

        // Doble ancho (CJK, Hangul, emojis anchos)
        if (cp >= 0x1100 &&
            (cp <= 0x115F || cp == 0x2329 || cp == 0x232A || (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) ||
             (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) || (cp >= 0xFE30 && cp <= 0xFE6F) ||
             (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6) || (cp >= 0x1F000 && cp <= 0x1F02F) ||
             (cp >= 0x1F300 && cp <= 0x1F9FF))) {
            cols += 2;
        } else {
            cols += 1;
        }
    }
    return cols;
}

// Quita secuencias ANSI (\033[...m) para poder medir el texto limpio
inline std::string strip_ansi(const std::string& s) {
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

// Ancho visible de una línea CON colores ANSI
inline size_t visible_width(const std::string& with_ansi) {
    return utf8_width(strip_ansi(with_ansi));
}

// Espacios para alinear a target_cols. Se le pasa el texto SIN colores.
inline std::string pad_to(const std::string& text_plain, size_t target_cols) {
    size_t w = utf8_width(text_plain);
    if (w >= target_cols)
        return "";
    return std::string(target_cols - w, ' ');
}

// Trunca a max_cols sin cortar un code point al medio.
// Si corta, agrega "…" (ocupa 1 columna, se descuenta del límite).
inline std::string truncate_utf8(const std::string& s, size_t max_cols) {
    if (utf8_width(s) <= max_cols)
        return s;
    if (max_cols == 0)
        return "";

    std::string out;
    size_t cols = 0;
    size_t i = 0;
    size_t limit = max_cols - 1; // reservar 1 columna para "…"

    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t len = 1;
        uint32_t cp = c;

        if (c < 0x80) {
            len = 1;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            len = 2;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            len = 3;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07;
            len = 4;
        } else {
            i++;
            continue;
        }

        if (i + len > s.size())
            break;

        bool bad = false;
        for (size_t k = 1; k < len; ++k) {
            unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) {
                bad = true;
                break;
            }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (bad) {
            i++;
            continue;
        }

        size_t w = 1;
        if (cp >= 0x1100 &&
            (cp <= 0x115F || (cp >= 0x2E80 && cp <= 0xA4CF && cp != 0x303F) || (cp >= 0xAC00 && cp <= 0xD7A3) ||
             (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0x1F300 && cp <= 0x1F9FF))) {
            w = 2;
        }

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
// TRANSLATOR — singleton header-only
// ============================================================

class Translator {
  public:
    static Translator& instance() {
        static Translator t; // thread-safe desde C++11
        return t;
    }

    // Carga <dir>/<lang>.lang. Devuelve false si el archivo no existe.
    bool load(const std::string& lang_code) {
        std::string path = translationsDir() + "/" + lang_code + ".lang";
        std::ifstream f(path);
        if (!f)
            return false;

        std::unordered_map<std::string, std::string> fresh;
        std::string line;
        while (std::getline(f, line)) {
            if (!line.empty() && line.back() == '\r')
                line.pop_back(); // CRLF
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

    // --- API principal ---
    std::string t(const std::string& key) const {
        std::shared_lock lock(mtx_);
        auto it = strings_.find(key);
        if (it == strings_.end())
            return key; // fallback al key crudo
        return it->second;
    }

    std::string t(const std::string& key, std::initializer_list<std::string> args) const {
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

    // --- Info ---
    const std::string& currentLang() const {
        return current_;
    }

    std::vector<std::string> availableLangs() const {
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

    // ============================================================
    // NUEVAS FUNCIONES DE UX E IDIOMAS
    // ============================================================

    // Detecta el idioma del sistema operativo (Linux)
    static std::string detectSystemLanguage() {
        const char* lang_env = getenv("LANG");
        if (!lang_env) lang_env = getenv("LC_ALL");
        if (!lang_env) lang_env = getenv("LC_MESSAGES");
        
        if (lang_env) {
            std::string lang(lang_env);
            if (lang.length() >= 2) {
                return lang.substr(0, 2); // Devuelve "es" de "es_ES.UTF-8"
            }
        }
        return "en"; // Fallback a inglés
    }

    // Devuelve el nombre nativo del idioma
    static std::string getNativeLanguageName(const std::string& code) {
        if (code == "es") return "Español";
        if (code == "en") return "English";
        if (code == "pt") return "Português";
        if (code == "fr") return "Français";
        if (code == "de") return "Deutsch";
        if (code == "ru") return "Русский";
        if (code == "ja") return "日本語";
        if (code == "zh") return "中文";
        return code; // Si no está, devuelve el código
    }

    // Orden de búsqueda del directorio de traducciones:
    static std::string translationsDir() {
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

  private:
    Translator() = default;
    Translator(const Translator&) = delete;
    Translator& operator=(const Translator&) = delete;

    std::unordered_map<std::string, std::string> strings_;
    std::string current_ = "es";
    mutable std::shared_mutex mtx_;
};

// Atajo global: TR().t("...")
inline Translator& TR() {
    return Translator::instance();
}

#endif // UI_TRANSLATOR_H