// src/keygest/key_pipeline.cpp - 0.1 alpha
// Pipeline de persistencia del gestor de claves.
//
// Responsabilidades:
//   1. KeyInfo::serialize_secure / deserialize_secure  (formato binario)
//   2. key_persist::save / load                        (pipeline archivo)
//
//   save: serialize → compress(zlib) → encrypt(Argon2id+GCM) → write atómico
//   load: read → decrypt → decompress → deserialize
//
// Formato en disco v2:
//   [MAGIC:4]["RUBK"][VER:1][FLAGS:1][CSIZE:4 BE][PSIZE:4 BE][PAYLOAD:N]
//     CSIZE = tamaño del payload cifrado (comprimido o no)
//     PSIZE = tamaño del plaintext serializado original (para uncompress)

#include "key_manager.h"

#include <zlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>

// ============================================================
// Helpers del formato (anónimos: solo este TU los ve)
// ============================================================
namespace {

constexpr uint8_t  MAGIC[4]     = {'R','U','B','K'};
constexpr uint8_t  FORMAT_VER   = 0x02;
constexpr uint8_t  FLAG_ZLIB    = 0x01;
constexpr size_t   HEADER_SIZE  = 14;
constexpr size_t   MIN_COMPRESS = 128;
constexpr int      ZLIB_LEVEL   = 9;
constexpr uint32_t MAX_PSIZE    = 64u * 1024u * 1024u;  // sanity: 64 MB

inline void put_u32_be(Botan::secure_vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>( v        & 0xFF));
}

inline uint32_t get_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) <<  8) |
            static_cast<uint32_t>(p[3]);
}

Botan::secure_vector<uint8_t> zlib_pack(const uint8_t* src, size_t len) {
    uLongf bound = compressBound(static_cast<uLong>(len));
    Botan::secure_vector<uint8_t> dst(bound);
    if (compress2(dst.data(), &bound, src, static_cast<uLong>(len), ZLIB_LEVEL) != Z_OK)
        return {};
    dst.resize(bound);
    return dst;
}

Botan::secure_vector<uint8_t> zlib_unpack(const uint8_t* src, size_t len, size_t expected) {
    Botan::secure_vector<uint8_t> dst(expected);
    uLongf out_len = static_cast<uLongf>(expected);
    if (uncompress(dst.data(), &out_len, src, static_cast<uLong>(len)) != Z_OK)
        return {};
    if (out_len != expected)
        return {};
    return dst;
}

} // namespace

// ============================================================
// KeyInfo — formato binario
//   Declaración en key_manager.h, implementación aquí
//   (es infraestructura: describe CÓMO se escribe en disco)
// ============================================================

Botan::secure_vector<uint8_t> KeyInfo::serialize_secure() const {
    Botan::secure_vector<uint8_t> out;

    auto put_str = [&](const std::string& s) {
        put_u32_be(out, static_cast<uint32_t>(s.size()));
        out.insert(out.end(),
                   reinterpret_cast<const uint8_t*>(s.data()),
                   reinterpret_cast<const uint8_t*>(s.data()) + s.size());
    };
    auto put_sec = [&](const Botan::secure_vector<uint8_t>& v) {
        put_u32_be(out, static_cast<uint32_t>(v.size()));
        out.insert(out.end(), v.begin(), v.end());
    };
    auto put_u64 = [&](uint64_t v) {
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    };

    put_str(key_name);
    put_sec(key_value);
    put_sec(access_code);
    put_str(key_type);
    put_str(key_usage);
    put_u64(static_cast<uint64_t>(created_at));
    put_u64(static_cast<uint64_t>(last_used));
    out.push_back(is_active ? 1 : 0);
    put_u32_be(out, static_cast<uint32_t>(strength));
    out.push_back(requires_access ? 1 : 0);

    return out;
}

bool KeyInfo::deserialize_secure(const Botan::secure_vector<uint8_t>& data) {
    size_t pos = 0;

    auto need    = [&](size_t n){ return pos + n <= data.size(); };
    auto get_u8  = [&](uint8_t& v){ if (!need(1)) return false; v = data[pos++]; return true; };
    auto get_u32 = [&](uint32_t& v){ if (!need(4)) return false;
                                     v = get_u32_be(data.data() + pos); pos += 4; return true; };
    auto get_u64 = [&](uint64_t& v){ if (!need(8)) return false;
                                     v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | data[pos + i];
                                     pos += 8; return true; };
    auto get_str = [&](std::string& s){ uint32_t n; if (!get_u32(n) || !need(n)) return false;
                                        s.assign(reinterpret_cast<const char*>(data.data() + pos), n);
                                        pos += n; return true; };
    auto get_sec = [&](Botan::secure_vector<uint8_t>& s){ uint32_t n;
                                                          if (!get_u32(n) || !need(n)) return false;
                                                          s.assign(data.begin() + pos, data.begin() + pos + n);
                                                          pos += n; return true; };

    uint8_t  u8  = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;

    if (!get_str(key_name))    return false;
    if (!get_sec(key_value))   return false;
    if (!get_sec(access_code)) return false;
    if (!get_str(key_type))    return false;
    if (!get_str(key_usage))   return false;

    if (!get_u64(u64)) return false; created_at = static_cast<time_t>(u64);
    if (!get_u64(u64)) return false; last_used  = static_cast<time_t>(u64);
    if (!get_u8(u8))   return false; is_active  = (u8 == 1);
    if (!get_u32(u32)) return false; strength   = static_cast<int>(u32);
    if (!get_u8(u8))   return false; requires_access = (u8 == 1);

    return true;
}

// ============================================================
// key_persist — pipeline archivo
// ============================================================

namespace key_persist {

bool save(const std::map<std::string, KeyInfo>& keys,
          const std::string& filepath,
          const Botan::secure_vector<uint8_t>& user_password) {
    try {
        // --- 1. Serializar todos los KeyInfo (con prefijo de longitud) ---
        Botan::secure_vector<uint8_t> plain;
        for (const auto& pair : keys) {
            auto blob = pair.second.serialize_secure();
            put_u32_be(plain, static_cast<uint32_t>(blob.size()));
            plain.insert(plain.end(), blob.begin(), blob.end());
        }
        const uint32_t plain_size = static_cast<uint32_t>(plain.size());

        // --- 2. Comprimir (opcional) ---
        uint8_t flags = 0;
        Botan::secure_vector<uint8_t> payload = std::move(plain);
        if (plain_size >= MIN_COMPRESS) {
            auto z = zlib_pack(payload.data(), payload.size());
            if (!z.empty() && z.size() < payload.size()) {
                payload = std::move(z);
                flags |= FLAG_ZLIB;
            }
        }

        // --- 3. Construir cabecera ---
        Botan::secure_vector<uint8_t> framed;
        framed.insert(framed.end(), MAGIC, MAGIC + 4);
        framed.push_back(FORMAT_VER);
        framed.push_back(flags);
        put_u32_be(framed, static_cast<uint32_t>(payload.size()));
        put_u32_be(framed, plain_size);

        // --- 4. Cifrar con Argon2id + AES-256-GCM ---
        auto ct = KeyCryptoUtils::encryptData(payload, user_password);
        if (ct.empty())
            return false;
        framed.insert(framed.end(), ct.begin(), ct.end());

        // --- 5. Escritura atómica: tmp + fsync + rename ---
        std::string tmp = filepath + ".tmp";
        {
            int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd < 0)
                return false;
            bool ok = (::write(fd, framed.data(), framed.size()) == static_cast<ssize_t>(framed.size()))
                   && (::fsync(fd) == 0);
            ::close(fd);
            if (!ok) {
                ::unlink(tmp.c_str());
                return false;
            }
        }
        if (::rename(tmp.c_str(), filepath.c_str()) != 0) {
            ::unlink(tmp.c_str());
            return false;
        }
        ::chmod(filepath.c_str(), 0600);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool load(const std::string& filepath,
          std::map<std::string, KeyInfo>& out_keys,
          const Botan::secure_vector<uint8_t>& user_password) {
    struct stat st;
    if (::stat(filepath.c_str(), &st) != 0)
        return true;   // archivo no existe → ok (no es error)
    if (st.st_size < static_cast<off_t>(HEADER_SIZE))
        return false;

    // --- 1. Leer archivo completo ---
    Botan::secure_vector<uint8_t> raw(static_cast<size_t>(st.st_size));
    {
        int fd = ::open(filepath.c_str(), O_RDONLY);
        if (fd < 0)
            return false;
        ssize_t got = ::read(fd, raw.data(), raw.size());
        ::close(fd);
        if (got != static_cast<ssize_t>(raw.size()))
            return false;
    }

    // --- 2. Validar cabecera ---
    if (std::memcmp(raw.data(), MAGIC, 4) != 0)
        return false;

    uint8_t  ver   = raw[4];
    uint8_t  flags = raw[5];
    uint32_t csize = get_u32_be(raw.data() + 6);
    uint32_t psize = get_u32_be(raw.data() + 10);

    if (ver != FORMAT_VER)
        return false;
    if (HEADER_SIZE + static_cast<size_t>(csize) != raw.size())
        return false;
    if (psize > MAX_PSIZE)
        return false;

    // --- 3. Descifrar ---
    Botan::secure_vector<uint8_t> ct(raw.begin() + HEADER_SIZE, raw.end());
    auto payload = KeyCryptoUtils::decryptData(ct, user_password);
    if (payload.empty() || payload.size() != csize)
        return false;

    // --- 4. Descomprimir ---
    Botan::secure_vector<uint8_t> plain;
    if (flags & FLAG_ZLIB) {
        plain = zlib_unpack(payload.data(), payload.size(), psize);
        if (plain.empty())
            return false;
    } else {
        plain = std::move(payload);
    }

    // --- 5. Deserializar cada KeyInfo ---
    std::map<std::string, KeyInfo> parsed;
    size_t pos = 0;
    while (pos + 4 <= plain.size()) {
        uint32_t blob_len = get_u32_be(plain.data() + pos);
        pos += 4;
        if (pos + blob_len > plain.size())
            return false;

        Botan::secure_vector<uint8_t> blob(plain.begin() + pos,
                                           plain.begin() + pos + blob_len);
        pos += blob_len;

        KeyInfo k;
        if (!k.deserialize_secure(blob))
            return false;
        k.lockMemory();
        parsed[k.key_name] = std::move(k);
    }

    out_keys = std::move(parsed);
    return true;
}

} // namespace key_persist