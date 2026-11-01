// cipher/unit/unit_header.cpp - 0.1 alpha
#include "../unit_encryptor.h"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <span>
#include <algorithm>

/**
 * Deriva una subclave  usando HKDF-SHA512.
 */
Botan::secure_vector<uint8_t> KeyDeriv::deriveSubKey(
    const Botan::secure_vector<uint8_t>& master_key,
    const Botan::secure_vector<uint8_t>& salt,
    size_t key_length) {
    try {
        auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-512)");
        Botan::secure_vector<uint8_t> derived_key(key_length);
        std::string info_str = KEY_DERIVATION_INFO;

        kdf->derive_key(
            std::span<uint8_t>(derived_key.data(), derived_key.size()),
            std::span<const uint8_t>(master_key.data(), master_key.size()),
            std::span<const uint8_t>(salt.data(), salt.size()),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(info_str.data()),
                info_str.size()));

        return derived_key;
    } catch (const std::exception&) {
        return {};
    }
}

Botan::secure_vector<uint8_t> KeyDeriv::generateSalt(size_t size) {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> salt(size);
        rng.randomize(salt.data(), salt.size());
        return salt;
    } catch (const std::exception&) {
        return {};
    }
}

/**
 * Inicializa el MAC (KMAC) para validar la integridad del header.
 * Usa KMAC-256, con fallback a HMAC(SHA-3) si el CPU no lo soporta.
 */
KMACProc::KMACProc(const Botan::secure_vector<uint8_t>& key_data) {
    key = key_data;

    try {
        Kmac = Botan::MessageAuthenticationCode::create("KMAC-256(512)");
    } catch (const std::exception&) {
        Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(512))");
        if (!Kmac)
            Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    }

    if (!Kmac)
        throw std::runtime_error("No se pudo crear el MAC criptográfico");

    Kmac->set_key(key);
}

Botan::secure_vector<uint8_t> KMACProc::calculate(const uint8_t* data, size_t size) {
    Kmac->update(data, size);
    return Kmac->final();
}

// Comparación en tiempo constante para evitar ataques de timing.
bool KMACProc::verify(const uint8_t* data, size_t size,
                      const uint8_t* expected_Kmac, size_t Kmac_size) {
    auto calc = calculate(data, size);
    if (calc.size() != Kmac_size)
        return false;

    volatile uint8_t diff = 0;
    for (size_t i = 0; i < Kmac_size; i++)
        diff |= (calc[i] ^ expected_Kmac[i]);

    return diff == 0;
}

/**
 * Obtiene la ruta del backup del header.
 * Se guarda en la carpeta XDG del usuario para no ensuciar el disco.
 */
std::string HdrBackup::getBackupPath(const std::string& device_path) {
    std::string devname = device_path;
    if (devname.find("/dev/") == 0)
        devname = devname.substr(5);
    std::replace(devname.begin(), devname.end(), '/', '_');

    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update(devname);
    std::string hashed = Botan::hex_encode(hash->final()).substr(0, 16);

    const char* xdg = getenv("XDG_DATA_HOME");
    std::string base;
    if (xdg && xdg[0]) {
        base = std::string(xdg) + "/RUBIC-A/backups";
    } else {
        const char* home = getenv("HOME");
        base = home && home[0]
            ? std::string(home) + "/.local/share/RUBIC-A/backups"
            : "/var/lib/rubic-a/backups";
    }

    std::filesystem::create_directories(base);
    std::filesystem::permissions(base,
                                 std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace);

    return base + "/.rubic_" + hashed + ".dat";
}

Botan::secure_vector<uint8_t> HdrBackup::encryptBackup(
    const EncUnitHdr& header,
    const Botan::secure_vector<uint8_t>& key) {
    try {
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM",
                                                  Botan::Cipher_Dir::Encryption);
        if (!cipher)
            return {};

        Botan::secure_vector<uint8_t> data(sizeof(header));
        std::memcpy(data.data(), &header, sizeof(header));

        cipher->set_key(key);

        Botan::secure_vector<uint8_t> nonce(12);
        Botan::AutoSeeded_RNG rng;
        rng.randomize(nonce.data(), nonce.size());
        cipher->start(nonce);
        cipher->finish(data);

        Botan::secure_vector<uint8_t> result;
        result.insert(result.end(), nonce.begin(), nonce.end());
        result.insert(result.end(), data.begin(), data.end());
        return result;
    } catch (const std::exception&) {
        return {};
    }
}

bool HdrBackup::decryptBackup(
    const std::string& backup_path,
    EncUnitHdr& header,
    const Botan::secure_vector<uint8_t>& key) {
    std::ifstream file(backup_path, std::ios::binary);
    if (!file.is_open())
        return false;

    Botan::secure_vector<uint8_t> enc;
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    enc.resize(size);
    file.read(reinterpret_cast<char*>(enc.data()), size);
    file.close();

    if (enc.size() < 12 + 16)
        return false;

    try {
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM",
                                                  Botan::Cipher_Dir::Decryption);
        if (!cipher)
            return false;

        Botan::secure_vector<uint8_t> nonce(enc.begin(), enc.begin() + 12);
        Botan::secure_vector<uint8_t> ct(enc.begin() + 12, enc.end());

        cipher->set_key(key);
        cipher->start(nonce);
        cipher->finish(ct);

        if (ct.size() != sizeof(header))
            return false;

        std::memcpy(&header, ct.data(), sizeof(header));
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

/**
 * Deriva la clave para el backup del header.
 * IMPORTANTE: Depende tanto de la master_key como del path del dispositivo.
 * Esto evita que alguien pueda descifrar el backup solo conociendo el path.
 */
Botan::secure_vector<uint8_t> HdrBackup::deriveBackupKey(
    const std::string& device_path,
    const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.size() != 32)
        return {};

    try {
        auto kdf = Botan::KDF::create("HKDF(SHA-512)");
        if (!kdf)
            return {};

        Botan::secure_vector<uint8_t> out(32);
        std::string info = "RUBIC_HEADER_BACKUP_V1";

        kdf->derive_key(
            std::span<uint8_t>(out.data(), out.size()),
            std::span<const uint8_t>(master_key.data(), master_key.size()),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(device_path.data()),
                device_path.size()),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(info.data()),
                info.size()));

        return out;
    } catch (const std::exception&) {
        return {};
    }
}

bool HdrBackup::saveHeader(const std::string& device_path,
                           const EncUnitHdr& header,
                           const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.size() != 32)
        return false;

    auto bk = deriveBackupKey(device_path, master_key);
    if (bk.empty())
        return false;

    auto enc = encryptBackup(header, bk);
    if (enc.empty())
        return false;

    std::string path = getBackupPath(device_path);
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open())
        return false;
    file.write(reinterpret_cast<const char*>(enc.data()), enc.size());
    file.close();
    chmod(path.c_str(), 0600);
    return true;
}

bool HdrBackup::loadHeader(const std::string& device_path,
                           EncUnitHdr& header,
                           const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.size() != 32)
        return false;

    auto bk = deriveBackupKey(device_path, master_key);
    if (bk.empty())
        return false;

    return decryptBackup(getBackupPath(device_path), header, bk);
}

bool HdrBackup::backupExists(const std::string& device_path) {
    struct stat st;
    return stat(getBackupPath(device_path).c_str(), &st) == 0;
}

bool HdrBackup::removeBackup(const std::string& device_path) {
    return unlink(getBackupPath(device_path).c_str()) == 0;
}