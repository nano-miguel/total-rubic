// cipher/unit/unit_header.cpp 
#include "../unit_encryptor.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <filesystem>
#include <fstream>
#include <span>
#include <algorithm>

// HELPERS (I/O y Entorno aislados)
namespace {
    bool read_file_bytes(
        const std::string& path,
        Botan::secure_vector<uint8_t>& out) {
        std::ifstream file(path,
        std::ios::binary | std::ios::ate);
        if (!file.is_open()) 
            return false;
        
        std::streamsize size = file.tellg();
        if (size <= 0) 
            return false;

        out.resize(
            static_cast<size_t>(size));
            file.seekg(0, std::ios::beg);

            return file.read(
            reinterpret_cast<char*>(
            out.data()), size).good();
    }

    bool write_file_bytes(
        const std::string& path,
        const Botan::secure_vector<uint8_t>& data) {
        
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) 
            return false;

        file.write(reinterpret_cast<const char*>(
            data.data()),
            data.size());
        file.close();

        // Aplicamos los permisos (owner_read | owner_write) de forma portable
        std::filesystem::permissions(path, 
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);

        return true;
    }

    //purea mierda
    std::string get_backup_dir() {
        const char* xdg = getenv("XDG_DATA_HOME");
        if (xdg && xdg[0]) 
            return std::string(xdg) + "/RUBIC-A/backups";

        const char* home = getenv("HOME");
        if (home && home[0])
            return std::string(home) + "/.local/share/RUBIC-A/backups";
            return "/tmp/RUBIC-A/backups";  
    }
} // Cierre del namespace
       
//  derivamo la clave de key
 Botan::secure_vector<uint8_t> KeyDeriv::deriveSubKey(
    const Botan::secure_vector<uint8_t>& master_key,
    const Botan::secure_vector<uint8_t>& salt,
    size_t key_length) {
    try {
        auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-512)");
        Botan::secure_vector<uint8_t> derived_key(key_length);
        std::string info_str = KEY_DERIVATION_INFO;
        kdf->derive_key(

        std::span<uint8_t>(
            derived_key.data(),
            derived_key.size()),

        std::span<const uint8_t>(
            master_key.data(),
            master_key.size()),

        std::span<const uint8_t>(
            salt.data(),
            salt.size()),

        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(
            info_str.data()),
            info_str.size()));

        return derived_key;
    } catch (const std::exception&) { 
        return {}; }
}

 Botan::secure_vector<uint8_t> KeyDeriv::generateSalt(size_t size) {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> salt(size);
            rng.randomize(
            salt.data(),
            salt.size());
        return salt;
    } catch (const std::exception&) { 
        return {}; }
}

/*flojo de kmac*/
 KMACProc::KMACProc(
    const Botan::secure_vector<uint8_t>& key_data) {
    key = key_data;
    try {  
            Kmac = Botan::MessageAuthenticationCode::create("KMAC-256(512)"); } 
    catch (const std::exception&) {
            Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(512))");
    if (!Kmac) 
            Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    }
    // FIX CRITICO: Si Kmac es nulo, explotamos. Si no, le seteamos la clave.
    if (!Kmac) {
        throw std::runtime_error("No se pudo crear el MAC criptográfico"); 
    }
    Kmac->set_key(key);
}

Botan::secure_vector<uint8_t> KMACProc::calculate(
    const uint8_t* data, size_t size) { Kmac->update(data, size);
    return Kmac->final();
}

bool KMACProc::verify(
    const uint8_t* data,size_t size,
    const uint8_t* expected_Kmac, size_t Kmac_size) {
    auto calc = calculate(data, size);
    if (calc.size() != Kmac_size)
    return false; 
    
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < Kmac_size; i++) diff |= (calc[i] ^ expected_Kmac[i]);
    return diff == 0;
}

/*respaldo de clave*/
std::string HdrBackup::getBackupPath(
    const std::string& device_path) {
        std::string devname = device_path;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    std::replace(
        devname.begin(),
        devname.end(), '/', '_');

    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update(devname);

    std::string hashed = Botan::hex_encode(hash->final()).substr(0, 16);
    std::string base = get_backup_dir(); // Acá llamamos a la función limpia
    std::filesystem::create_directories(base);
    std::filesystem::permissions(base,
    std::filesystem::perms::owner_all,
    std::filesystem::perm_options::replace);
    return base + "/.rubic_" + hashed + ".dat";
}

Botan::secure_vector<uint8_t> HdrBackup::deriveBackupKey(
    const std::string& device_path,
    const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.size() != 32) return {};
    try {
        auto kdf = Botan::KDF::create("HKDF(SHA-512)");
    if (!kdf) 
        return {};
        Botan::secure_vector<uint8_t> out(32);
           std::string info = "RUBIC_HEADER_BACKUP_V1";
                kdf->derive_key(
           std::span<uint8_t>(out.data(),
                out.size()),
           std::span<const uint8_t>(
                master_key.data(),
                master_key.size()),
           std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(
                device_path.data()),
                device_path.size()),
           std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(
                info.data()),
                info.size()));
        return out;
    } catch (const std::exception&) { 
        return {}; }
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
            rng.randomize(
            nonce.data(),
            nonce.size());

            cipher->start(nonce);
            cipher->finish(data);

        Botan::secure_vector<uint8_t> result;
        result.insert(
            result.end(),
            nonce.begin(),
            nonce.end());

        result.insert(
            result.end(),
            data.begin(),
            data.end());
        return result;
    } catch (const std::exception&) { 
        return {}; }
}

bool HdrBackup::decryptBackup(
    const std::string& backup_path,EncUnitHdr& header,
    const Botan::secure_vector<uint8_t>& key) {
    Botan::secure_vector<uint8_t> enc;
    if (!read_file_bytes(backup_path, enc)) 
        return false; 
    if (enc.size() < 12 + 16) 
        return false;

    try {
        Botan::secure_vector<uint8_t> nonce(
            enc.begin(),
            enc.begin() + 12);
        Botan::secure_vector<uint8_t> ct(
            enc.begin() + 12,
            enc.end());

        auto cipher = 
        Botan::Cipher_Mode::create("AES-256/GCM",
        Botan::Cipher_Dir::Decryption);
        if (!cipher) 
        return false;
            cipher->set_key(key);
            cipher->start(nonce);
            cipher->finish(ct);
        if (ct.size() != sizeof(header))
        return false;
        
        std::memcpy(&header, ct.data(), sizeof(header));
        return true;
    } catch (const std::exception&) { 
        return false; }
}

bool HdrBackup::saveHeader(
    const std::string& device_path,
    const EncUnitHdr& header,
    const Botan::secure_vector<uint8_t>& master_key) {
    auto bk = deriveBackupKey(device_path, master_key);
    if (bk.empty()) 
        return false;

    auto enc = encryptBackup(header, bk);
    if (enc.empty())
        return false;

    return write_file_bytes(
        getBackupPath(device_path), enc);
}

bool HdrBackup::loadHeader(
    const std::string& device_path,EncUnitHdr& header,
    const Botan::secure_vector<uint8_t>& master_key) {
    auto bk = deriveBackupKey(device_path, master_key);
    if (bk.empty()) 
        return false;

    return decryptBackup(
        getBackupPath(device_path),header, bk);
}

bool HdrBackup::backupExists(
    const std::string& device_path) {
    struct stat st;

    return stat(
        getBackupPath(device_path).c_str(),&st) == 0;
}

bool HdrBackup::removeBackup(
    const std::string& device_path) {

    return unlink(
        getBackupPath(device_path).c_str()) == 0;
}

// ==========================================
// CONTROL FISICO DE LA CABECERA (Movido de unit_encryptor.cpp)
// ==========================================

bool UnitEncryptor::isUnitEncrypt(
    const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0) 
        return false;
        
    EncUnitHdr hdr;
    bool ok = read_enc_header(fd, hdr);
    close(fd);
        return ok;
}

bool UnitEncryptor::readHdr(
int fd, EncUnitHdr& hdr) {
        return read_enc_header(fd, hdr);
}

bool UnitEncryptor::writeHdr(
int fd,
    const EncUnitHdr& hdr) {
    ssize_t w = -1;
    {
        DirectIOGuard guard(fd);
    if (!guard.valid()) 
        return false;
        w = pwrite(fd, &hdr,sizeof(hdr),
        HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    }
    if (w != sizeof(hdr))
        return false;
    if (fsync(fd) != 0) 
        return false;
        return true;
}

bool UnitEncryptor::cleanHeader(
    const StorUnit& unit) {
        log(LogLevel::Info,
            LogEvent::CleanupHeader,unit.device_path);
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);

    if (fd < 0) { 
        log(LogLevel::Error,
             LogEvent::DeviceOpenFailed,strerror(errno));
        return false; }

    size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(hsz, 0);
    bool ok = safe_pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE);

    if (ok) 
        {if (fsync(fd) != 0) ok = false;}
    close(fd);

    if (!ok) { 
    log(LogLevel::Error,
         LogEvent::HeaderCleanFailed, "");
        return false; }
    log(LogLevel::Success,
         LogEvent::HeaderRemoved, "");

    if (backup_mgr.backupExists(unit.device_path)
     && backup_mgr.removeBackup(unit.device_path))

    log(LogLevel::Success,
         LogEvent::BackupRemoved, "");
        return true;
}

bool UnitEncryptor::restoreHeader(
    const StorUnit& unit,
    const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info,
         LogEvent::HeaderRestoring, ""); EncUnitHdr hdr;

    if (!backup_mgr.loadHeader(
        unit.device_path, hdr, master_key)) {
    log(LogLevel::Error,
         LogEvent::BackupLoadFailed, "");
        return false;
    }
    int fd = open(
        unit.device_path.c_str(), O_RDWR | O_SYNC);

    if (fd < 0) {
    log(LogLevel::Error,
         LogEvent::DeviceOpenFailed, strerror(errno)); 
        return false;
    }
    
    if (!writeHdr(fd, hdr)) {
    log(LogLevel::Error,
         LogEvent::HeaderRestoreFailed, "");
    close(fd);
        return false;
    }

    close(fd);
    log(LogLevel::Success,
         LogEvent::HeaderRestored, "");
        return true;
}
