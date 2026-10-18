// cipher/unit_encryptor.cpp - 0.1 alpha
#include "unit_encryptor.h"
#include "../keygest/key_manager.h"
#include "../rubic_core.h"

#include <limits.h>
#include <sys/wait.h>
#include <filesystem>
#include <fcntl.h>
#include <span>

#include <linux/fs.h>
#include <sys/ioctl.h>
#include <mntent.h>
#include <sys/mman.h>
#include <sys/statvfs.h>

#ifdef BLOCK_SIZE
#undef BLOCK_SIZE
#endif
#ifdef SECTOR_SIZE
#undef SECTOR_SIZE
#endif

#if defined(__x86_64__) || defined(__i386__)
  #include <immintrin.h>
#endif

// ============================================
// Helpers de proceso
// ============================================

static int safe_exec(const std::vector<std::string>& args) {
    if (args.empty()) return -1;
    pid_t pid = fork();
    if (pid == -1) return -1;
    if (pid == 0) {
        std::vector<char*> c_args;
        for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static std::string exec_cmd_output(const std::vector<std::string>& args) {
    if (args.empty()) return "";
    int pipefd[2];
    if (pipe(pipefd) == -1) return "";
    pid_t pid = fork();
    if (pid == -1) { close(pipefd[0]); close(pipefd[1]); return ""; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        std::vector<char*> c_args;
        for (const auto& arg : args) c_args.push_back(const_cast<char*>(arg.c_str()));
        c_args.push_back(nullptr);
        execvp(c_args[0], c_args.data());
        _exit(127);
    }
    close(pipefd[1]);
    std::string result;
    char buffer[256];
    ssize_t bytes_read;
    while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';
        result += buffer;
    }
    close(pipefd[0]);
    int status;
    waitpid(pid, &status, 0);
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

// ============================================
// KeyDeriv
// ============================================

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
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()));
        return derived_key;
    } catch (...) {
        return {};
    }
}

Botan::secure_vector<uint8_t> KeyDeriv::generateSalt(size_t size) {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> salt(size);
        rng.randomize(salt.data(), salt.size());
        return salt;
    } catch (...) {
        return {};
    }
}

// ============================================
// CustCfg
// ============================================

CustCfg::CustCfg()
    : buffer_size_mb(64), io_threads(2), crypto_threads(4),
      use_direct_io(true), custom_mode(false) {}

void CustCfg::loadFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "buffer_size_mb") buffer_size_mb = std::stoul(value);
            else if (key == "io_threads") io_threads = std::stoi(value);
            else if (key == "crypto_threads") crypto_threads = std::stoi(value);
            else if (key == "use_direct_io") use_direct_io = (value == "true");
            else if (key == "custom_mode") custom_mode = (value == "true");
        }
    }
}

void CustCfg::saveToFile(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    file << "# Configuración personalizada de RUBI-C\n";
    file << "# Valores por defecto: buffer_size_mb=64, io_threads=2, crypto_threads=4\n\n";
    file << "buffer_size_mb=" << buffer_size_mb << "\n";
    file << "io_threads=" << io_threads << "\n";
    file << "crypto_threads=" << crypto_threads << "\n";
    file << "use_direct_io=" << (use_direct_io ? "true" : "false") << "\n";
    file << "custom_mode=" << (custom_mode ? "true" : "false") << "\n";
}

// ============================================
// AlignBuf
// ============================================

AlignBuf::AlignBuf(size_t size) : data_ptr(nullptr), size_bytes(size) {
    if (posix_memalign(&data_ptr, ALIGNMENT, size) != 0) throw std::bad_alloc();
    memset(data_ptr, 0, size);
}
AlignBuf::~AlignBuf() { if (data_ptr) free(data_ptr); }
AlignBuf::AlignBuf(AlignBuf&& other) noexcept : data_ptr(other.data_ptr), size_bytes(other.size_bytes) {
    other.data_ptr = nullptr; other.size_bytes = 0;
}
AlignBuf& AlignBuf::operator=(AlignBuf&& other) noexcept {
    if (this != &other) {
        if (data_ptr) free(data_ptr);
        data_ptr = other.data_ptr; size_bytes = other.size_bytes;
        other.data_ptr = nullptr; other.size_bytes = 0;
    }
    return *this;
}
uint8_t* AlignBuf::data() { return static_cast<uint8_t*>(data_ptr); }
const uint8_t* AlignBuf::data() const { return static_cast<const uint8_t*>(data_ptr); }
size_t AlignBuf::size() const { return size_bytes; }

// ============================================
// DevDetect
// ============================================

std::string DevDetect::getSysPath(const std::string& device) {
    std::string devname = device;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    while (!devname.empty() && isdigit(devname.back())) devname.pop_back();
    return "/sys/block/" + devname;
}
bool DevDetect::checkUSB(const std::string& syspath) {
    std::string uevent = syspath + "/device/uevent";
    FILE* f = fopen(uevent.c_str(), "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f))
            if (strstr(line, "USB") || strstr(line, "usb")) { fclose(f); return true; }
        fclose(f);
    }
    char buf[256];
    ssize_t len = readlink(syspath.c_str(), buf, sizeof(buf)-1);
    if (len != -1) { buf[len] = '\0'; if (std::string(buf).find("usb") != std::string::npos) return true; }
    return false;
}
std::string DevDetect::readSpeed(const std::string& syspath) {
    FILE* f = fopen((syspath + "/device/speed").c_str(), "r");
    if (!f) return "";
    char speed[32];
    if (fgets(speed, sizeof(speed), f)) { speed[strcspn(speed, "\n")] = 0; fclose(f); return speed; }
    fclose(f);
    return "";
}
bool DevDetect::checkNVMe(const std::string& d) { return d.find("nvme") != std::string::npos; }
bool DevDetect::checkSD(const std::string& d) { return d.find("mmcblk") != std::string::npos; }
bool DevDetect::isRemovable(const std::string& syspath) {
    FILE* f = fopen((syspath + "/removable").c_str(), "r");
    if (f) { char r; if (fscanf(f, "%c", &r) == 1) { fclose(f); return r == '1'; } fclose(f); }
    return false;
}
DevType DevDetect::detect(const std::string& device) {
    std::string devname = device;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    if (checkNVMe(devname)) return DevType::NVME;
    if (checkSD(devname)) return DevType::SD_CARD;
    std::string syspath = getSysPath(device);
    if (checkUSB(syspath) || isRemovable(syspath)) {
        std::string speed = readSpeed(syspath);
        if (!speed.empty()) return atoi(speed.c_str()) >= 500 ? DevType::USB3 : DevType::USB2;
        return DevType::USB2;
    }
    FILE* f = fopen((syspath + "/queue/rotational").c_str(), "r");
    if (f) {
        char rot;
        if (fscanf(f, "%c", &rot) == 1) { fclose(f); return rot == '0' ? DevType::SSD_SATA : DevType::HDD; }
        fclose(f);
    }
    return DevType::UNKNOWN;
}

// ============================================
// FixedThCfg
// ============================================

FixedThCfg FixedThCfg::getConfigForSystem() {
    FixedThCfg config;
    int sys = HardwareDetect::getCoreCount();
    int avail = sys > 1 ? sys - 1 : sys;
    if (avail <= 2)      { config.io_threads = 1; config.crypto_threads = 1;          config.reserved_os = 0; }
    else if (avail <= 4) { config.io_threads = 1; config.crypto_threads = 2;          config.reserved_os = 1; }
    else if (avail <= 8) { config.io_threads = 2; config.crypto_threads = 5;          config.reserved_os = 1; }
    else if (avail <= 16){ config.io_threads = 3; config.crypto_threads = 11;         config.reserved_os = 2; }
    else if (avail <= 32){ config.io_threads = 4; config.crypto_threads = 24;         config.reserved_os = 4; }
    else                 { config.io_threads = 6; config.crypto_threads = avail - 8;  config.reserved_os = 2; }
    return config;
}

// ============================================
// ThCfg
// ============================================

ThCfg::ThCfg() : num_threads(HardwareDetect::getCoreCount()), chunk_size_mb(64), use_direct_io(true) {}

void ThCfg::applyFixedConfig(const FixedThCfg& f, DevType t) {
    num_threads = f.io_threads + f.crypto_threads + f.reserved_os;
    chunk_size_mb = DevDetect::getOptimalChunkMB(t);
    use_direct_io = DevDetect::useDirectIO(t);
}
void ThCfg::applyCustomConfig(const CustCfg& c) {
    num_threads = c.io_threads + c.crypto_threads;
    chunk_size_mb = c.buffer_size_mb;
    use_direct_io = c.use_direct_io;
}
void ThCfg::validate() {
    if (num_threads < MIN_THREADS) num_threads = MIN_THREADS;
    if (num_threads > MAX_THREADS) num_threads = MAX_THREADS;
    if (chunk_size_mb < 1) chunk_size_mb = 1;
    if (chunk_size_mb > 1024) chunk_size_mb = 1024;
    size_t bytes = chunk_size_mb * MB;
    if (bytes % ALIGNMENT != 0) chunk_size_mb = ((bytes + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT / MB;
}
size_t ThCfg::getChunkSize() const {
    size_t size = chunk_size_mb * MB;
    if (size % ALIGNMENT != 0) size = ((size + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
    return size;
}
std::string ThCfg::getDesc() const {
    std::stringstream ss;
    ss << num_threads << " hilos | Chunk: " << chunk_size_mb << "MB";
    if (use_direct_io) ss << " | I/O DIRECTO";
    return ss.str();
}

// ============================================
// SpeedMtr
// ============================================

SpeedMtr::SpeedMtr() { reset(); }
void SpeedMtr::addBytes(uint64_t b) { total_bytes += b; }
double SpeedMtr::getCurrentSpeed() {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_time).count();
    if (ms >= 200) {
        uint64_t cur = total_bytes.load();
        double speed = ((cur - last_bytes) / 1048576.0) / (ms / 1000.0);
        current_speed = speed;
        if (speed > peak_speed) peak_speed = speed;
        last_bytes = cur;
        last_time = now;
    }
    return current_speed.load();
}
double SpeedMtr::getAvgSpeed() {
    auto now = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
    return ms > 0 ? (total_bytes / 1048576.0) / (ms / 1000.0) : 0;
}
double SpeedMtr::getPeakSpeed() { return peak_speed.load(); }
uint64_t SpeedMtr::getTotalBytes() { return total_bytes.load(); }
void SpeedMtr::reset() {
    start_time = last_time = std::chrono::steady_clock::now();
    total_bytes = last_bytes = 0;
    current_speed = peak_speed = 0;
}

// ============================================
// HdrBackup
// ============================================

std::string HdrBackup::getBackupPath(const std::string& device_path) {
    std::string devname = device_path;
    if (devname.find("/dev/") == 0) devname = devname.substr(5);
    std::replace(devname.begin(), devname.end(), '/', '_');
    auto hash = Botan::HashFunction::create("SHA-256");
    hash->update(devname);
    std::string hashed = Botan::hex_encode(hash->final()).substr(0, 16);
    const char* xdg = getenv("XDG_DATA_HOME");
    std::string base;
    if (xdg && xdg[0]) base = std::string(xdg) + "/RUBIC-A/backups";
    else {
        const char* home = getenv("HOME");
        base = home && home[0] ? std::string(home) + "/.local/share/RUBIC-A/backups" : "/var/lib/rubic-a/backups";
    }
    std::filesystem::create_directories(base);
    std::filesystem::permissions(base, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
    return base + "/.rubic_" + hashed + ".dat";
}
Botan::secure_vector<uint8_t> HdrBackup::encryptBackup(const EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
    try {
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        if (!cipher) return {};
        Botan::secure_vector<uint8_t> data(sizeof(header));
        memcpy(data.data(), &header, sizeof(header));
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
    } catch (...) { return {}; }
}
bool HdrBackup::decryptBackup(const std::string& path, EncUnitHdr& header, const Botan::secure_vector<uint8_t>& key) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    Botan::secure_vector<uint8_t> enc;
    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    enc.resize(size);
    file.read(reinterpret_cast<char*>(enc.data()), size);
    file.close();
    if (enc.size() < 12 + 16) return false;
    try {
        auto cipher = Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        if (!cipher) return false;
        Botan::secure_vector<uint8_t> nonce(enc.begin(), enc.begin() + 12);
        Botan::secure_vector<uint8_t> ct(enc.begin() + 12, enc.end());
        cipher->set_key(key);
        cipher->start(nonce);
        cipher->finish(ct);
        if (ct.size() != sizeof(header)) return false;
        memcpy(&header, ct.data(), sizeof(header));
        return true;
    } catch (...) { return false; }
}
Botan::secure_vector<uint8_t> HdrBackup::deriveBackupKey(const std::string& device_path) {
    Botan::secure_vector<uint8_t> key(32);
    auto hash = Botan::HashFunction::create("SHA-512");
    if (!hash) return {};
    hash->update(device_path);
    auto digest = hash->final();
    for (size_t i = 0; i < 32; i++) key[i] = digest[i];
    return key;
}
bool HdrBackup::saveHeader(const std::string& dev, const EncUnitHdr& h, const Botan::secure_vector<uint8_t>&) {
    auto enc = encryptBackup(h, deriveBackupKey(dev));
    if (enc.empty()) return false;
    std::string path = getBackupPath(dev);
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;
    file.write(reinterpret_cast<const char*>(enc.data()), enc.size());
    file.close();
    chmod(path.c_str(), 0600);
    return true;
}
bool HdrBackup::loadHeader(const std::string& dev, EncUnitHdr& h, const Botan::secure_vector<uint8_t>&) {
    return decryptBackup(getBackupPath(dev), h, deriveBackupKey(dev));
}
bool HdrBackup::backupExists(const std::string& dev) {
    struct stat st;
    return stat(getBackupPath(dev).c_str(), &st) == 0;
}
bool HdrBackup::removeBackup(const std::string& dev) {
    return unlink(getBackupPath(dev).c_str()) == 0;
}

// ============================================
// StorUnit
// ============================================

std::string StorUnit::formatBytes(uint64_t bytes) {
    const char* s[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0; double d = bytes;
    while (d >= 1024.0 && i < 4) { d /= 1024.0; i++; }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << d << " " << s[i];
    return ss.str();
}
std::string StorUnit::getSafeFSType() const {
    if (strlen(fs_info.fstype) == 0) return "";
    for (size_t i = 0; i < strlen(fs_info.fstype); i++)
        if (!isprint(fs_info.fstype[i])) return "";
    return std::string(fs_info.fstype);
}

// ============================================
// KMACProc
// ============================================

KMACProc::KMACProc(const Botan::secure_vector<uint8_t>& key_data) {
    key = key_data;
    try {
        Kmac = Botan::MessageAuthenticationCode::create("KMAC-256(512)");
    } catch (...) {
        Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-3(512))");
        if (!Kmac) Kmac = Botan::MessageAuthenticationCode::create("HMAC(SHA-512)");
    }
    if (!Kmac) throw std::runtime_error("No se pudo crear el MAC criptográfico");
    Kmac->set_key(key);
}
Botan::secure_vector<uint8_t> KMACProc::calculate(const uint8_t* data, size_t size) {
    Kmac->update(data, size);
    return Kmac->final();
}
bool KMACProc::verify(const uint8_t* data, size_t size, const uint8_t* exp, size_t exp_size) {
    auto calc = calculate(data, size);
    if (calc.size() != exp_size) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < exp_size; i++) diff |= (calc[i] ^ exp[i]);
    return diff == 0;
}

// ============================================
// SIMDProc
// ============================================

void SIMDProc::xor_blocks(uint8_t* dst, const uint8_t* src, size_t blocks) {
    size_t total_bytes = blocks * 16;
    size_t i = 0;

#if defined(__AVX512F__)
    if (HardwareDetect::hasAVX512F() && total_bytes >= 64) {
        for (; i + 64 <= total_bytes; i += 64) {
            __m512i vd = _mm512_loadu_si512(reinterpret_cast<const void*>(dst + i));
            __m512i vs = _mm512_loadu_si512(reinterpret_cast<const void*>(src + i));
            _mm512_storeu_si512(reinterpret_cast<void*>(dst + i), _mm512_xor_si512(vd, vs));
        }
    }
#endif

#if defined(__AVX2__)
    if (HardwareDetect::hasAVX2() && total_bytes >= 32) {
        for (; i + 32 <= total_bytes; i += 32) {
            __m256i vd = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(dst + i));
            __m256i vs = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(src + i));
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst + i), _mm256_xor_si256(vd, vs));
        }
    }
#endif

    for (; i + 16 <= total_bytes; i += 16) {
        __m128i vd = _mm_loadu_si128(reinterpret_cast<const __m128i*>(dst + i));
        __m128i vs = _mm_loadu_si128(reinterpret_cast<const __m128i*>(src + i));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(dst + i), _mm_xor_si128(vd, vs));
    }

    for (; i < total_bytes; i++) dst[i] ^= src[i];
}

void SIMDProc::gf_mul_alpha(uint8_t t[16]) {
    uint64_t lo, hi;
    std::memcpy(&lo, t, 8);
    std::memcpy(&hi, t + 8, 8);
    const uint64_t carry_in  = lo >> 63;
    const uint64_t carry_out = hi >> 63;
    lo = lo << 1;
    hi = (hi << 1) | carry_in;
    if (carry_out) lo ^= 0x87ULL;
    std::memcpy(t, &lo, 8);
    std::memcpy(t + 8, &hi, 8);
}

// ============================================
// AESXTSProc
// ============================================

// verify_compat: test byte-a-byte contra Botan XTS.
// Zeroiza TODOS los buffers locales (pt, ours, all_tw, t0) antes de retornar.
bool AESXTSProc::verify_compat() {
    uint8_t pt[1024];
    uint8_t ours[1024];
    uint8_t all_tw[32 * 16];
    uint8_t t0[16];
    bool result = false;

    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> key(64);
        rng.randomize(key.data(), key.size());
        rng.randomize(pt, sizeof(pt));

        auto ref = Botan::Cipher_Mode::create("AES-256/XTS", Botan::Cipher_Dir::Encryption);
        if (ref) {
            ref->set_key(key);
            uint8_t iv[16] = {0};
            ref->start(iv, 16);
            Botan::secure_vector<uint8_t> ref_out(pt, pt + sizeof(pt));
            ref->finish(ref_out);

            auto k1 = Botan::BlockCipher::create("AES-256");
            auto k2 = Botan::BlockCipher::create("AES-256");
            if (k1 && k2) {
                Botan::secure_vector<uint8_t> k1v(key.begin(), key.begin() + 32);
                Botan::secure_vector<uint8_t> k2v(key.begin() + 32, key.end());
                k1->set_key(k1v);
                k2->set_key(k2v);

                std::memcpy(ours, pt, sizeof(pt));

                for (size_t s = 0; s < sizeof(pt) / SECTOR_SIZE; s++) {
                    uint64_t sn = s;
                    std::memset(t0, 0, 16);
                    std::memcpy(t0, &sn, 8);
                    k2->encrypt(t0, t0);

                    std::memcpy(all_tw, t0, 16);
                    for (int b = 1; b < 32; b++) {
                        std::memcpy(all_tw + b * 16, all_tw + (b - 1) * 16, 16);
                        SIMDProc::gf_mul_alpha(all_tw + b * 16);
                    }

                    uint8_t* sd = ours + s * SECTOR_SIZE;
                    SIMDProc::xor_blocks(sd, all_tw, 32);
                    k1->encrypt_n(sd, sd, 32);
                    SIMDProc::xor_blocks(sd, all_tw, 32);
                }

                result = std::memcmp(ref_out.data(), ours, sizeof(pt)) == 0;
            }
        }
    } catch (...) {
        result = false;
    }

    // Wipe incondicional (aunque haya excepción)
    rubic_sec::secure_wipe(pt,      sizeof(pt));
    rubic_sec::secure_wipe(ours,    sizeof(ours));
    rubic_sec::secure_wipe(all_tw,  sizeof(all_tw));
    rubic_sec::secure_wipe(t0,      sizeof(t0));
    return result;
}

AESXTSProc::AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt)
    : encrypt_mode_(encrypt), use_avx512_(false)
{
    if (key_data.size() == 32) {
        k1_ = key_data;
        k2_ = key_data;
    } else if (key_data.size() >= 64) {
        k1_.assign(key_data.begin(), key_data.begin() + 32);
        k2_.assign(key_data.begin() + 32, key_data.begin() + 64);
    } else {
        throw std::runtime_error("AESXTSProc: invalid key size");
    }

    aes_k1_ = Botan::BlockCipher::create("AES-256");
    aes_k2_ = Botan::BlockCipher::create("AES-256");
    if (!aes_k1_ || !aes_k2_)
        throw std::runtime_error("AESXTSProc: cannot create AES-256 BlockCipher");
    aes_k1_->set_key(k1_);
    aes_k2_->set_key(k2_);

    botan_xts_ = Botan::Cipher_Mode::create(
        "AES-256/XTS",
        encrypt ? Botan::Cipher_Dir::Encryption : Botan::Cipher_Dir::Decryption);
    if (!botan_xts_)
        throw std::runtime_error("AESXTSProc: cannot create AES-256/XTS Cipher_Mode");
    botan_xts_->set_key(key_data);

    // Scratch buffers (miembros, no pila)
    tweak_scratch_.resize(kTweakBytes);
    std::memset(t0_scratch_, 0, sizeof(t0_scratch_));

    static const bool verified = verify_compat();
    use_avx512_ = verified;
}

void AESXTSProc::scrub_scratch() noexcept {
    if (!tweak_scratch_.empty())
        rubic_sec::secure_wipe(tweak_scratch_.data(), tweak_scratch_.size());
    rubic_sec::secure_wipe(t0_scratch_, sizeof(t0_scratch_));
}

bool AESXTSProc::processBuffer(uint8_t* data, size_t size, uint64_t start_sector) {
    bool result = false;
    try {
        if (use_avx512_)
            result = processBuffer_avx512(data, size, start_sector);
        else
            result = processBuffer_botan(data, size, start_sector);
    } catch (...) {
        result = false;
    }
    scrub_scratch();  // wipe SIEMPRE, incluso en excepción
    return result;
}

bool AESXTSProc::processBuffer_avx512(uint8_t* data, size_t size, uint64_t start_sector) {
    const size_t num_sectors = size / SECTOR_SIZE;
    uint8_t* tw_base = tweak_scratch_.data();

    for (size_t batch_start = 0; batch_start < num_sectors; batch_start += kBatchSectors) {
        size_t batch_count = std::min<size_t>(kBatchSectors, num_sectors - batch_start);
        size_t batch_blocks = batch_count * kBlocksPerSector;

        for (size_t s = 0; s < batch_count; s++) {
            uint64_t sector_num = start_sector + batch_start + s;

            // t0 = AES_K2(sector || 0^8)   ← key-derived, se wipea al final
            std::memset(t0_scratch_, 0, 16);
            std::memcpy(t0_scratch_, &sector_num, 8);
            aes_k2_->encrypt(t0_scratch_, t0_scratch_);

            uint8_t* tw = tw_base + s * kBlocksPerSector * 16;
            std::memcpy(tw, t0_scratch_, 16);
            for (size_t b = 1; b < kBlocksPerSector; b++) {
                std::memcpy(tw + b * 16, tw + (b - 1) * 16, 16);
                SIMDProc::gf_mul_alpha(tw + b * 16);
            }
        }

        uint8_t* batch_data = data + batch_start * SECTOR_SIZE;

        // XOR whitening (AVX-512 real, 4 KB por batch)
        SIMDProc::xor_blocks(batch_data, tw_base, batch_blocks);

        // AES core (Botan: AES-NI o VAES-NI según CPU)
        if (encrypt_mode_)
            aes_k1_->encrypt_n(batch_data, batch_data, batch_blocks);
        else
            aes_k1_->decrypt_n(batch_data, batch_data, batch_blocks);

        SIMDProc::xor_blocks(batch_data, tw_base, batch_blocks);
    }
    return true;
}

bool AESXTSProc::processBuffer_botan(uint8_t* data, size_t size, uint64_t start_sector) {
    const size_t num_sectors = size / SECTOR_SIZE;
    for (size_t s = 0; s < num_sectors; s++) {
        uint64_t sector_num = start_sector + s;
        uint8_t tweak[16] = {0};  // solo [sector, 0×8] — NO es key-derived
        std::memcpy(tweak, &sector_num, 8);
        botan_xts_->start(tweak, 16);
        Botan::secure_vector<uint8_t> buf(data + s * SECTOR_SIZE,
                                          data + (s + 1) * SECTOR_SIZE);
        botan_xts_->finish(buf);
        std::memcpy(data + s * SECTOR_SIZE, buf.data(), SECTOR_SIZE);
        // buf es secure_vector → auto-scrub al final de la iteración
    }
    return true;
}

bool AESXTSProc::processSecBuf(SecBuf& buffer, uint64_t start_sector) {
    return processBuffer(buffer.data(), buffer.size(), start_sector);
}

// ============================================
// UnitEncryptor
// ============================================

UnitEncryptor::UnitEncryptor()
    : use_custom_config(false), last_refresh(0) {
    fixed_config = FixedThCfg::getConfigForSystem();
    std::string cfg = XDG::get_rubic_config_dir() + "/rubic_config.cfg";
    custom_config.loadFromFile(cfg);
    use_custom_config = custom_config.custom_mode;
    refreshUnits();
}

void UnitEncryptor::setDirectKeyHex(const std::string& hexKey) {
    try {
        Botan::secure_vector<uint8_t> k(32);
        for (size_t i = 0; i < 32 && i + 1 < hexKey.length(); i += 2)
            k[i/2] = static_cast<uint8_t>(std::stoul(hexKey.substr(i, 2), nullptr, 16));
        directKey = k;
        useDirectKey = true;
        keyManager = nullptr;
    } catch (...) { useDirectKey = false; }
}

bool UnitEncryptor::hasKey() const {
    if (useDirectKey) return !directKey.empty();
    return keyManager && !keyManager->getActiveKeys().empty();
}

void UnitEncryptor::refreshUnits() {
    if (time(nullptr) - last_refresh > 2) {
        cached_units = detectUnits();
        last_refresh = time(nullptr);
    }
}

bool UnitEncryptor::isPhysicalDevice(const std::string& p) {
    return p.find("/dev/loop") == std::string::npos && p.find("/dev/ram") == std::string::npos;
}

std::string UnitEncryptor::getParentDevice(const std::string& path) {
    std::string dev = path;
    if (dev.find("/dev/") == 0) dev = dev.substr(5);
    if (dev.find("nvme") == 0) {
        size_t p = dev.find('p');
        return "/dev/" + (p != std::string::npos ? dev.substr(0, p) : dev);
    }
    size_t p = dev.find_first_of("0123456789");
    return p != std::string::npos ? "/dev/" + dev.substr(0, p) : "";
}

bool UnitEncryptor::isSystemDisk(const std::string& path) {
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev, mnt;
            iss >> dev >> mnt;
            if (mnt == "/") return path == dev;
        }
    }
    return false;
}

FSInfo UnitEncryptor::getFileSystemInfo(const std::string& path) {
    FSInfo info;
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fs;
        iss >> dev >> mnt >> fs;
        if (dev == path) {
            strncpy(info.fstype, fs.c_str(), sizeof(info.fstype) - 1);
            return info;
        }
    }
    std::string out = exec_cmd_output({"blkid", "-o", "value", "-s", "TYPE", path});
    if (!out.empty()) strncpy(info.fstype, out.c_str(), sizeof(info.fstype) - 1);
    out = exec_cmd_output({"blkid", "-o", "value", "-s", "LABEL", path});
    if (!out.empty()) strncpy(info.label, out.c_str(), sizeof(info.label) - 1);
    return info;
}

bool UnitEncryptor::isUnitEncrypted(const std::string& device_path) {
    int fd = open(device_path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    EncUnitHdr hdr;
    ssize_t r = pread(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    close(fd);
    return r == sizeof(hdr) && hdr.isValid();
}

bool UnitEncryptor::readHeaderFromDevice(int fd, EncUnitHdr& hdr) {
    ssize_t r = pread(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    return r == sizeof(hdr) && hdr.isValid();
}

bool UnitEncryptor::writeHeaderToDevice(int fd, const EncUnitHdr& hdr) {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) return false;
    bool direct = flags & O_DIRECT;
    if (direct) fcntl(fd, F_SETFL, flags & ~O_DIRECT);
    ssize_t w = pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    if (direct) fcntl(fd, F_SETFL, flags);
    return w == sizeof(hdr);
}

std::vector<StorUnit> UnitEncryptor::detectUnits() {
    std::vector<StorUnit> units;
    std::map<std::string, StorUnit> uniq;
    std::set<std::string> seen;

    std::string root_dev;
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line)) {
        if (line.find(" / ") != std::string::npos) {
            std::istringstream iss(line);
            std::string dev; iss >> dev;
            root_dev = dev;
            break;
        }
    }

    mounts.clear(); mounts.seekg(0);
    while (std::getline(mounts, line)) {
        std::istringstream iss(line);
        std::string dev, mnt, fs;
        iss >> dev >> mnt >> fs;
        if (dev.find("/dev/") != 0 || !isPhysicalDevice(dev)) continue;

        StorUnit u;
        u.device_path = dev;
        u.mount_point = mnt;
        u.filesystem = fs;
        u.is_mounted = true;
        u.is_partition = dev.find_first_of("0123456789") != std::string::npos;
        u.parent_device = getParentDevice(dev);
        u.is_system_disk = dev == root_dev;

        std::string devname = std::filesystem::path(dev).filename().string();
        std::ifstream sf("/sys/class/block/" + devname + "/size");
        uint64_t sectors = 0;
        if (sf >> sectors) u.total_size = sectors * 512ULL;

        int fd = open(dev.c_str(), O_RDONLY);
        if (fd >= 0) {
            u.is_encrypted = isUnitEncrypted(dev);
            u.fs_info = getFileSystemInfo(dev);
            u.label = u.fs_info.label;
            close(fd);
        } else if (errno == EACCES || errno == EPERM) {
            u.requires_elevation = true;
        }
        u.device_type = DevDetect::detect(dev);
        u.has_header_backup = backup_mgr.backupExists(dev);

        uniq[dev] = u;
        seen.insert(dev);
    }

    DIR* d = opendir("/dev");
    if (d) {
        struct dirent* e;
        while ((e = readdir(d))) {
            std::string name = e->d_name;
            std::string dev = "/dev/" + name;
            if ((name.find("sd") == 0 || name.find("hd") == 0 ||
                 name.find("nvme") == 0 || name.find("mmcblk") == 0) &&
                !seen.count(dev) && isPhysicalDevice(dev)) {
                bool is_part = name.find_first_of("0123456789") != std::string::npos;
                if (!is_part) {
                    bool has_parts = false;
                    for (auto& p : uniq)
                        if (p.second.parent_device == dev) { has_parts = true; break; }
                    if (has_parts) continue;
                }
                StorUnit u;
                u.device_path = dev;
                u.is_partition = is_part;
                u.parent_device = getParentDevice(dev);
                u.is_system_disk = dev == root_dev;

                std::string devname = std::filesystem::path(dev).filename().string();
                std::ifstream sf("/sys/class/block/" + devname + "/size");
                uint64_t sectors = 0;
                if (sf >> sectors) u.total_size = sectors * 512ULL;

                if (u.total_size > 0) {
                    int fd = open(dev.c_str(), O_RDONLY);
                    if (fd >= 0) {
                        u.is_encrypted = isUnitEncrypted(dev);
                        u.fs_info = getFileSystemInfo(dev);
                        u.label = u.fs_info.label;
                        close(fd);
                    } else if (errno == EACCES || errno == EPERM) {
                        u.requires_elevation = true;
                    }
                    u.device_type = DevDetect::detect(dev);
                    u.has_header_backup = backup_mgr.backupExists(dev);
                    uniq[dev] = u;
                }
            }
        }
        closedir(d);
    }

    units.reserve(uniq.size());
    for (auto& p : uniq) units.push_back(p.second);
    std::sort(units.begin(), units.end(), [](const StorUnit& a, const StorUnit& b) {
        if (a.is_system_disk != b.is_system_disk) return a.is_system_disk > b.is_system_disk;
        return a.total_size > b.total_size;
    });
    return units;
}

bool UnitEncryptor::unmount(StorUnit& u) {
    if (!u.is_mounted) return true;
    log(LogLevel::Info, LogEvent::Unmounting, u.mount_point);
    safe_exec({"umount", "-l", u.mount_point});
    std::ifstream mounts("/proc/mounts");
    std::string line;
    while (std::getline(mounts, line))
        if (line.find(u.device_path) != std::string::npos) return false;
    u.is_mounted = false;
    u.mount_point.clear();
    log(LogLevel::Success, LogEvent::Unmounted, "");
    return true;
}

bool UnitEncryptor::mount(const StorUnit& u, const std::string& point) {
    log(LogLevel::Info, LogEvent::Mounting, point);
    safe_exec({"mkdir", "-p", point});
    std::string fs = u.filesystem;
    if (fs.empty() && strlen(u.fs_info.fstype) > 0) fs = u.getSafeFSType();
    int ret = fs.empty()
        ? safe_exec({"mount", u.device_path, point})
        : safe_exec({"mount", "-t", fs, u.device_path, point});
    if (ret == 0) { log(LogLevel::Success, LogEvent::Mounted, point); return true; }
    log(LogLevel::Error, LogEvent::MountFailed, std::to_string(ret));
    return false;
}

std::vector<StorUnit> UnitEncryptor::getUnits() { refreshUnits(); return cached_units; }
void UnitEncryptor::refresh() { cached_units = detectUnits(); last_refresh = time(nullptr); }

void UnitEncryptor::reloadCustomConfig() {
    custom_config.loadFromFile(XDG::get_rubic_config_dir() + "/rubic_config.cfg");
    use_custom_config = custom_config.custom_mode;
}

bool UnitEncryptor::tryElevatedProcess(const StorUnit& unit, bool encrypt,
                                        const Botan::secure_vector<uint8_t>& master_key) {
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string("pipe: ") + strerror(errno));
        return false;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, std::string("fork: ") + strerror(errno));
        return false;
    }
    if (pid == 0) {
        close(pipefd[1]);
        if (pipefd[0] != 3) { dup2(pipefd[0], 3); close(pipefd[0]); }
        int flags = fcntl(3, F_GETFD);
        if (flags >= 0) fcntl(3, F_SETFD, flags & ~FD_CLOEXEC);
        char exe[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (n <= 0) _exit(127);
        exe[n] = '\0';
        execlp("sudo", "sudo", "--preserve-fds=1",
               exe, "--unit-op", unit.device_path.c_str(),
               encrypt ? "encrypt" : "decrypt", nullptr);
        _exit(127);
    }
    close(pipefd[0]);
    uint32_t len = static_cast<uint32_t>(master_key.size());
    bool ok = (write(pipefd[1], &len, sizeof(len)) == (ssize_t)sizeof(len))
           && (write(pipefd[1], master_key.data(), len) == (ssize_t)len);
    close(pipefd[1]);
    int status = 0;
    waitpid(pid, &status, 0);
    if (!ok) { log(LogLevel::Error, LogEvent::MasterKeyInvalid, "write pipe"); return false; }
    if (!WIFEXITED(status)) { log(LogLevel::Error, LogEvent::ProcessingFailed, "killed"); return false; }
    int rc = WEXITSTATUS(status);
    if (rc == 127) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, "sudo missing"); return false; }
    if (rc != 0) { log(LogLevel::Error, LogEvent::ProcessingFailed, "rc=" + std::to_string(rc)); return false; }
    return true;
}

bool UnitEncryptor::processUnit(StorUnit& unit, bool encrypt,
                                 const Botan::secure_vector<uint8_t>& master_key) {
    if (geteuid() != 0) {
        bool ok = tryElevatedProcess(unit, encrypt, master_key);
        if (ok) {
            unit.is_encrypted = encrypt;
            unit.has_header_backup = encrypt;
            refreshUnits();
        }
        return ok;
    }
    if (encrypt && unit.is_encrypted)   { log(LogLevel::Warning, LogEvent::UnitAlreadyEncrypted, ""); return false; }
    if (!encrypt && !unit.is_encrypted) { log(LogLevel::Warning, LogEvent::UnitNotEncrypted, "");     return false; }
    if (unit.is_system_disk)            { log(LogLevel::Error, LogEvent::SystemDiskBlocked, "");      return false; }
    if (unit.is_mounted)                { log(LogLevel::Warning, LogEvent::UnitMounted, unit.mount_point); return false; }
    if (master_key.empty() || master_key.size() != 32) {
        log(LogLevel::Error, LogEvent::MasterKeyInvalid, "");
        return false;
    }
    stop_requested = false;
    processing_active = true;
    speed_meter.reset();
    stats = Stats();
    auto t0 = std::chrono::high_resolution_clock::now();
    bool ok = doProcess(unit, master_key, encrypt);
    auto t1 = std::chrono::high_resolution_clock::now();
    processing_active = false;
    if (ok) {
        stats.total_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
        stats.total_bytes = speed_meter.getTotalBytes();
        stats.avg_speed_mbps = speed_meter.getAvgSpeed();
        stats.peak_speed_mbps = speed_meter.getPeakSpeed();
        unit.is_encrypted = encrypt;
        unit.has_header_backup = encrypt;
        refreshUnits();
    }
    return ok;
}

bool UnitEncryptor::doProcess(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key, bool encrypt) {
    ThCfg cfg;
    if (use_custom_config && custom_config.custom_mode) cfg.applyCustomConfig(custom_config);
    else cfg.applyFixedConfig(fixed_config, unit.device_type);
    cfg.validate();

    log(LogLevel::Info, LogEvent::DeviceTypeDetected, unit.getDevTypeStr());
    log(LogLevel::Info,
        (use_custom_config && custom_config.custom_mode) ? LogEvent::ConfigCustom : LogEvent::ConfigAuto,
        std::to_string(cfg.num_threads) + " threads");
    log(LogLevel::Info, LogEvent::ChunkSizeInfo, std::to_string(cfg.chunk_size_mb));
    log(LogLevel::Info, LogEvent::IoModeInfo, cfg.use_direct_io ? "direct" : "normal");

    int flags = O_RDWR | O_SYNC;
    if (cfg.use_direct_io) flags |= O_DIRECT;
    int fd = open(unit.device_path.c_str(), flags);
    if (fd < 0) {
        log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno));
        if (cfg.use_direct_io && errno == EINVAL) {
            log(LogLevel::Warning, LogEvent::DeviceOpenRetry, "sin O_DIRECT");
            flags &= ~O_DIRECT;
            fd = open(unit.device_path.c_str(), flags);
            if (fd < 0) return false;
            cfg.use_direct_io = false;
        } else return false;
    }

    uint64_t total_size = 0;
    if (ioctl(fd, BLKGETSIZE64, &total_size) < 0) {
        log(LogLevel::Error, LogEvent::DeviceSizeFailed, strerror(errno));
        close(fd);
        return false;
    }
    uint64_t total_sectors = total_size / SECTOR_SIZE;
    uint64_t data_start_sector = DATA_OFFSET_SECTORS;
    uint64_t data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;

    Botan::secure_vector<uint8_t> kdf_salt, xts_key;
    FSInfo fs_info = unit.fs_info;

    if (encrypt) {
        log(LogLevel::Info, LogEvent::SaltGenerating, "");
        kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
        if (kdf_salt.empty()) { log(LogLevel::Error, LogEvent::SaltError, ""); close(fd); return false; }
        log(LogLevel::Info, LogEvent::KeyDeriving, "");
        xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
        if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); close(fd); return false; }
        log(LogLevel::Success, LogEvent::KeyDerived, "");
        if (strlen(fs_info.fstype) == 0) fs_info = getFileSystemInfo(unit.device_path);

        EncUnitHdr hdr{};
        memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
        hdr.version = HEADER_VERSION_CURRENT;
        hdr.data_start_sector = data_start_sector;
        hdr.total_sectors = total_sectors;
        hdr.fs_info = fs_info;

        log(LogLevel::Info, LogEvent::KmacCalculating, "");
        try {
            KMACProc Kmac(master_key);
            auto m = Kmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac));
            if (m.size() == KMAC_SIZE) memcpy(hdr.Kmac, m.data(), KMAC_SIZE);
            else { log(LogLevel::Error, LogEvent::KmacError, "size"); close(fd); return false; }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            close(fd);
            return false;
        }
        if (backup_mgr.saveHeader(unit.device_path, hdr, master_key))
            log(LogLevel::Success, LogEvent::BackupSaved, "");
        else
            log(LogLevel::Warning, LogEvent::BackupSaveFailed, "");

        log(LogLevel::Info, LogEvent::HeaderWriting, "");
        if (!writeHeaderToDevice(fd, hdr)) {
            log(LogLevel::Error, LogEvent::HeaderWriting, strerror(errno));
            close(fd);
            return false;
        }
        fsync(fd);
        log(LogLevel::Success, LogEvent::HeaderWritten, "");
    } else {
        EncUnitHdr hdr;
        log(LogLevel::Info, LogEvent::HeaderVerified, "reading");
        if (!readHeaderFromDevice(fd, hdr)) {
            log(LogLevel::Warning, LogEvent::HeaderReadFailed, "intentando backup");
            if (backup_mgr.loadHeader(unit.device_path, hdr, master_key))
                log(LogLevel::Success, LogEvent::BackupLoaded, "");
            else {
                log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
                close(fd);
                return false;
            }
        }
        if (hdr.version < 2) {
            log(LogLevel::Warning, LogEvent::KeyDerived, "version<2 sin KDF");
            xts_key.resize(64);
            memcpy(xts_key.data(), master_key.data(), 32);
            memcpy(xts_key.data() + 32, master_key.data(), 32);
        } else {
            log(LogLevel::Info, LogEvent::KeyDeriving, "");
            kdf_salt.resize(KDF_SALT_SIZE);
            memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
            xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
            if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); close(fd); return false; }
            log(LogLevel::Success, LogEvent::KeyDerived, "");
        }
        log(LogLevel::Info, LogEvent::KmacCalculating, "verificando");
        try {
            KMACProc Kmac(master_key);
            if (!Kmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac), hdr.Kmac, KMAC_SIZE)) {
                log(LogLevel::Error, LogEvent::KmacFailed, "");
                close(fd);
                return false;
            }
        } catch (const std::exception& e) {
            log(LogLevel::Error, LogEvent::KmacError, e.what());
            close(fd);
            return false;
        }
        log(LogLevel::Success, LogEvent::KmacVerified, "");
        fs_info = hdr.fs_info;
        data_start_sector = hdr.data_start_sector;
        data_size = (total_sectors - data_start_sector) * SECTOR_SIZE;
    }

    log(LogLevel::Info, LogEvent::DataSizeInfo, std::to_string(data_size));
    size_t chunk_size = cfg.getChunkSize();
    uint64_t total_chunks = (data_size + chunk_size - 1) / chunk_size;
    log(LogLevel::Info, LogEvent::ChunkCountInfo, std::to_string(total_chunks));

    LimQueue<PipeChunk> read_q(MAX_QUEUE_SIZE), write_q(MAX_QUEUE_SIZE);
    std::atomic<uint64_t> done{0}, bytes_done{0};
    std::atomic<bool> err{false};

    // Buffers de chunk: encriptación → quedan con ciphertext, no scrub.
    //                    desencriptación → quedan con plaintext, scrub on destroy.
    const bool scrub_chunks = !encrypt;

    std::thread reader([&]() {
        for (uint64_t c = 0; c < total_chunks && !err && !stop_requested; c++) {
            PipeChunk chunk(chunk_size, cfg.use_direct_io);
            chunk.data->set_scrub_on_destroy(scrub_chunks);  // ← plaintext wipe
            chunk.index = c;
            chunk.offset = data_start_sector * SECTOR_SIZE + c * chunk_size;
            chunk.size = std::min<uint64_t>(chunk_size, total_size - chunk.offset);
            chunk.start_sector = chunk.offset / SECTOR_SIZE;
            if (pread(fd, chunk.data->data(), chunk.size, chunk.offset) != (ssize_t)chunk.size) {
                log(LogLevel::Error, LogEvent::ChunkReadError, std::to_string(c));
                err = true;
                break;
            }
            read_q.push(std::move(chunk));
        }
        read_q.close();
    });

    int ncpu = (use_custom_config && custom_config.custom_mode)
                   ? custom_config.crypto_threads
                   : fixed_config.crypto_threads;
    std::vector<std::thread> workers;
    workers.reserve(ncpu);
    for (int t = 0; t < ncpu; t++) {
        workers.emplace_back([&]() {
            AESXTSProc proc(xts_key, encrypt);
            if (!proc.used_avx512())
                log(LogLevel::Warning, LogEvent::XtsFallback, "Botan XTS (AVX-512 self-test failed)");
            PipeChunk chunk(chunk_size, cfg.use_direct_io);
            while (read_q.pop(chunk) && !err && !stop_requested) {
                if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                    log(LogLevel::Error, LogEvent::ChunkProcessError, std::to_string(chunk.index));
                    err = true;
                    break;
                }
                write_q.push(std::move(chunk));
                chunk = PipeChunk(chunk_size, cfg.use_direct_io);
            }
        });
    }

    std::thread writer([&]() {
        PipeChunk chunk(chunk_size, cfg.use_direct_io);
        uint64_t expected = 0;
        std::vector<PipeChunk> reorder;
        while (!err && !stop_requested && expected < total_chunks) {
            if (!write_q.pop(chunk)) break;
            if (chunk.index == expected) {
                if (pwrite(fd, chunk.data->data(), chunk.size, chunk.offset) != (ssize_t)chunk.size) {
                    log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(chunk.index));
                    err = true;
                    break;
                }
                done++;
                bytes_done += chunk.size;
                speed_meter.addBytes(chunk.size);
                progress(bytes_done.load(), data_size, speed_meter.getCurrentSpeed());
                expected++;
                int flush = (unit.device_type == DevType::HDD || unit.device_type == DevType::USB2) ? 2 : 1;
                if (chunk.index % flush == 0) fsync(fd);
                for (auto it = reorder.begin(); it != reorder.end(); ) {
                    if (it->index == expected) {
                        if (pwrite(fd, it->data->data(), it->size, it->offset) != (ssize_t)it->size) {
                            err = true; break;
                        }
                        done++;
                        bytes_done += it->size;
                        speed_meter.addBytes(it->size);
                        progress(bytes_done.load(), data_size, speed_meter.getCurrentSpeed());
                        expected++;
                        it = reorder.erase(it);
                    } else ++it;
                }
            } else if (chunk.index > expected) {
                reorder.push_back(std::move(chunk));
                chunk = PipeChunk(chunk_size, cfg.use_direct_io);
            }
        }
        write_q.close();
    });

    while (!err && !stop_requested && done < total_chunks)
        std::this_thread::sleep_for(std::chrono::milliseconds(PROGRESS_UPDATE_MS));

    read_q.close();
    write_q.close();
    if (reader.joinable()) reader.join();
    for (auto& t : workers) if (t.joinable()) t.join();
    if (writer.joinable()) writer.join();
    fsync(fd);

    if (!encrypt && !err && !stop_requested) {
        log(LogLevel::Info, LogEvent::CleanupHeader, "");
        size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
        std::vector<uint8_t> zeros(hsz, 0);
        if (pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE) == (ssize_t)hsz) {
            fsync(fd);
            log(LogLevel::Success, LogEvent::HeaderRemoved, "");
        }
        if (backup_mgr.removeBackup(unit.device_path))
            log(LogLevel::Success, LogEvent::BackupRemoved, "");
    }
    close(fd);

    stats.total_bytes = bytes_done.load();
    if (err) log(LogLevel::Error, LogEvent::ProcessingFailed, "");
    else if (stop_requested) log(LogLevel::Warning, LogEvent::ProcessingStopped, "");
    else log(LogLevel::Success, LogEvent::ProcessingComplete, "");

    return !err && done == total_chunks && !stop_requested;
}

bool UnitEncryptor::cleanHeader(const StorUnit& unit) {
    log(LogLevel::Info, LogEvent::CleanupHeader, unit.device_path);
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); return false; }
    size_t hsz = HEADER_SECTORS * SECTOR_SIZE;
    std::vector<uint8_t> zeros(hsz, 0);
    ssize_t w = pwrite(fd, zeros.data(), hsz, HEADER_OFFSET_SECTORS * SECTOR_SIZE);
    fsync(fd);
    close(fd);
    if (w != (ssize_t)hsz) { log(LogLevel::Error, LogEvent::HeaderCleanFailed, ""); return false; }
    log(LogLevel::Success, LogEvent::HeaderRemoved, "");
    if (backup_mgr.backupExists(unit.device_path) && backup_mgr.removeBackup(unit.device_path))
        log(LogLevel::Success, LogEvent::BackupRemoved, "");
    return true;
}

bool UnitEncryptor::restoreHeader(const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key) {
    log(LogLevel::Info, LogEvent::HeaderRestoring, "");
    EncUnitHdr hdr;
    if (!backup_mgr.loadHeader(unit.device_path, hdr, master_key)) {
        log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
        return false;
    }
    int fd = open(unit.device_path.c_str(), O_RDWR | O_SYNC);
    if (fd < 0) { log(LogLevel::Error, LogEvent::DeviceOpenFailed, strerror(errno)); return false; }
    if (!writeHeaderToDevice(fd, hdr)) {
        log(LogLevel::Error, LogEvent::HeaderRestoreFailed, "");
        close(fd);
        return false;
    }
    close(fd);
    log(LogLevel::Success, LogEvent::HeaderRestored, "");
    return true;
}

bool UnitEncryptor::formatUnit(const StorUnit& unit, const std::string& fstype) {
    log(LogLevel::Info, LogEvent::FormatStart, unit.device_path + ":" + fstype);
    int res = -1;
    if (fstype == "vfat" || fstype == "fat32")
        res = safe_exec({"mkfs.vfat", "-F", "32", unit.device_path});
    else if (fstype == "ntfs")
        res = safe_exec({"mkfs.ntfs", "-f", unit.device_path});
    else if (fstype == "ext4")
        res = safe_exec({"mkfs.ext4", "-F", unit.device_path});
    else
        res = safe_exec({"mkfs." + fstype, unit.device_path});
    if (res == 0) { log(LogLevel::Success, LogEvent::FormatOk, ""); return true; }
    log(LogLevel::Error, LogEvent::FormatFailed, std::to_string(res));
    return false;
}