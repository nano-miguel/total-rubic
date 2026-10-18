// cipher/universal_cipher.h - 0.1 alpha
#ifndef CIPHER_UNIVERSAL_CIPHER_H
#define CIPHER_UNIVERSAL_CIPHER_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <atomic>
#include <queue>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <future>
#include <memory>
#include <functional>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <termios.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h>
#include <random>
#include <filesystem>
#include <algorithm>
#include <limits>
#include <array>
#include <map>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <deque>
#include <list>
#include <fcntl.h>
#include <errno.h>
#include <csignal>
#include <botan/auto_rng.h>
#include <botan/secmem.h>
#include <botan/hex.h>
#include <botan/hash.h>
#include <botan/aead.h>
#include <botan/stream_cipher.h>
#include <botan/cipher_mode.h>
#include <botan/version.h>
#include <botan/base64.h>
#include <botan/system_rng.h>
#include <botan/mac.h>
#include <botan/pwdhash.h>

#include "../hardware_detect.h"

class KeyManager;

namespace univ_log {
enum class LogLevel { Info, Warning, Error, Success, Progress };
enum class LogEvent {
    PathInvalid, NoFilesFound, NoFilesToProcess, ProcessingSingle,
    FileDone, FileError, FileMoveError, ScanError,
    NoKeyManager, KeyNotFound, KeyNotActive, KeyValueError, KeyLengthError,
    CountersError
};
}

class UserPermissions {
  public:
    static void fixFilePermissions(const std::string& path) {
        const char* sudo_uid = getenv("SUDO_UID");
        uid_t uid = sudo_uid ? static_cast<uid_t>(std::stoul(sudo_uid)) : getuid();
        const char* sudo_gid = getenv("SUDO_GID");
        gid_t gid = sudo_gid ? static_cast<gid_t>(std::stoul(sudo_gid)) : getgid();

        if (chown(path.c_str(), uid, gid) == -1) {}
        chmod(path.c_str(), S_IRUSR | S_IWUSR);
    }
};

class FileRAII {
  private:
    int fd;
    std::string path;
    bool is_open;
  public:
    FileRAII() : fd(-1), is_open(false) {}
    explicit FileRAII(const std::string& file_path, int flags, mode_t mode = 0644)
        : fd(-1), path(file_path), is_open(false) {
        open(file_path, flags, mode);
    }
    ~FileRAII() { close(); }
    bool open(const std::string& file_path, int flags, mode_t mode = 0644) {
        if (is_open) close();
        fd = ::open(file_path.c_str(), flags, mode);
        if (fd >= 0) { is_open = true; path = file_path; }
        return is_open;
    }
    void close() {
        if (is_open && fd >= 0) { ::close(fd); fd = -1; is_open = false; }
    }
    int get() const { return fd; }
    bool valid() const { return is_open && fd >= 0; }
    FileRAII(FileRAII&& other) noexcept : fd(other.fd), path(std::move(other.path)), is_open(other.is_open) {
        other.fd = -1; other.is_open = false;
    }
    FileRAII& operator=(FileRAII&& other) noexcept {
        if (this != &other) {
            close(); fd = other.fd; path = std::move(other.path); is_open = other.is_open;
            other.fd = -1; other.is_open = false;
        }
        return *this;
    }
    FileRAII(const FileRAII&) = delete;
    FileRAII& operator=(const FileRAII&) = delete;
};

class MMapRAII {
  private:
    void* data;
    size_t size;
    int fd;
    bool is_mapped;
  public:
    MMapRAII() : data(nullptr), size(0), fd(-1), is_mapped(false) {}
    ~MMapRAII() { unmap(); }
    bool map(int file_fd, size_t file_size, int prot = PROT_READ, int flags = MAP_PRIVATE) {
        if (is_mapped) unmap();
        data = mmap(nullptr, file_size, prot, flags, file_fd, 0);
        if (data == MAP_FAILED) { data = nullptr; return false; }
        size = file_size; fd = file_fd; is_mapped = true;
        madvise(data, size, MADV_SEQUENTIAL);
        return true;
    }
    void unmap() {
        if (is_mapped && data && data != MAP_FAILED) { munmap(data, size); data = nullptr; is_mapped = false; }
    }
    void* get() const { return data; }
    size_t get_size() const { return size; }
    bool valid() const { return is_mapped && data && data != MAP_FAILED; }
    MMapRAII(MMapRAII&& other) noexcept : data(other.data), size(other.size), fd(other.fd), is_mapped(other.is_mapped) {
        other.data = nullptr; other.is_mapped = false;
    }
    MMapRAII& operator=(MMapRAII&& other) noexcept {
        if (this != &other) {
            unmap(); data = other.data; size = other.size; fd = other.fd; is_mapped = other.is_mapped;
            other.data = nullptr; other.is_mapped = false;
        }
        return *this;
    }
    MMapRAII(const MMapRAII&) = delete;
    MMapRAII& operator=(const MMapRAII&) = delete;
};

class MemoryLockRAII {
  private:
    void* ptr;
    size_t size;
    bool locked;
  public:
    MemoryLockRAII(void* memory_ptr, size_t memory_size) : ptr(memory_ptr), size(memory_size), locked(false) { lock(); }
    ~MemoryLockRAII() { unlock(); }
    bool lock() {
        if (locked || !ptr || size == 0) return false;
#ifdef __unix__
        if (mlock(ptr, size) == 0) { locked = true; return true; }
#endif
        return false;
    }
    void unlock() {
        if (locked && ptr && size > 0) {
#ifdef __unix__
            munlock(ptr, size);
#endif
            locked = false;
        }
    }
    MemoryLockRAII(const MemoryLockRAII&) = delete;
    MemoryLockRAII& operator=(const MemoryLockRAII&) = delete;
};

struct ThreadCfg {
    size_t total_system_threads;
    size_t crypto_threads;
    size_t io_threads;
    size_t reserved_os;

    static ThreadCfg getConfig(size_t system_threads) {
        ThreadCfg config;
        config.total_system_threads = system_threads;
        if (system_threads <= 2) { config.io_threads = 1; config.crypto_threads = 1; config.reserved_os = 0; }
        else if (system_threads <= 4) { config.io_threads = 1; config.crypto_threads = 2; config.reserved_os = 1; }
        else if (system_threads == 6) { config.io_threads = 2; config.crypto_threads = 3; config.reserved_os = 1; }
        else if (system_threads <= 8) { config.io_threads = 2; config.crypto_threads = 5; config.reserved_os = 1; }
        else if (system_threads <= 16) { config.io_threads = 3; config.crypto_threads = 11; config.reserved_os = 2; }
        else if (system_threads <= 32) { config.io_threads = 4; config.crypto_threads = 24; config.reserved_os = 4; }
        else { config.io_threads = 6; config.crypto_threads = system_threads - 8; config.reserved_os = 2; }
        return config;
    }
};

struct SystemConfig {
    ThreadCfg thread_config;
    size_t min_buffer_size = 512 * 1024;
    size_t max_buffer_size = 8 * 1024 * 1024;
    size_t optimal_buffer_size = 2 * 1024 * 1024;
    size_t queue_size = 64;
    size_t max_files_per_second = 1000;
    size_t max_bytes_per_second = 1024 * 1024 * 1024;
    bool verify_integrity = true;
    bool use_hardware_rng = true;
    size_t nonce_size = 12;
    bool use_header_mac = true;
    bool show_progress = true;
    bool show_detailed_stats = false;
    uint64_t max_file_size = std::numeric_limits<uint64_t>::max();
    std::string output_extension = ".enc";
    size_t name_cache_size = 1024;
    size_t max_retries = 3;
    size_t retry_delay_ms = 100;
    static constexpr size_t GCM_TAG_SIZE = 16;
    size_t max_parallel_files = 4;
    size_t mmap_threshold = 1024 * 1024;
    std::string counter_file_path = ".cipher_counters.dat";
    std::string name_key_file_path = ".cipher_namekey.dat";

    size_t get_dynamic_buffer_size(uint64_t file_size) const {
        if (file_size < 1024 * 1024) return min_buffer_size;
        if (file_size < 10 * 1024 * 1024) return optimal_buffer_size;
        return max_buffer_size;
    }
    bool should_use_mmap(uint64_t file_size) const { return file_size >= mmap_threshold; }
    void autoConfigure(size_t system_threads) {
        thread_config = ThreadCfg::getConfig(system_threads);
        queue_size = thread_config.crypto_threads * 8;
        max_parallel_files = thread_config.crypto_threads;
    }
};

class ConstantTime {
  public:
    static bool compare(const uint8_t* a, const uint8_t* b, size_t len) {
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
};

class SecMemGuard {
  public:
    static bool lock_memory(void* ptr, size_t size) {
        if (ptr && size > 0) { MemoryLockRAII lock(ptr, size); return lock.lock(); }
        return false;
    }
    static void secure_memset(void* ptr, int value, size_t num) {
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (num--) *p++ = static_cast<unsigned char>(value);
    }
};

class SecureRandom {
  private:
    static Botan::AutoSeeded_RNG& getBotanRNG() { static Botan::AutoSeeded_RNG rng; return rng; }
    static Botan::System_RNG& getHardwareRNG() { static Botan::System_RNG rng; return rng; }
    inline static bool use_hardware = true;
  public:
    static void setUseHardware(bool use) { use_hardware = use; }
    static void generate_bytes(uint8_t* data, size_t size) {
        if (use_hardware) getHardwareRNG().randomize(data, size);
        else getBotanRNG().randomize(data, size);
    }
    static Botan::secure_vector<uint8_t> secure_random(size_t size) {
        Botan::secure_vector<uint8_t> result(size);
        generate_bytes(result.data(), size);
        return result;
    }
    static uint64_t random_uint64() {
        uint64_t value;
        generate_bytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        return value;
    }
};

class HeaderKMAC {
  private:
    Botan::secure_vector<uint8_t> mac_key;
  public:
    HeaderKMAC() = default;
    void set_key(const Botan::secure_vector<uint8_t>& master_key);
    Botan::secure_vector<uint8_t> calculate(const uint8_t* data, size_t len);
    bool verify(const uint8_t* data, size_t len, const uint8_t* mac, size_t mac_len);
};

class RateLimiter {
  private:
    std::chrono::steady_clock::time_point window_start;
    std::atomic<size_t> files_processed;
    std::atomic<size_t> bytes_processed;
    size_t max_files_per_second;
    size_t max_bytes_per_second;
    std::mutex rate_mutex;
  public:
    RateLimiter(size_t max_files = 1000, size_t max_bytes = 1024 * 1024 * 1024);
    void reset();
    void wait_if_needed(size_t bytes = 0);
    void setLimits(size_t max_files, size_t max_bytes);
};

template <typename T> class WorkQueue {
  private:
    std::deque<T> queue;
    std::mutex mutex;
    std::condition_variable not_empty;
    std::condition_variable not_full;
    std::atomic<bool> stopped{false};
    size_t max_size;
    std::atomic<size_t> queue_size{0};
  public:
    WorkQueue(size_t max_sz = 64) : max_size(max_sz) {}
    ~WorkQueue() { stop(); }
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_full.wait(lock, [this]() { return queue.size() < max_size || stopped; });
        if (stopped) return;
        queue.push_back(std::move(item));
        queue_size++;
        not_empty.notify_one();
    }
    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        not_empty.wait(lock, [this]() { return !queue.empty() || stopped; });
        if (stopped && queue.empty()) return false;
        item = std::move(queue.front());
        queue.pop_front();
        queue_size--;
        not_full.notify_one();
        return true;
    }
    void stop() { stopped = true; not_empty.notify_all(); not_full.notify_all(); }
    size_t size() const { return queue_size.load(); }
};

struct FileWork {
    std::string input_path;
    std::string output_path;
    bool is_encrypt;
    std::promise<bool> result_promise;
    uint64_t file_size;
    int retry_count;
    FileWork() : is_encrypt(true), file_size(0), retry_count(0) {}
    FileWork(FileWork&& other) noexcept
        : input_path(std::move(other.input_path)), output_path(std::move(other.output_path)),
          is_encrypt(other.is_encrypt), result_promise(std::move(other.result_promise)), file_size(other.file_size),
          retry_count(other.retry_count) {}
    FileWork& operator=(FileWork&& other) noexcept {
        if (this != &other) {
            input_path = std::move(other.input_path);
            output_path = std::move(other.output_path);
            is_encrypt = other.is_encrypt;
            result_promise = std::move(other.result_promise);
            file_size = other.file_size;
            retry_count = other.retry_count;
        }
        return *this;
    }
    FileWork(const FileWork&) = delete;
    FileWork& operator=(const FileWork&) = delete;
};

class NameKeyMgr {
  private:
    std::string key_file_path;
    Botan::secure_vector<uint8_t> master_key;
    Botan::secure_vector<uint8_t> name_key;
    bool initialized = false;
    Botan::secure_vector<uint8_t> derive_name_key(const Botan::secure_vector<uint8_t>& master);
    bool write_full(int fd, const void* data, size_t size);
    bool read_full(int fd, void* data, size_t size);
    bool save_master_key();
    bool load_master_key();
  public:
    explicit NameKeyMgr(const std::string& key_file);
    ~NameKeyMgr();
    const Botan::secure_vector<uint8_t>& get_name_key() const { return name_key; }
    bool is_initialized() const { return initialized && name_key.size() == 32; }
};

class PersistCounter {
  private:
    std::map<std::string, uint64_t> counters;
    mutable std::shared_timed_mutex counters_mutex;
    std::string storage_file;
    std::atomic<bool> dirty{false};
    std::atomic<uint64_t> save_counter{0};
    std::atomic<bool> is_saving{false};
    std::condition_variable save_cv;
    std::mutex save_mutex;
    std::thread auto_save_thread;
    std::atomic<bool> auto_save_running{false};
    static constexpr uint64_t SAVE_THRESHOLD = 5;
    static constexpr int AUTO_SAVE_INTERVAL_MS = 3000;
    bool write_full(int fd, const void* data, size_t size);
    bool read_full(int fd, void* data, size_t size);
    void load_from_file();
    bool save_to_file_internal();
    void auto_save_loop();
  public:
    explicit PersistCounter(const std::string& file_path);
    ~PersistCounter();
    uint64_t get_and_increment(const std::string& key);
    uint64_t get(const std::string& key) const;
    bool force_save() { return save_to_file_internal(); }
    size_t size() const {
        std::shared_lock<std::shared_timed_mutex> lock(counters_mutex);
        return counters.size();
    }
};

class NameObfus {
  private:
    Botan::secure_vector<uint8_t> name_key;
    std::unique_ptr<PersistCounter> persistent_counter;
    std::unique_ptr<NameKeyMgr> key_manager;
    struct NameCacheEntry {
        std::string original;
        std::string obfuscated;
        std::chrono::steady_clock::time_point timestamp;
        std::atomic<uint64_t> hits;
        NameCacheEntry() : hits(0) { timestamp = std::chrono::steady_clock::now(); }
    };
    std::vector<std::unique_ptr<NameCacheEntry>> name_cache;
    std::shared_mutex cache_mutex;
    std::atomic<size_t> cache_index{0};
    size_t cache_size;
    static std::string base64_url_encode(const std::string& data);
    static std::string base64_url_decode(const std::string& encoded);
    struct EncryptedName {
        std::vector<uint8_t> nonce;
        std::string ciphertext;
        std::string serialize() const {
            std::string result;
            result.reserve(nonce.size() + ciphertext.size());
            result.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
            result.append(ciphertext);
            return result;
        }
        static EncryptedName deserialize(const std::string& data) {
            EncryptedName result;
            if (data.size() < 16) throw std::runtime_error("Datos muy pequeños");
            result.nonce.assign(data.begin(), data.begin() + 16);
            result.ciphertext = data.substr(16);
            return result;
        }
    };
  public:
    NameObfus(size_t cache_sz = 1024,
              const std::string& counter_file = ".cipher_counters.dat",
              const std::string& key_file = ".cipher_namekey.dat");
    ~NameObfus();
    std::string obfuscate_name(const std::string& original_name);
    std::string deobfuscate_name(const std::string& obfuscated_name);
    void force_save_counters();
};

class AES256GCM {
  private:
    Botan::secure_vector<uint8_t> key;
    std::vector<std::thread> file_workers;
    WorkQueue<FileWork> work_queue;
    std::atomic<bool> workers_running;
    std::unique_ptr<RateLimiter> rate_limiter;
    HeaderKMAC header_mac;
    SystemConfig config;
    std::atomic<uint64_t> total_files_processed{0};
    std::atomic<uint64_t> total_bytes_processed{0};
    std::atomic<uint64_t> total_errors{0};
    std::atomic<uint64_t> total_retries{0};
    std::atomic<uint64_t> mmap_used{0};
    bool write_full_with_retry(int fd, const void* data, size_t size, int max_retries = 3);
    bool read_full_with_retry(int fd, void* data, size_t size, int max_retries = 3);
    bool validate_header_integrity(const uint8_t* data, size_t size);
    bool encrypt_with_mmap(const MMapRAII& mapped, const std::string& outputPath);
    bool decrypt_with_mmap(const MMapRAII& mapped, const std::string& outputPath);
    bool process_with_traditional_io(const std::string& inputPath, const std::string& outputPath, bool encryptMode);
    bool process_with_mmap_wrapper(const std::string& inputPath, const std::string& outputPath, bool encryptMode);
    bool process_single_file_with_retry(const std::string& inputPath, const std::string& outputPath, bool encryptMode);
    void file_worker_function();
  public:
    AES256GCM(const uint8_t* key_data, size_t key_len, size_t num_threads, size_t queue_sz, const SystemConfig& cfg);
    ~AES256GCM();
    void setRateLimits(size_t max_files, size_t max_bytes);
    bool encrypt_file(const std::string& inputPath, const std::string& outputPath);
    bool decrypt_file(const std::string& inputPath, const std::string& outputPath);
    std::vector<bool> process_files_parallel(const std::vector<std::pair<std::string, std::string>>& files, bool encryptMode);
    std::string name() const { return "AES-256-GCM"; }
    std::string provider() const;
    bool has_aes_ni() const;
    uint64_t get_files_processed() const { return total_files_processed.load(); }
    uint64_t get_bytes_processed() const { return total_bytes_processed.load(); }
    uint64_t get_errors() const { return total_errors.load(); }
    uint64_t get_retries() const { return total_retries.load(); }
    uint64_t get_mmap_used() const { return mmap_used.load(); }
};

class UniversalCipher {
  public:
    using LogCallback = std::function<void(univ_log::LogLevel level, univ_log::LogEvent event, const std::string& data)>;
    using ProgressCallback = std::function<void(size_t current, size_t total, const std::string& file)>;
    struct Stats {
        size_t total_files = 0;
        size_t success = 0;
        size_t fail = 0;
        uint64_t total_time_ms = 0;
    };
    const Stats& getLastStats() const { return last_stats; }
  private:
    SystemConfig config;
    KeyManager* keyManager;
    std::unique_ptr<NameObfus> name_obfuscator;
    std::unique_ptr<AES256GCM> cipher;
    std::string currentKeyName;
    std::atomic<bool> processing_active{false};
    std::atomic<bool> stop_requested{false};
    Stats last_stats;
    LogCallback log_cb_;
    ProgressCallback progress_cb_;
    void log(univ_log::LogLevel level, univ_log::LogEvent event, const std::string& data = "") {
        if (log_cb_) log_cb_(level, event, data);
    }
    void progress(size_t cur, size_t total, const std::string& file) {
        if (progress_cb_) progress_cb_(cur, total, file);
    }
    Botan::secure_vector<uint8_t> hexToSecureBytes(const std::string& hex);
    std::string secureVectorToHex(const Botan::secure_vector<uint8_t>& data);
    bool fileExists(const std::string& path);
    bool isDirectory(const std::string& path);
    uint64_t getFileSize(const std::string& path);
    bool should_ignore_file(const std::string& filename);
    bool is_already_encrypted(const std::string& filename);
    std::vector<std::string> getAllFiles(const std::string& path, bool recursive = true);
    bool processDirectory(const std::string& path, bool encryptMode);
    bool encryptFileInPlace(const std::string& inputPath);
    bool decryptFileInPlace(const std::string& inputPath);
    bool processPath(const std::string& path, bool encryptMode);
  public:
    UniversalCipher();
    ~UniversalCipher();
    void setLogCallback(LogCallback cb) { log_cb_ = std::move(cb); }
    void setProgressCallback(ProgressCallback cb) { progress_cb_ = std::move(cb); }
    void setKeyManager(KeyManager* km) { keyManager = km; }
    void stop() { if (processing_active) stop_requested = true; }
    bool encryptPath(const std::string& path);
    bool decryptPath(const std::string& path);
    SystemConfig& getConfig() { return config; }
    const SystemConfig& getConfig() const { return config; }
    const std::string& getCurrentKeyName() const { return currentKeyName; }
    NameObfus* getNameObfuscator() { return name_obfuscator.get(); }
    KeyManager* getKeyManager() { return keyManager; }
    bool setCipherKey(const std::string& keyName);
    uint64_t getFilesProcessed() const;
    uint64_t getBytesProcessed() const;
    uint64_t getErrors() const;
    uint64_t getRetries() const;
    uint64_t getMmapUsed() const;
};

#endif // CIPHER_UNIVERSAL_CIPHER_H