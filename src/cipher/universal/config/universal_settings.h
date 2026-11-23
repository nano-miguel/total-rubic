// cipher/universal/config/universal_settings.h - 0.1 alpha
#ifndef CIPHER_UNIVERSAL_SETTINGS_H
#define CIPHER_UNIVERSAL_SETTINGS_H

#include <cstddef>
#include <string>
#include <limits>
#include <cstdint>

/* 
 * ============================================================
 * CONFIGURACIÓN DE HILOS (ThreadCfg)
 * ============================================================
 * Decide cuántos hilos dedicar a leer/escribir del disco y 
 * cuántos a calcular la criptografía. En general, el cifrado
 * gasta más CPU que el I/O, así que se le dan más hilos al crypto.
 */
struct ThreadCfg {
    size_t total_system_threads;
    size_t crypto_threads;
    size_t io_threads;
    size_t reserved_os;

    static ThreadCfg getConfig(size_t system_threads);
};

/* 
 * ============================================================
 * CONFIGURACIÓN DEL SISTEMA (SystemConfig)
 * ============================================================
 * Almacena todos los límites y tamaños (buffers, reintentos, 
 * si usar mmap o no) que se usan durante el cifrado de archivos.
 */
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

    size_t get_dynamic_buffer_size(uint64_t file_size) const;
    bool should_use_mmap(uint64_t file_size) const;
    void autoConfigure(size_t system_threads);
};

#endif // CIPHER_UNIVERSAL_SETTINGS_H