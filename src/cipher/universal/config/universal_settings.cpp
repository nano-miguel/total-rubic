// cipher/universal/config/universal_settings.cpp - 0.1 alpha
#include "universal_settings.h"

/* 
 * Regla empírica: dejamos hilos libres para el OS, y le damos
 * el resto a la criptografía (que es el cuello de botella real).
 */
ThreadCfg ThreadCfg::getConfig(size_t system_threads) {
    ThreadCfg config;
    config.total_system_threads = system_threads;

    if (system_threads <= 2) {
        config.io_threads = 1;
        config.crypto_threads = 1;
        config.reserved_os = 0;
    } else if (system_threads <= 4) {
        config.io_threads = 1;
        config.crypto_threads = 2;
        config.reserved_os = 1;
    } else if (system_threads == 6) {
        config.io_threads = 2;
        config.crypto_threads = 3;
        config.reserved_os = 1;
    } else if (system_threads <= 8) {
        config.io_threads = 2;
        config.crypto_threads = 5;
        config.reserved_os = 1;
    } else if (system_threads <= 16) {
        config.io_threads = 3;
        config.crypto_threads = 11;
        config.reserved_os = 2;
    } else if (system_threads <= 32) {
        config.io_threads = 4;
        config.crypto_threads = 24;
        config.reserved_os = 4;
    } else {
        config.io_threads = 6;
        config.crypto_threads = system_threads - 8;
        config.reserved_os = 2;
    }

    return config;
}

size_t SystemConfig::get_dynamic_buffer_size(uint64_t file_size) const {
    if (file_size < 1024 * 1024) return min_buffer_size;
    if (file_size < 10 * 1024 * 1024) return optimal_buffer_size;
    return max_buffer_size;
}

bool SystemConfig::should_use_mmap(uint64_t file_size) const {
    return file_size >= mmap_threshold;
}

void SystemConfig::autoConfigure(size_t system_threads) {
    thread_config = ThreadCfg::getConfig(system_threads);
    queue_size = thread_config.crypto_threads * 8;
    max_parallel_files = thread_config.crypto_threads;
}