// cipher/unit/config/unit_settings.cpp - 0.1 alpha
#include "unit_settings.h"
#include "../../../hardware_detect.h"

#include <fstream>
#include <sstream>
#include <cstdlib>
#include <sys/stat.h>

/**
 * Calcula la cantidad óptima de hilos de I/O y de criptografía
 * dependiendo de cuántos núcleos tiene la máquina. 
 * Siempre se reserva al menos 1 núcleo para el Sistema .
 */
SystemCfg SystemCfg::getConfigSystem() {
    SystemCfg config;
    int sys = HardwareDetect::getCoreCount();
    int avail = sys > 1 ? sys - 1 : sys;
    if (avail <= 2)      { config.io_threads = 1; config.crypto_threads = 1;          config.reserved_os = 0; }
    else if (avail <= 4) { config.io_threads = 1; config.crypto_threads = 2;          config.reserved_os = 1; }
    else if (avail <= 8) { config.io_threads = 2; config.crypto_threads = 5;          config.reserved_os = 1; }
    else if (avail <= 16){ config.io_threads = 3; config.crypto_threads = 11;         config.reserved_os = 2; }
    else if (avail <= 32){ config.io_threads = 4; config.crypto_threads = 24;         config.reserved_os = 4; }
    else { config.io_threads = 6; config.crypto_threads = avail - 8;  config.reserved_os = 2; }
    return config;
}

/**
 * Aplica la configuración fija y ajusta los parámetros al tipo de hardware.
 * Los HDDs y USB 2.0 usan chunks más grandes porque tienen latencia alta.
 * El O_DIRECT se desactiva en USB2/SD porque algunos controladores no lo soportan bien.
 */
void ThCfg::applySystemConfig(const SystemCfg& f, DevType t) {
    num_threads = f.io_threads + f.crypto_threads + f.reserved_os;
    
    if (t == DevType::HDD || t == DevType::USB2) chunk_size_mb = 128;
    else chunk_size_mb = 64;

    use_direct_io = !(t == DevType::USB2 || t == DevType::SD_CARD);
}

void ThCfg::applyCustomConfig(const CustCfg& c) {
    num_threads = c.io_threads + c.crypto_threads;
    chunk_size_mb = c.buffer_size_mb;
    use_direct_io = c.use_direct_io;
}

/**
 * Valida los límites lógicos.
 *
 * NOTA sobre alineación:
 *   chunk_size_mb es size_t (entero). Multiplicar por 1 MiB (2^20 bytes)
 *   siempre da un múltiplo de 4096 (= 2^12), porque 2^20 = 2^12 * 256.
 *   Por construcción el resultado ya está alineado a O_DIRECT, así que
 *   el realineado dinámico era código muerto. Se elimina.
 */
void ThCfg::validate() {
    if (num_threads < 1) num_threads = 1;
    if (num_threads > 128) num_threads = 128;
    if (chunk_size_mb < 1) chunk_size_mb = 1;
    if (chunk_size_mb > 1024) chunk_size_mb = 1024;
}

size_t ThCfg::getChunkSize() const {
    return chunk_size_mb * 1024 * 1024;
}

std::string ThCfg::getDesc() const {
    std::stringstream ss;
    ss << num_threads << " hilos | Chunk: " << chunk_size_mb << "MB";
    if (use_direct_io) ss << " | I/O DIRECTO";
    return ss.str();
}

UnitSettings::UnitSettings() {
    fixed_ = SystemCfg::getConfigSystem();
    load();
}

/**
 * Usa el  XDG para guardar la configuración en ~/.config/RUBIC-A/
 */
std::string UnitSettings::getConfigPath() {
    const char* xdg_config = getenv("XDG_CONFIG_HOME");
    std::string base;
    if (xdg_config && xdg_config[0] != '\0') {
        base = std::string(xdg_config);
    }
    else {
        const char* home = getenv("HOME");
        base = home ? std::string(home) + "/.config" : "/tmp";
    }
    std::string dir = base + "/RUBIC-A";
    
    struct stat st;
    if (stat(dir.c_str(), &st) != 0) {
        mkdir(dir.c_str(), 0700);
    }
    return dir + "/rubic_config.cfg";
}

void UnitSettings::load() {
    std::string cfg_path = getConfigPath();
    std::ifstream file(cfg_path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            if (key == "buffer_size_mb") custom_.buffer_size_mb = std::stoul(value);
             else if (key == "io_threads") custom_.io_threads = std::stoi(value);
             else if (key == "crypto_threads") custom_.crypto_threads = std::stoi(value);
             else if (key == "use_direct_io") custom_.use_direct_io = (value == "true");
             else if (key == "custom_mode") custom_.custom_mode = (value == "true");
        } 
    }
}

void UnitSettings::save() {
    std::string cfg_path = getConfigPath();
    std::ofstream file(cfg_path);
    if (!file.is_open()) return;
    
    file << "# Configuración personalizada de RUBI-C\n";
    file << "buffer_size_mb=" << custom_.buffer_size_mb << "\n";
    file << "io_threads=" << custom_.io_threads << "\n";
    file << "crypto_threads=" << custom_.crypto_threads << "\n";
    file << "use_direct_io=" << (custom_.use_direct_io ? "true" : "false") << "\n";
    file << "custom_mode=" << (custom_.custom_mode ? "true" : "false") << "\n";
}

ThCfg UnitSettings::resolveConfig(DevType device_type) const {
    ThCfg cfg;
    if (custom_.custom_mode) {
        cfg.applyCustomConfig(custom_);
    }
    else {
        cfg.applySystemConfig(fixed_, device_type);
    }
    cfg.validate();
    return cfg;
}