// cipher/unit_settings.h - 0.1 alpha
#ifndef CIPHER_UNIT_SETTINGS_H
#define CIPHER_UNIT_SETTINGS_H

#include <string>
#include <cstddef>

// Enumeración de tipos de dispositivo
enum class DevType { UNKNOWN, USB2, USB3, NVME, SSD_SATA, HDD, SD_CARD };

// Configuración fija autodetectada
struct FixedThCfg {
    int io_threads = 1;
    int crypto_threads = 1;
    int reserved_os = 0;
    static FixedThCfg getConfigForSystem();
};

// Configuración personalizada del usuario
struct CustCfg {
    size_t buffer_size_mb = 64;
    int io_threads = 2;
    int crypto_threads = 4;
    bool use_direct_io = true;
    bool custom_mode = false;
};

// Configuración resultante de hilos/chunks para el dispositivo actual
struct ThCfg {
    int num_threads = 1;
    size_t chunk_size_mb = 64;
    bool use_direct_io = true;

    void applyFixedConfig(const FixedThCfg& fixed_cfg, DevType device_type);
    void applyCustomConfig(const CustCfg& custom_cfg);
    void validate();
    size_t getChunkSize() const;
    std::string getDesc() const;
};

// ============================================================
// LA CLASE MADRE DE LA CONFIGURACIÓN
// ============================================================
class UnitSettings {
public:
    UnitSettings();

    // Carga y guarda en disco (XDG_CONFIG_HOME)
    void load();
    void save();

    // Resuelve qué configuración usar dependiendo del hardware y el modo
    ThCfg resolveConfig(DevType device_type) const;

    // Getters
    const CustCfg& getCustom() const { return custom_; }
    CustCfg& getCustom() { return custom_; }
    
    const FixedThCfg& getFixed() const { return fixed_; }
    
    bool isCustomMode() const { return custom_.custom_mode; }
    void setCustomMode(bool enable) { custom_.custom_mode = enable; }

private:
    FixedThCfg fixed_;
    CustCfg custom_;
    static std::string getConfigPath();
};

#endif // CIPHER_UNIT_SETTINGS_H
