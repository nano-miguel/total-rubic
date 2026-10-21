// cipher/unit/config/unit_settings.h - 0.1 alpha
#ifndef CIPHER_UNIT_SETTINGS_H
#define CIPHER_UNIT_SETTINGS_H

#include <string>
#include <cstddef>

/**
 * Tipos de dispositivos de almacenamiento soportados.
 * Se usa para ajustar automáticamente el tamaño de los chunks
 * y el modo de I/O según el hardware.
 */
enum class DevType { UNKNOWN, USB2, USB3, NVME, SSD_SATA, HDD, SD_CARD };

/**
 * Configuración automática del sistema.
 * Se calcula en base a la cantidad de núcleos del procesador.
 */
struct SystemCfg {
    int io_threads = 1;
    int crypto_threads = 1;
    int reserved_os = 0;
    static SystemCfg getConfigSystem();
};

/**
 * Configuración personalizada por el usuario.
 * Sobrescribe la configuración automática si custom_mode == true.
 */
struct CustCfg {
    size_t buffer_size_mb = 64;
    int io_threads = 2;
    int crypto_threads = 4;
    bool use_direct_io = true;
    bool custom_mode = false;
};

/**
 * Configuración final resuelta que se pasa al motor de cifrado.
 * Es el resultado de aplicar los valores fijos o personalizados.
 */
struct ThCfg {
    int num_threads = 1;
    size_t chunk_size_mb = 64;
    bool use_direct_io = true;

    void applySystemConfig(const SystemCfg& fixed_cfg, DevType device_type);
    void applyCustomConfig(const CustCfg& custom_cfg);
    void validate(); // Asegura que los valores estén en rangos seguros
    size_t getChunkSize() const; // Devuelve el tamaño en bytes (alineado a 4096)
    std::string getDesc() const;
};

/**
 * Interfaz principal para gestionar la configuración.
 * Lee y escribe el archivo rubic_config.cfg en la carpeta XDG.
 */
class UnitSettings {
public:
    UnitSettings();
    void load();
    void save();
    ThCfg resolveConfig(DevType device_type) const;

    const CustCfg& getCustom() const { return custom_; }
    CustCfg& getCustom() { return custom_; }
    const SystemCfg& getFixed() const { return fixed_; }
    bool isCustomMode() const { return custom_.custom_mode; }
    void setCustomMode(bool enable) { custom_.custom_mode = enable; }

private:
    SystemCfg fixed_;
    CustCfg custom_;
    static std::string getConfigPath();
};

#endif // CIPHER_UNIT_SETTINGS_H