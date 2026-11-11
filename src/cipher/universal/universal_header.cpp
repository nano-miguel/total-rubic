// src/cipher/universal/universal_header.cpp
#include "../universal_cipher.h"
#include <botan/kdf.h>
#include <span>

// ==========================================
// HeaderKMAC (Criptografía del encabezado)
// ==========================================

void HeaderKMAC::set_key(
    const Botan::secure_vector<uint8_t>& master_key) {
    try {
        auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
        std::string info_str = "HEADER_KMAC"; 
        std::string salt_str = "RUBIC_SALT";
        Botan::secure_vector<uint8_t> derived_key(32);

        kdf->derive_key(
            std::span<uint8_t>(derived_key.data(), derived_key.size()),
            std::span<const uint8_t>(master_key.data(), master_key.size()),
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(salt_str.data()), salt_str.size()),
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()));

        mac_key = derived_key;
    } 
    catch (const std::exception&) {
        auto hash = Botan::HashFunction::create_or_throw("SHA-256");
        hash->update(master_key);
        hash->update("HEADER_KMAC_SECURE_V2");
        mac_key = hash->final();
    }
}

Botan::secure_vector<uint8_t> HeaderKMAC::calculate(const uint8_t* data, size_t len) {
    std::unique_ptr<Botan::MessageAuthenticationCode> mac;
    try {
        mac = Botan::MessageAuthenticationCode::create_or_throw("KMAC-128(256)");
    } 
    catch (const std::exception&) {
        mac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-3(256))");
    }
    mac->set_key(mac_key);
    mac->update(data, len);
    return mac->final();
}

bool HeaderKMAC::verify(
    const uint8_t* data, size_t len, 
    const uint8_t* mac_tag, size_t mac_len) {
    auto calculated = calculate(data, len);
    if (calculated.size() != mac_len)
        return false;
    return ConstantTime::compare(calculated.data(), mac_tag, mac_len);
}
