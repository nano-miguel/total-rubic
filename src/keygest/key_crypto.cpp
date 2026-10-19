// keygest/key_crypto.cpp - 0.1 alpha
// Implementación pura de las utilidades criptográficas para las claves.
// Utiliza Argon2id para derivación y AES-256-GCM para cifrado en reposo.

#include "key_manager.h"
#include <botan/pwdhash.h>
#include <botan/cipher_mode.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/base64.h>
#include <memory>
#include <stdexcept>

// ============================================
// KeyCryptoUtils
// ============================================

Botan::secure_vector<uint8_t> KeyCryptoUtils::generateSalt() {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> salt(SALT_SIZE);
        rng.randomize(salt.data(), salt.size());
        return salt;
    } catch (const std::exception&) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::generateRandomBytes(int bytes) {
    try {
        Botan::AutoSeeded_RNG rng;
        Botan::secure_vector<uint8_t> key(bytes);
        rng.randomize(key.data(), key.size());
        return key;
    } catch (const std::exception&) {
        return Botan::secure_vector<uint8_t>();
    }
}

std::string KeyCryptoUtils::generateRandomHex(int bytes) {
    try {
        Botan::AutoSeeded_RNG rng;
        std::vector<uint8_t> key(bytes);
        rng.randomize(key.data(), key.size());
        return Botan::hex_encode(key);
    } catch (const std::exception&) {
        return "";
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::deriveKey(const Botan::secure_vector<uint8_t>& password,
                                                        const Botan::secure_vector<uint8_t>& salt,
                                                        size_t key_len) {
    try {
        auto argon2_family = Botan::PasswordHashFamily::create("Argon2id");
        if (!argon2_family) {
            return Botan::secure_vector<uint8_t>();
        }

        auto argon2 = argon2_family->from_params(ARGON2_MEMORY_KB, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
        if (!argon2) {
            return Botan::secure_vector<uint8_t>();
        }

        Botan::secure_vector<uint8_t> key(key_len);
        argon2->derive_key(key.data(),
                           key.size(),
                           reinterpret_cast<const char*>(password.data()),
                           password.size(),
                           salt.data(),
                           salt.size());

        return key;
    } catch (const std::exception&) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::encryptData(const Botan::secure_vector<uint8_t>& plaintext,
                                                          const Botan::secure_vector<uint8_t>& password) {
    try {
        Botan::AutoSeeded_RNG rng;

        // 1. Generar salt
        Botan::secure_vector<uint8_t> salt = generateSalt();
        if (salt.empty()) return Botan::secure_vector<uint8_t>();

        // 2. Derivar la llave con Argon2id
        Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
        if (key.empty()) return Botan::secure_vector<uint8_t>();

        // 3. Generar IV para AES-GCM
        Botan::secure_vector<uint8_t> iv(IV_SIZE);
        rng.randomize(iv.data(), iv.size());

        // 4. Configurar el cifrador
        std::unique_ptr<Botan::Cipher_Mode> cipher =
            Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Encryption);
        if (!cipher) return Botan::secure_vector<uint8_t>();

        cipher->set_key(key);
        cipher->start(iv.data(), iv.size());

        // 5. Cifrar
        Botan::secure_vector<uint8_t> ct = plaintext;
        cipher->finish(ct);

        // 6. Empaquetar: [Salt (32B)] + [IV (12B)] + [Ciphertext + Tag GCM]
        Botan::secure_vector<uint8_t> result;
        result.reserve(salt.size() + iv.size() + ct.size());
        result.insert(result.end(), salt.begin(), salt.end());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), ct.begin(), ct.end());

        return result;
    } catch (const std::exception&) {
        return Botan::secure_vector<uint8_t>();
    }
}

Botan::secure_vector<uint8_t> KeyCryptoUtils::decryptData(const Botan::secure_vector<uint8_t>& encrypted,
                                                          const Botan::secure_vector<uint8_t>& password) {
    try {
        // Validar tamaño mínimo: Salt + IV + al menos 1 byte de Tag
        if (encrypted.size() < SALT_SIZE + IV_SIZE) {
            return Botan::secure_vector<uint8_t>();
        }

        // 1. Desempaquetar
        Botan::secure_vector<uint8_t> salt(encrypted.begin(), encrypted.begin() + SALT_SIZE);
        Botan::secure_vector<uint8_t> iv(encrypted.begin() + SALT_SIZE, encrypted.begin() + SALT_SIZE + IV_SIZE);
        Botan::secure_vector<uint8_t> ct(encrypted.begin() + SALT_SIZE + IV_SIZE, encrypted.end());

        // 2. Derivar la llave con Argon2id
        Botan::secure_vector<uint8_t> key = deriveKey(password, salt);
        if (key.empty()) return Botan::secure_vector<uint8_t>();

        // 3. Configurar el descifrador
        std::unique_ptr<Botan::Cipher_Mode> cipher =
            Botan::Cipher_Mode::create("AES-256/GCM", Botan::Cipher_Dir::Decryption);
        if (!cipher) return Botan::secure_vector<uint8_t>();

        cipher->set_key(key);
        cipher->start(iv.data(), iv.size());

        // 4. Descifrar y verificar Tag de integridad
        Botan::secure_vector<uint8_t> pt = ct;
        cipher->finish(pt);

        return pt;
    } catch (const std::exception&) {
        // Si falla el Tag GCM (contraseña incorrecta o datos corruptos), cae acá.
        return Botan::secure_vector<uint8_t>();
    }
}