// cipher/unit/unit_pipeline.cpp - 0.1 alpha
#include "../unit_encryptor.h"

#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept> // <-- Agregado para std::invalid_argument

#if defined(__x86_64__) || defined(__i386__)
  #include <immintrin.h>
#endif

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

    for (; i < total_bytes; i++)
        dst[i] ^= src[i];
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

bool AESXTSProc::verify_compat() {
    uint8_t pt[SECTOR_SIZE]; // <-- FIX: SOLO UN SECTOR (512 bytes)
    uint8_t ours[SECTOR_SIZE];
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
            uint8_t iv[16] = {0}; // Sector 0
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

                // Calculamos el tweak para el sector 0
                uint64_t sn = 0;
                std::memset(t0, 0, 16);
                std::memcpy(t0, &sn, 8);
                k2->encrypt(t0, t0);

                std::memcpy(all_tw, t0, 16);
                for (int b = 1; b < 32; b++) {
                    std::memcpy(all_tw + b * 16, all_tw + (b - 1) * 16, 16);
                    SIMDProc::gf_mul_alpha(all_tw + b * 16);
                }

                // Procesamos el único sector
                SIMDProc::xor_blocks(ours, all_tw, 32);
                k1->encrypt_n(ours, ours, 32);
                SIMDProc::xor_blocks(ours, all_tw, 32);

                result = std::memcmp(ref_out.data(), ours, sizeof(pt)) == 0;
            }
        }
    } catch (const std::exception&) {
        result = false;
    }

    rubic_sec::secure_wipe(pt,     sizeof(pt));
    rubic_sec::secure_wipe(ours,   sizeof(ours));
    rubic_sec::secure_wipe(all_tw, sizeof(all_tw));
    rubic_sec::secure_wipe(t0,     sizeof(t0));
    return result;
}

AESXTSProc::AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt)
    : encrypt_mode_(encrypt), use_avx512_(false) {
    
    // FIX: Exigimos exactamente 64 bytes para AES-256-XTS
    if (key_data.size() != 64) {
        throw std::invalid_argument("AESXTSProc: invalid key size (requires exactly 64 bytes)");
    }
    
    k1_.assign(key_data.begin(), key_data.begin() + 32);
    k2_.assign(key_data.begin() + 32, key_data.begin() + 64);

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

    tweak_scratch_.resize(kTweakBytes);
    std::memset(t0_scratch_, 0, sizeof(t0_scratch_));

    static const bool verified = verify_compat();
    use_avx512_ = verified;
}

void AESXTSProc::scrub_scratch() noexcept {
    if (!tweak_scratch_.empty()) {
        rubic_sec::secure_wipe(tweak_scratch_.data(), tweak_scratch_.size());     
    }
    rubic_sec::secure_wipe(t0_scratch_, sizeof(t0_scratch_));
}

bool AESXTSProc::processBuffer(uint8_t* data, size_t size, uint64_t start_sector) {
    bool result = false;
    try {
        if (use_avx512_)
            result = processBuffer_avx512(data, size, start_sector);
        else
            result = processBuffer_botan(data, size, start_sector);
    } catch (const std::exception&) {
        result = false;
    }
    scrub_scratch();
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

        SIMDProc::xor_blocks(batch_data, tw_base, batch_blocks);

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
        uint8_t tweak[16] = {0};
        std::memcpy(tweak, &sector_num, 8);
        botan_xts_->start(tweak, 16);
        Botan::secure_vector<uint8_t> buf(data + s * SECTOR_SIZE,
                                          data + (s + 1) * SECTOR_SIZE);
        botan_xts_->finish(buf);
        std::memcpy(data + s * SECTOR_SIZE, buf.data(), SECTOR_SIZE);
    }
    return true;
}

bool AESXTSProc::processSecBuf(SecBuf& buffer, uint64_t start_sector) {
    return processBuffer(buffer.data(), buffer.size(), start_sector);
}