// src/hardware_detect.h
#ifndef HARDWARE_DETECT_H
#define HARDWARE_DETECT_H

#include <string>
#include <sstream>
#include <thread>
#include <cstdint>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#define RUBIC_X86 1
#endif

class HardwareDetect {
public:
    static int getCoreCount() {
    static const int cores = [] {
        const int n = static_cast<int>(std::thread::hardware_concurrency());
        return n > 0 ? n : 4;
        }();
        return cores;
    }

#ifdef RUBIC_X86
    static bool hasAESNI()   { static const bool v = detect_aesni();   return v; }
    static bool hasAVX2()    { static const bool v = detect_avx2();    return v; }
    static bool hasAVX512F() { static const bool v = detect_avx512f(); return v; }
#else
    static bool hasAESNI()   { return false; }
    static bool hasAVX2()    { return false; }
    static bool hasAVX512F() { return false; }
#endif

    static bool hasAVX512() { return hasAVX512F(); }
    static std::string getCPUInfo(bool verbose = false) {
        std::stringstream ss;

        if (verbose) {
            ss << "Núcleos: " << getCoreCount();
            
            struct Feature { const char* name; bool supported; };
            const Feature features[] = {
                {"AES-NI", hasAESNI()},
                {"AVX2",   hasAVX2()},
                {"AVX-512",hasAVX512F()}
            };

            for (const auto& f : features) {
            if (f.supported) ss << " | " << f.name << ": ✓";
            }
            
        } else {
            ss << "Nucleos: "   << getCoreCount();
            ss << "| AES-NI: "  << (hasAESNI() ? "Si" : "No");
            if (hasAVX512F())    ss << " | SIMD: AVX-512";
            else if (hasAVX2())  ss << " | SIMD: AVX2";
            else                 ss << " | SIMD: SSE";
        }

        return ss.str();
    }

private:
#ifdef RUBIC_X86
    static uint64_t read_xcr0() {
        uint32_t lo = 0, hi = 0;
        __asm__ __volatile__(".byte 0x0f, 0x01, 0xd0": "=a"(lo), "=d"(hi) : "c"(0));
        return (static_cast<uint64_t>(hi) << 32) | static_cast<uint64_t>(lo);
    }

    static bool os_enabled_avx()    { return (read_xcr0() & 0x06) == 0x06; }
    static bool os_enabled_avx512() { return (read_xcr0() & 0xE6) == 0xE6; }

    static bool cpu_has_osxsave_avx() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) < 1) return false;
        __cpuid_count(1, 0, eax, ebx, ecx, edx);
        return (ecx & (1u << 27)) && (ecx & (1u << 28));
    }

    static bool detect_aesni() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) < 1) return false;
        __cpuid_count(1, 0, eax, ebx, ecx, edx);
        return (ecx & (1u << 25)) != 0;
    }

    static bool detect_avx2() {
        if (!cpu_has_osxsave_avx() || !os_enabled_avx()) return false;
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) < 7) return false;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1u << 5)) != 0;
    }

    static bool detect_avx512f() {
        if (!cpu_has_osxsave_avx() || !os_enabled_avx512()) return false;
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid_max(0, nullptr) < 7) return false;
        __cpuid_count(7, 0, eax, ebx, ecx, edx);
        return (ebx & (1u << 16)) != 0;
    }
#endif
};

#endif // HARDWARE_DETECT_H