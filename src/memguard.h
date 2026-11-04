#ifndef SECURITY_MEMGUARD_H
#define SECURITY_MEMGUARD_H

#include <string>
#include <cstddef>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <cerrno>
#include <cstring>

namespace MemGuard {

struct Status {
    bool mlockall_ok         = false;
    bool dump_disabled       = false;
    bool core_disabled       = false;
    size_t rlimit_memlock_kb = 0;
    std::string warning;
};

inline bool g_active = false;
inline Status activate() {
    Status st;

    // Sin core dumps, sin ptrace
    struct rlimit core = {0, 0};
    st.core_disabled = (setrlimit(RLIMIT_CORE, &core) == 0);
    st.dump_disabled = (prctl(PR_SET_DUMPABLE, 0) == 0);

    //  Subir RLIMIT_MEMLOCK para que quepa Argon2 (64 MB) + margen
    const rlim_t needed = 512ULL * 1024 * 1024;
    struct rlimit ml;
    if (getrlimit(RLIMIT_MEMLOCK, &ml) == 0) {
    if (ml.rlim_cur < needed && ml.rlim_max >= needed) {
     struct rlimit req = {needed, ml.rlim_max};
            setrlimit(RLIMIT_MEMLOCK, &req);
            getrlimit(RLIMIT_MEMLOCK, &ml);}
        st.rlimit_memlock_kb = ml.rlim_cur / 1024;
    }

    // UNA sola llamada a mlockall
    //  MCL_ONFAULT evita que Argon2 muera al pedir 64 MB
    if (mlockall(MCL_CURRENT | MCL_ONFAULT) == 0) {
        st.mlockall_ok = true; g_active = true;
    } 
    else {
        st.warning = "mlockall falló (RLIMIT_MEMLOCK="
        + std::to_string(st.rlimit_memlock_kb)
        + " KB, errno=" + std::to_string(errno)
        + ": " + std::strerror(errno) + ")";
    }
    return st;
}

inline void shutdown() {
    if (g_active) {
        munlockall();
        g_active = false;
    }
}

} // namespace MemGuard
#endif
