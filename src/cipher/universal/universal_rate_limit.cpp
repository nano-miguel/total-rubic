/* cipher/universal/universal_rate_limit.cpp
Implementacion del limitador de tasa para el modulo universal.
Modelo: ventana fija de 1 segundo con doble presupuesto
(archivos por segundo y bytes por segundo). */
#include "../universal_cipher.h"
#include <algorithm>
#include <thread>
#include <chrono>

namespace {

/* Duracion de la ventana de medicion. */
constexpr long long kWindowMs = 1000;

/* Margen de seguridad: nunca dormir mas de esto para no
bloquear el pipeline si los limites son muy bajos. */
constexpr long long kMaxSleepMs = 500;

/* Minimos aceptables para setLimits. Cero desactiva el limite. */
constexpr size_t kMinRate = 0;

bool isWindowExpired(long long elapsed_ms) {
    return elapsed_ms >= kWindowMs;
}

long long computeSleepMs(long long elapsed_ms) {
    long long remaining = kWindowMs - elapsed_ms;
    if (remaining <= 0) return 0;
    return std::min(remaining, kMaxSleepMs);
}

bool budgetExceeded(size_t files, size_t bytes,
                    size_t max_files, size_t max_bytes) {
    if (max_files > 0 && files > max_files) return true;
    if (max_bytes > 0 && bytes > max_bytes) return true;
    return false;
}

} /* namespace anonimo */

RateLimiter::RateLimiter(size_t max_files, size_t max_bytes)
    : max_files_per_second(max_files)
    , max_bytes_per_second(max_bytes) {
    reset();
}

void RateLimiter::reset() {
    std::lock_guard<std::mutex> lock(rate_mutex);
    window_start = std::chrono::steady_clock::now();
    files_processed = 0;
    bytes_processed = 0;
}

/* Flujo:
1. Calcular cuanto tiempo paso desde que abrio la ventana.
2. Si la ventana expiro, abrir una nueva.
3. Registrar el consumo (1 archivo, N bytes).
4. Si se excedio algun presupuesto, dormir hasta que
   la ventana expire. El sleep se hace fuera del lock
   para no bloquear a los demas workers. */
void RateLimiter::wait_if_needed(size_t bytes) {
    long long sleep_ms = 0;

    {
        std::lock_guard<std::mutex> lock(rate_mutex);

        auto now = std::chrono::steady_clock::now();
        long long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - window_start).count();

        if (isWindowExpired(elapsed)) {
            window_start = now;
            files_processed = 0;
            bytes_processed = 0;
            elapsed = 0;
        }

        files_processed++;
        bytes_processed += bytes;

        if (budgetExceeded(files_processed.load(), bytes_processed.load(),
                           max_files_per_second, max_bytes_per_second)) {
            sleep_ms = computeSleepMs(elapsed);
        }
    }

    /* Sleep fuera del lock: otros workers pueden seguir
    consultando y registrando mientras este duerme. */
    if (sleep_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
    }
}

void RateLimiter::setLimits(size_t max_files, size_t max_bytes) {
    std::lock_guard<std::mutex> lock(rate_mutex);
    max_files_per_second = std::max(max_files, kMinRate);
    max_bytes_per_second = std::max(max_bytes, kMinRate);
}
