#include "rubic_core.h"
#include "ui/rubic_core_ui.h"
#include "ui/translator.h"
#include "memguard.h"

int main(int argc, char* argv[]) {
    try {
        // Disclaimer of Liability // Aviso de Responsabilidad
        std::cout << GREEN
                  << "rubi-c es un codigo abierto y de uso libre no me responsabilizo "
                     "por el mal uso de la herramienta o perdida de datos es una "
                     "herramienta en fase alpha\n"
                  << RESET << std::endl;

        std::cout << "\033[2J\033[1;1H";

        // ── Protección de memoria (una sola vez al arrancar) ──
        auto mem = MemGuard::activate();
        if (!mem.mlockall_ok) {
            std::cerr << YELLOW << "  ⚠ " << mem.warning << RESET << "\n";
            std::cerr << YELLOW << "    Las claves podrían ir a swap (RLIMIT_MEMLOCK bajo).\n"
                      << "    Esto no impide el uso normal de la app.\n"
                      << "    Ver: man 2 mlockall" << RESET << "\n";
        }

        CrashHnd::setup();

        // Si el binario fue lanzado por sudo desde executeElevatedOp(),
        // corre la operación y sale. Si no, sigue con el arranque normal.
        int worker_rc = UnitEncryptor::tryRunAsWorker(argc, argv);
        if (worker_rc >= 0) {
            MemGuard::shutdown();
            return worker_rc;
        }

        // --- Auto-detectar idioma del sistema ---
        std::string sys_lang = Translator::detectSystemLanguage();
        if (!TR().load(sys_lang)) {
            TR().load("en");
        }

        UserMgr um;
        RubicCoreUI ui(um);
        ui.run();
    }
    catch (const std::exception& e) {
        std::cerr << RED << "\n\u2717 ERROR: " << e.what() << RESET << std::endl;
        MemGuard::shutdown();
        return 1;
    }
    catch (...) {
        std::cerr << RED << "\n\u2717 ERROR DESCONOCIDO" << RESET << std::endl;
        MemGuard::shutdown();
        return 1;
    }

    MemGuard::shutdown();
    return 0;
}