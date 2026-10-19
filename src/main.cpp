#include "rubic_core.h"
#include "ui/rubic_core_ui.h"
#include "ui/translator.h"

int main(int argc, char* argv[]) {
    try {
        //Disclaimer of Liability // Aviso de Responsabilidad
        std::cout << GREEN << "rubi-c es un codigo abierto y de uso libre no me responsabilizo por el mal uso de la herramienta o perdida de datos es una herramienta en fase alpha\n" << RESET << std::endl;
        
        std::cout << "\033[2J\033[1;1H";
        Memguardin::lockProcess();
        CrashHnd::setup();
        // Si el binario fue lanzado por sudo desde tryElevatedProcess(),
        // corre la operación y sale. Si no, sigue con el arranque normal.
        int worker_rc = UnitEncryptorUI::tryRunAsWorker(argc, argv); // <-- CORREGIDO AQUÍ
        if (worker_rc >= 0) {
            Memguardin::unlockProcess();
            return worker_rc;
        }

        // Idioma default antes del login (el usuario real se carga en authenticate())
        TR().load("es");
        
        UserMgr um;
        RubicCoreUI ui(um);
        ui.run();
    } 
    catch (const std::exception& e) {
        std::cerr << RED << "\n\u2717 ERROR: " << e.what() << RESET << std::endl;
        Memguardin::unlockProcess();
        return 1;
    }
    catch (...) {
        std::cerr << RED << "\n\u2717 ERROR DESCONOCIDO" << RESET << std::endl;
        Memguardin::unlockProcess();
        return 1;
    }

    Memguardin::unlockProcess();
    return 0;
}