// cipher/unit/unit_worker.cpp
#include "../unit_encryptor.h"
#include <sys/wait.h>
#include <unistd.h>

namespace UnitEvents {
    void print_cli(LogLevel level, LogEvent event, const std::string& data);
    void print_cli_progress(uint64_t cur, uint64_t total, double speed);
    void print_worker_result(bool ok);
}

bool UnitEncryptor::executeElevatedOp(
    const StorUnit& unit,
    bool encrypt,
    const Botan::secure_vector<uint8_t>& master_key) {
    
    if (master_key.empty() || master_key.size() != 32) return false;

    char keyfile[] = "/dev/shm/.rubic_key_XXXXXX";
    int kfd = mkstemp(keyfile);
    if (kfd < 0) return false;

    fchmod(kfd, 0600);
    bool write_ok = (write(kfd, master_key.data(), master_key.size()) == (ssize_t)master_key.size());
    fsync(kfd);
    close(kfd);

    if (!write_ok) { 
        unlink(keyfile); 
        return false; 
    }

    const char* env_lang = getenv("LANG");
    std::string cur_lang = env_lang ? env_lang : "en";

    pid_t pid = fork();
    if (pid < 0) { unlink(keyfile); return false; }

    if (pid == 0) {
        setenv("LANG", cur_lang.c_str(), 1);
        const char* sudo_path = "/usr/bin/sudo";
        if (access(sudo_path, X_OK) != 0) sudo_path = "/bin/sudo";

        execl(sudo_path, "sudo", "/proc/self/exe", "--unit-op",
              unit.device_path.c_str(),
              encrypt ? "encrypt" : "decrypt", "--keyfile",
              keyfile, nullptr);
        _exit(127);
    }

    int status = 0;
    waitpid(pid, &status, 0);
    unlink(keyfile);

    if (!WIFEXITED(status)) return false;
    return WEXITSTATUS(status) == 0;
}

int UnitEncryptor::tryRunAsWorker(
int argc, char* argv[]) {
    if (argc < 2) return -1;
    if (std::string(argv[1]) != "--unit-op") return -1;

    if (geteuid() != 0) { std::cerr << "[-] --unit-op requiere sudo (root).\n"; return 1; }
    if (argc < 6) return 1;

    std::string device = argv[2];
    std::string action = argv[3];
    
    if (device.rfind("/dev/", 0) != 0) return 1;
    
    bool encrypt = (action == "encrypt");
    if (!encrypt && action != "decrypt") return 1;
    
    std::string keyfile;
    for (int i = 4; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--keyfile") { 
            keyfile = argv[i + 1]; break; 
        }
    }

    if (keyfile.empty()) return 1;
    if (keyfile.rfind("/dev/shm/.rubic_key_", 0) != 0) return 1;

    int kfd = open(keyfile.c_str(), O_RDONLY);
    if (kfd < 0) return 1;
    unlink(keyfile.c_str());

    Botan::secure_vector<uint8_t> master_key(32);
    ssize_t r = read(kfd, master_key.data(), 32);
    close(kfd);
    if (r != 32) return 1;
    
    StorUnit u;
    u.device_path = device;
    u.is_encrypted = !encrypt;
    u.is_mounted = false;
    u.is_system_disk = false;
    u.device_type = DevDetect::detect(device);

    UnitEncryptor enc;
    enc.setLogCallback([](LogLevel level, LogEvent event, const std::string& data) {
        UnitEvents::print_cli(level, event, data);
    });
    enc.setProgressCallback([](uint64_t cur, uint64_t total, double speed) {
        UnitEvents::print_cli_progress(cur, total, speed);
    });

    bool ok = enc.processUnit(u, encrypt, master_key);
    UnitEvents::print_worker_result(ok);
    return ok ? 0 : 1;
}
