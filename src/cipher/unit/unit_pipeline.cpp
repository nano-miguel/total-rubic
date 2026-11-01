// cipher/unit/unit_pipeline.cpp - 0.1 alpha
#include "../unit_encryptor.h"

#include <cstring>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <thread>
#include <atomic>
#include <functional>

// ============================================
// AESXTSProc (Motor de cifrado por bloques)
// ============================================

AESXTSProc::AESXTSProc(const Botan::secure_vector<uint8_t>& key_data, bool encrypt)
    : encrypt_mode_(encrypt) {
    
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
}

bool AESXTSProc::processBuffer(uint8_t* data, size_t size, uint64_t start_sector) {
    if (size == 0 || size % SECTOR_SIZE != 0) {
        return false;
    }

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


// ============================================================
// PIPELINE LOGIC (Movido desde unit_encryptor.cpp)
// ============================================================

namespace unit_pipeline {

class DataPipeline {
public:
    struct Context {
        int fd;
        uint64_t total_size;
        uint64_t data_start_sector;
        const ThCfg& cfg;
        DevType device_type;
        const Botan::secure_vector<uint8_t>& xts_key;
        bool encrypt;
        SpeedMtr& speed_meter;
        std::atomic<bool>& stop_requested;
        std::function<void(LogLevel, LogEvent, const std::string&)> log;
        std::function<void(uint64_t, uint64_t, double)> progress;
    };

    explicit DataPipeline(Context ctx) : ctx_(ctx) {}

    bool run() {
        size_t chunk_size = ctx_.cfg.getChunkSize();
        uint64_t total_chunks = (ctx_.total_size + chunk_size - 1) / chunk_size;

        ctx_.log(LogLevel::Info, LogEvent::DataSizeInfo, std::to_string(ctx_.total_size));
        ctx_.log(LogLevel::Info, LogEvent::ChunkCountInfo, std::to_string(total_chunks));

        LimQueue<PipeChunk> read_q(MAX_QUEUE_SIZE), write_q(MAX_QUEUE_SIZE);
        std::atomic<uint64_t> done{0}, bytes_done{0};
        std::atomic<bool> err{false};

        auto reader = spawn_reader(read_q, chunk_size, total_chunks, err);
        auto workers = spawn_workers(read_q, write_q, chunk_size, err);
        auto writer = spawn_writer(write_q, chunk_size, total_chunks, done, bytes_done, err);

        while (!err && !ctx_.stop_requested && done < total_chunks) {
            std::this_thread::sleep_for(std::chrono::milliseconds(PROGRESS_UPDATE_MS));
            if (err || ctx_.stop_requested) { read_q.close(); write_q.close(); }
        }

        read_q.close();
        write_q.close();
        if (reader.joinable()) reader.join();
        for (auto& t : workers) if (t.joinable()) t.join();
        if (writer.joinable()) writer.join();

        if (fsync(ctx_.fd) != 0) {
            ctx_.log(LogLevel::Error, LogEvent::FinalFsyncFailed, "");
            err = true;
        }

        if (err) ctx_.log(LogLevel::Error, LogEvent::ProcessingFailed, "");
        else if (ctx_.stop_requested) ctx_.log(LogLevel::Warning, LogEvent::ProcessingStopped, "");
        else ctx_.log(LogLevel::Success, LogEvent::ProcessingComplete, "");

        return !err && done == total_chunks && !ctx_.stop_requested;
    }

private:
    Context ctx_;

    std::thread spawn_reader(LimQueue<PipeChunk>& read_q, size_t chunk_size, uint64_t total_chunks, std::atomic<bool>& err) {
        bool scrub = !ctx_.encrypt;
        return std::thread([this, &read_q, chunk_size, total_chunks, &err, scrub]() {
            for (uint64_t c = 0; c < total_chunks && !err && !ctx_.stop_requested; c++) {
                PipeChunk chunk(chunk_size, ctx_.cfg.use_direct_io);
                chunk.data->set_scrub_on_destroy(scrub);

                uint64_t rel_offset = c * chunk_size;
                chunk.offset = ctx_.data_start_sector * SECTOR_SIZE + rel_offset;
                chunk.size = std::min<uint64_t>(chunk_size, ctx_.total_size - rel_offset);
                chunk.start_sector = chunk.offset / SECTOR_SIZE;
                chunk.index = c;

                if (!safe_pread(ctx_.fd, chunk.data->data(), chunk.size, chunk.offset)) {
                    ctx_.log(LogLevel::Error, LogEvent::ChunkReadError, std::to_string(c));
                    err = true;
                    break;
                }

                if (err || ctx_.stop_requested) break;
                read_q.push(std::move(chunk));
            }
            read_q.close();
        });
    }

    std::vector<std::thread> spawn_workers(LimQueue<PipeChunk>& read_q, LimQueue<PipeChunk>& write_q, size_t chunk_size, std::atomic<bool>& err) {
        int ncpu = ctx_.cfg.num_threads > 0 ? ctx_.cfg.num_threads : 4;
        ctx_.log(LogLevel::Info, LogEvent::XtsFallback, "");

        std::vector<std::thread> workers;
        workers.reserve(ncpu);
        for (int t = 0; t < ncpu; t++) {
            workers.emplace_back([this, &read_q, &write_q, chunk_size, &err]() {
                AESXTSProc proc(ctx_.xts_key, ctx_.encrypt);
                PipeChunk chunk(chunk_size, ctx_.cfg.use_direct_io);
                while (read_q.pop(chunk) && !err && !ctx_.stop_requested) {
                    if (!proc.processBuffer(chunk.data->data(), chunk.size, chunk.start_sector)) {
                        ctx_.log(LogLevel::Error, LogEvent::ChunkProcessError, std::to_string(chunk.index));
                        err = true;
                        break;
                    }
                    write_q.push(std::move(chunk));
                    chunk = PipeChunk(chunk_size, ctx_.cfg.use_direct_io);
                }
            });
        }
        return workers;
    }

    std::thread spawn_writer(LimQueue<PipeChunk>& write_q, size_t chunk_size, uint64_t total_chunks,
        std::atomic<uint64_t>& done,
        std::atomic<uint64_t>& bytes_done,
        std::atomic<bool>& err) {
        const size_t kMaxReorder = static_cast<size_t>(ctx_.cfg.num_threads) * 4 + 64;
    return std::thread([this, &write_q, chunk_size, total_chunks, &done, &bytes_done, &err, kMaxReorder]() {
            PipeChunk chunk(chunk_size, ctx_.cfg.use_direct_io);
            uint64_t expected = 0;
            std::vector<PipeChunk> reorder;
            while (!err && !ctx_.stop_requested && expected < total_chunks) {
                if (!write_q.pop(chunk)) break;
                if (chunk.index == expected) {
                    if (!safe_pwrite(ctx_.fd, chunk.data->data(), chunk.size, chunk.offset)) {
                        ctx_.log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(chunk.index));
                        err = true;
                        break;
                    }
                    done++;
                    bytes_done += chunk.size;
                    ctx_.speed_meter.addBytes(chunk.size);
                    ctx_.progress(bytes_done.load(), ctx_.total_size, ctx_.speed_meter.getCurrentSpeed());
                    expected++;

                    int flush = (ctx_.device_type == DevType::HDD || ctx_.device_type == DevType::USB2) ? 2 : 1;
                    if (chunk.index % flush == 0) {
                        if (fsync(ctx_.fd) != 0) {
                            ctx_.log(LogLevel::Error, LogEvent::ProcessingFsyncFailed, "");
                            err = true;
                            break;
                        }
                    }

                    for (auto it = reorder.begin(); it != reorder.end(); ) {
                        if (it->index == expected) {
                            if (!safe_pwrite(ctx_.fd, it->data->data(), it->size, it->offset)) {
                                ctx_.log(LogLevel::Error, LogEvent::ChunkWriteError, std::to_string(it->index));
                                err = true;
                                break;
                            }
                            done++;
                            bytes_done += it->size;
                            ctx_.speed_meter.addBytes(it->size);
                            ctx_.progress(bytes_done.load(), ctx_.total_size, ctx_.speed_meter.getCurrentSpeed());
                            expected++;
                            it = reorder.erase(it);
                        } else ++it;
                    }
                } else if (chunk.index > expected) {
                    if (reorder.size() >= kMaxReorder) {
                        ctx_.log(LogLevel::Error, LogEvent::ReorderOverflow, "");
                        err = true;
                        break;
                    }
                    reorder.push_back(std::move(chunk));
                    chunk = PipeChunk(chunk_size, ctx_.cfg.use_direct_io);
                }
            }
            write_q.close();
        });
    }
};

bool runDataPipeline(const ProcessContext& ctx) {
    DataPipeline pipeline(DataPipeline::Context{
        ctx.fd, ctx.total_size, ctx.data_start_sector, ctx.cfg, ctx.device_type,
        ctx.xts_key, ctx.encrypt, ctx.speed_meter, ctx.stop_requested, ctx.log, ctx.progress
    });
    return pipeline.run();
}

bool runHeaderProcessorEncrypt(
    int fd, const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key,
    uint64_t data_start_sector, uint64_t total_sectors, HdrBackup& backup_mgr,
    Botan::secure_vector<uint8_t>& xts_key, FSInfo& fs_info,
    std::function<void(LogLevel, LogEvent, const std::string&)> log)
{
    log(LogLevel::Info, LogEvent::SaltGenerating, "");
    auto kdf_salt = KeyDeriv::generateSalt(KDF_SALT_SIZE);
    if (kdf_salt.empty()) { log(LogLevel::Error, LogEvent::SaltError, ""); return false; }

    log(LogLevel::Info, LogEvent::KeyDeriving, "");
    xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
    if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); return false; }
    log(LogLevel::Success, LogEvent::KeyDerived, "");

    EncUnitHdr hdr{};
    memcpy(hdr.kdf_salt, kdf_salt.data(), KDF_SALT_SIZE);
    hdr.version = HEADER_VERSION_CURRENT;
    hdr.data_start_sector = data_start_sector;
    hdr.total_sectors = total_sectors;
    hdr.fs_info = fs_info;

    if (!safe_pread(fd, hdr.orig_sector0, sizeof(hdr.orig_sector0), 0)) {
        log(LogLevel::Error, LogEvent::Sector0ReadFailed, "");
        return false;
    }
    log(LogLevel::Info, LogEvent::Sector0BackedUp, "");

    log(LogLevel::Info, LogEvent::KmacCalculating, "");
    try {
        KMACProc Kmac(master_key);
        auto m = Kmac.calculate(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac));
        if (m.size() == KMAC_SIZE) memcpy(hdr.Kmac, m.data(), KMAC_SIZE);
        else { log(LogLevel::Error, LogEvent::KmacSizeError, ""); return false; }
    } catch (const std::exception& e) {
        log(LogLevel::Error, LogEvent::KmacError, e.what());
        return false;
    }

    if (backup_mgr.saveHeader(unit.device_path, hdr, master_key)) {
        log(LogLevel::Success, LogEvent::BackupSaved, "");
    } else {
        log(LogLevel::Error, LogEvent::BackupSaveFailed, "");
        return false;
    }

    log(LogLevel::Info, LogEvent::HeaderWriting, "");
    {
        DirectIOGuard guard(fd);
        if (!guard.valid()) return false;
        if (!safe_pwrite(fd, &hdr, sizeof(hdr), HEADER_OFFSET_SECTORS * SECTOR_SIZE)) {
            log(LogLevel::Error, LogEvent::HeaderWriting, strerror(errno));
            return false;
        }
    }

    if (fsync(fd) != 0) {
        log(LogLevel::Error, LogEvent::HeaderWriting, strerror(errno));
        return false;
    }
    log(LogLevel::Success, LogEvent::HeaderWritten, "");
    return true;
}

bool runHeaderProcessorDecrypt(
    int fd, const StorUnit& unit, const Botan::secure_vector<uint8_t>& master_key,
    HdrBackup& backup_mgr, Botan::secure_vector<uint8_t>& xts_key,
    uint64_t& data_start_sector, FSInfo& fs_info,
    std::function<void(LogLevel, LogEvent, const std::string&)> log)
{
    EncUnitHdr hdr;
    log(LogLevel::Info, LogEvent::HeaderVerified, "reading");

    bool valid_header = read_enc_header(fd, hdr);

    if (!valid_header) {
        log(LogLevel::Warning, LogEvent::HeaderReadFailed, "");
        log(LogLevel::Info, LogEvent::HeaderBackupAttempting, "");
        if (backup_mgr.loadHeader(unit.device_path, hdr, master_key))
            log(LogLevel::Success, LogEvent::BackupLoaded, "");
        else {
            log(LogLevel::Error, LogEvent::BackupLoadFailed, "");
            return false;
        }
    }

    if (hdr.version < 2) {
        log(LogLevel::Warning, LogEvent::LegacyHeaderNoKdf, "");
        xts_key.resize(64);
        memcpy(xts_key.data(), master_key.data(), 32);
        memcpy(xts_key.data() + 32, master_key.data(), 32);
    } else {
        log(LogLevel::Info, LogEvent::KeyDeriving, "");
        Botan::secure_vector<uint8_t> kdf_salt(KDF_SALT_SIZE);
        memcpy(kdf_salt.data(), hdr.kdf_salt, KDF_SALT_SIZE);
        xts_key = KeyDeriv::deriveSubKey(master_key, kdf_salt, 64);
        if (xts_key.empty()) { log(LogLevel::Error, LogEvent::KeyDeriveError, ""); return false; }
        log(LogLevel::Success, LogEvent::KeyDerived, "");
    }

    log(LogLevel::Info, LogEvent::KmacCalculating, "verificando");
    try {
        KMACProc Kmac(master_key);
        if (!Kmac.verify(reinterpret_cast<uint8_t*>(&hdr), offsetof(EncUnitHdr, Kmac), hdr.Kmac, KMAC_SIZE)) {
            log(LogLevel::Error, LogEvent::KmacFailed, "");
            return false;
        }
    } catch (const std::exception& e) {
        log(LogLevel::Error, LogEvent::KmacError, e.what());
        return false;
    }
    log(LogLevel::Success, LogEvent::KmacVerified, "");

    if (hdr.version >= 4) {
        if (!safe_pwrite(fd, hdr.orig_sector0, sizeof(hdr.orig_sector0), 0)) {
            log(LogLevel::Warning, LogEvent::Sector0RestoreFailed, "");
        } else {
            log(LogLevel::Info, LogEvent::Sector0Restored, "");
        }
    }

    fs_info = hdr.fs_info;
    data_start_sector = hdr.data_start_sector;
    return true;
}

} // namespace unit_pipeline