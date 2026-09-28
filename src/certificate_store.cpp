#include "certificate_store.h"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <chrono>

namespace tbox {
namespace sec {

namespace {

constexpr const char* kManifestName = "manifest.json";
constexpr const char* kChainFileName = "device_cert_chain.pem";
constexpr const char* kDeviceCertFileName = "device_cert.json";

std::string dirJoin(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

bool makeDirs(const std::string& path) {
    // mkdir -p 语义
    std::string cur;
    for (auto& c : path) {
        cur += c;
        if (c == '/') {
            if (!cur.empty() && cur != "/") {
                ::mkdir(cur.c_str(), 0700);
            }
        }
    }
    ::mkdir(path.c_str(), 0700);
    struct stat st;
    return ::stat(path.c_str(), &st) == 0 && (st.st_mode & S_IFDIR);
}

} // anonymous namespace

CertificateStore::CertificateStore(std::string root)
    : root_(std::move(root)),
      generations_dir_(dirJoin(root_, "generations")),
      current_path_(dirJoin(root_, "CURRENT")) {}

// ---------------------------------------------------------------------------
// 文件系统原语
// ---------------------------------------------------------------------------

bool CertificateStore::fsyncFile(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    bool ok = (::fsync(fd) == 0);
    ::close(fd);
    return ok;
}

bool CertificateStore::fsyncDir(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0) return false;
    bool ok = (::fsync(fd) == 0);
    ::close(fd);
    return ok;
}

bool CertificateStore::writeFile(const std::string& path, const std::string& content) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < content.size()) {
        ssize_t n = ::write(fd, content.data() + off, content.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        off += static_cast<size_t>(n);
    }
    bool ok = (::fsync(fd) == 0);
    ::close(fd);
    return ok;
}

bool CertificateStore::writeFileAtomic(const std::string& path, const std::string& content) {
    std::string tmp = path + ".tmp";
    if (!writeFile(tmp, content)) return false;
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::remove(tmp.c_str());
        return false;
    }
    // fsync 父目录保证 rename 持久化
    std::string parent = path;
    auto slash = parent.find_last_of('/');
    if (slash != std::string::npos) parent.resize(slash);
    fsyncDir(parent);
    return true;
}

std::string CertificateStore::readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

std::string CertificateStore::sha256Hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out += hex[hash[i] >> 4];
        out += hex[hash[i] & 0x0F];
    }
    return out;
}

std::string CertificateStore::newGenerationId() {
    unsigned char rnd[8];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
        // 极低概率：用时间戳兜底（不影响正确性，只影响唯一性）
        for (auto& b : rnd) b = 0;
    }
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    static const char* hex = "0123456789abcdef";
    std::string out = "g-";
    out += std::to_string(now);
    out += "-";
    for (int i = 0; i < 8; ++i) {
        out += hex[rnd[i] >> 4];
        out += hex[rnd[i] & 0x0F];
    }
    return out;
}

// ---------------------------------------------------------------------------
// generation 生命周期
// ---------------------------------------------------------------------------

bool CertificateStore::writeGeneration(const Generation& g) const {
    if (!makeDirs(g.dir)) return false;

    // 1) 内容文件（目录内原子写）
    if (!writeFileAtomic(dirJoin(g.dir, kChainFileName), g.device_cert_chain_pem)) return false;
    if (!writeFileAtomic(dirJoin(g.dir, kDeviceCertFileName), g.device_cert.dump())) return false;

    // 2) manifest（含文件清单/长度/SHA-256）
    nlohmann::json files;
    auto chain = g.device_cert_chain_pem;
    auto dc = g.device_cert.dump();
    files[kChainFileName] = {
        {"length", chain.size()},
        {"sha256", sha256Hex(chain)},
    };
    files[kDeviceCertFileName] = {
        {"length", dc.size()},
        {"sha256", sha256Hex(dc)},
    };

    nlohmann::json manifest;
    manifest["gid"] = g.generation_id;
    manifest["previous_generation"] = g.previous_generation;
    manifest["version"] = g.version;
    manifest["provision_state"] = g.provision_state;
    manifest["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    manifest["files"] = files;

    std::string manifest_str = manifest.dump();
    if (!writeFileAtomic(dirJoin(g.dir, kManifestName), manifest_str)) return false;

    // 3) fsync generation 目录（保证 manifest + 内容文件落盘）
    return fsyncDir(g.dir);
}

std::optional<CertificateStore::Generation>
CertificateStore::loadGeneration(const std::string& gid) const {
    std::string dir = dirJoin(generations_dir_, gid);
    std::string manifest_str = readFile(dirJoin(dir, kManifestName));
    if (manifest_str.empty()) return std::nullopt;

    nlohmann::json m;
    try {
        m = nlohmann::json::parse(manifest_str);
    } catch (...) {
        return std::nullopt;
    }

    Generation g;
    g.generation_id = m.value("gid", "");
    if (g.generation_id != gid) return std::nullopt;
    g.previous_generation = m.value("previous_generation", "");
    g.version = m.value("version", 0ULL);
    g.provision_state = m.value("provision_state", "");
    g.dir = dir;

    // 校验文件清单/长度/SHA-256
    if (!m.contains("files") || !m["files"].is_object()) return std::nullopt;
    for (auto it = m["files"].begin(); it != m["files"].end(); ++it) {
        const std::string& name = it.key();
        auto& meta = it.value();
        if (!meta.contains("length") || !meta.contains("sha256")) return std::nullopt;
        size_t expect_len = meta["length"].get<uint64_t>();
        std::string expect_sha = meta["sha256"].get<std::string>();
        std::string content = readFile(dirJoin(dir, name));
        if (content.size() != expect_len) return std::nullopt;
        if (sha256Hex(content) != expect_sha) return std::nullopt;
        if (name == kChainFileName) {
            g.device_cert_chain_pem = std::move(content);
        } else if (name == kDeviceCertFileName) {
            try {
                g.device_cert = nlohmann::json::parse(content);
            } catch (...) {
                return std::nullopt;
            }
        }
    }

    // 必须包含证书链材料
    if (g.device_cert_chain_pem.empty() || !g.device_cert.is_object()) {
        return std::nullopt;
    }
    return g;
}

bool CertificateStore::switchCurrent(const std::string& gid) {
    // 唯一线性化点：CURRENT.tmp(fsync) -> rename CURRENT -> fsync 父目录
    if (!writeFileAtomic(current_path_, gid + "\n")) return false;
    return fsyncDir(root_);
}

std::optional<std::string> CertificateStore::readCurrentPointer() const {
    std::string content = readFile(current_path_);
    if (content.empty()) return std::nullopt;
    std::string gid;
    for (char c : content) {
        if (c == '\n' || c == '\r') break;
        gid += c;
    }
    if (gid.empty()) return std::nullopt;
    return gid;
}

void CertificateStore::cleanupOrphans(const std::string& keep_a, const std::string& keep_b) {
    DIR* dir = opendir(generations_dir_.c_str());
    if (!dir) return;
    struct dirent* e;
    while ((e = readdir(dir)) != nullptr) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        if (name == keep_a || name == keep_b) continue;
        std::string full = dirJoin(generations_dir_, name);
        // 仅清理目录（candidate / 损坏 generation）
        struct stat st;
        if (::stat(full.c_str(), &st) == 0 && (st.st_mode & S_IFDIR)) {
            ::remove(dirJoin(full, kManifestName).c_str());
            ::remove(dirJoin(full, kChainFileName).c_str());
            ::remove(dirJoin(full, kDeviceCertFileName).c_str());
            ::remove(dirJoin(full, kManifestName + std::string(".tmp")).c_str());
            ::remove(dirJoin(full, kChainFileName + std::string(".tmp")).c_str());
            ::remove(dirJoin(full, kDeviceCertFileName + std::string(".tmp")).c_str());
            ::rmdir(full.c_str());
        }
    }
    closedir(dir);
}

// ---------------------------------------------------------------------------
// 公共 API
// ---------------------------------------------------------------------------

bool CertificateStore::openAndRecover() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!makeDirs(generations_dir_)) return false;

    // 1) 读取 CURRENT 指向
    auto ptr = readCurrentPointer();

    // 2) CURRENT 有效 -> 直接采用
    if (ptr) {
        auto gen = loadGeneration(*ptr);
        if (gen) {
            current_generation_ = std::move(gen);
            // 保留 current 与 previous 两代，清理其余 orphan
            cleanupOrphans(current_generation_->generation_id,
                           current_generation_->previous_generation);
            recovered_ = true;
            return true;
        }
        // CURRENT 指向无效 generation：沿 manifest.previous_generation 回退
        // （manifest 若能解析出 previous 链）
        std::string fallback = *ptr;
        std::string prev;
        {
            std::string dir = dirJoin(generations_dir_, fallback);
            std::string manifest_str = readFile(dirJoin(dir, kManifestName));
            if (!manifest_str.empty()) {
                try {
                    auto m = nlohmann::json::parse(manifest_str);
                    prev = m.value("previous_generation", "");
                } catch (...) {}
            }
        }
        while (!prev.empty()) {
            auto gen = loadGeneration(prev);
            if (gen) {
                current_generation_ = std::move(gen);
                cleanupOrphans(current_generation_->generation_id,
                               current_generation_->previous_generation);
                recovered_ = true;
                return true;
            }
            // 继续沿链回退
            std::string dir = dirJoin(generations_dir_, prev);
            std::string manifest_str = readFile(dirJoin(dir, kManifestName));
            std::string next;
            if (!manifest_str.empty()) {
                try {
                    auto m = nlohmann::json::parse(manifest_str);
                    next = m.value("previous_generation", "");
                } catch (...) {}
            }
            prev = next;
        }
        // 回退链耗尽：无完整 commit，进入 ERROR（保持无当前，fail-closed）
        cleanupOrphans("", "");
        recovered_ = false;
        return false;
    }

    // 3) 无 CURRENT（首次/全新）：无当前 generation；清理所有 candidate
    cleanupOrphans("", "");
    current_generation_ = std::nullopt;
    recovered_ = true;
    return true;
}

ErrorCode CertificateStore::commit(const CertificateCommit& commit) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!recovered_) {
        return ErrorCode::STORAGE_CORRUPTION;
    }
    if (commit.device_cert_chain_pem.empty()) {
        return ErrorCode::INVALID_PARAMETER;
    }

    Generation g;
    g.generation_id = newGenerationId();
    g.previous_generation = current_generation_ ? current_generation_->generation_id : "";
    g.dir = dirJoin(generations_dir_, g.generation_id);
    g.device_cert_chain_pem = commit.device_cert_chain_pem;
    try {
        g.device_cert = nlohmann::json::parse(commit.device_cert_json);
    } catch (...) {
        return ErrorCode::INVALID_PARAMETER;
    }
    g.provision_state = commit.provision_state;
    g.version = commit.version;

    // 1) 写入非当前 generation（暂存）
    if (!writeGeneration(g)) {
        // 清理 candidate
        ::remove(dirJoin(g.dir, kManifestName).c_str());
        ::remove(dirJoin(g.dir, kChainFileName).c_str());
        ::remove(dirJoin(g.dir, kDeviceCertFileName).c_str());
        ::rmdir(g.dir.c_str());
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    // 2) 自校验（manifest + 文件可完整读取）
    auto check = loadGeneration(g.generation_id);
    if (!check) {
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    // 3) 唯一线性化点：切换 CURRENT
    if (!switchCurrent(g.generation_id)) {
        // CURRENT 未切换：旧 generation 仍有效，candidate 视为 orphan
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    current_generation_ = std::move(g);
    // 4) 清理不再引用的 orphan（保留 current + previous）
    cleanupOrphans(current_generation_->generation_id,
                   current_generation_->previous_generation);
    return ErrorCode::SUCCESS;
}

std::string CertificateStore::currentDeviceCertChain() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_generation_ ? current_generation_->device_cert_chain_pem : "";
}

std::optional<CertificateSnapshot> CertificateStore::currentSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!current_generation_) return std::nullopt;
    CertificateSnapshot s;
    s.generation_id = current_generation_->generation_id;
    s.device_cert_chain_pem = current_generation_->device_cert_chain_pem;
    s.device_cert = current_generation_->device_cert;
    s.provision_state = current_generation_->provision_state;
    s.version = current_generation_->version;
    return s;
}

std::string CertificateStore::currentChainDigest() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!current_generation_) return "";
    return sha256Hex(current_generation_->device_cert_chain_pem);
}

bool CertificateStore::hasCurrent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_generation_.has_value();
}

} // namespace sec
} // namespace tbox
