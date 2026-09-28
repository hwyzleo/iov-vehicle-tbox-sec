#pragma once

#include <string>
#include <optional>
#include <mutex>
#include <nlohmann/json.hpp>
#include "tbox/sec/errors.h"

namespace tbox {
namespace sec {

/// 一次证书安装的原子提交载荷（TBOX-SEC-DSN-CR-014 §4.1）
struct CertificateCommit {
    std::string device_cert_chain_pem;  ///< canonical PEM，leaf -> intermediate
    std::string device_cert_json;       ///< DeviceCert 档案快照（JSON 字符串）
    std::string provision_state;        ///< 目标 ProvisionState（如 "CERT_INSTALLED"）
    uint64_t version = 0;               ///< 本次提交后的凭据版本（调用方保证单调递增）
};

/// 当前生效 generation 的只读快照
struct CertificateSnapshot {
    std::string generation_id;
    std::string device_cert_chain_pem;  ///< canonical PEM，leaf -> intermediate
    nlohmann::json device_cert;         ///< DeviceCert 档案快照
    std::string provision_state;
    uint64_t version = 0;
};

/// 跨键原子证书存储（immutable generation + commit manifest + 单文件 CURRENT 指针）
///
/// framework-store 仅保证单键原子写（temp + fsync + rename），不提供跨键事务。
/// 本模块以不可变 generation 目录 + manifest + CURRENT 单文件指针实现跨键一致性：
///   - 每次安装写入新 generation（非当前），fsync 并自校验后原子切换 CURRENT；
///   - 读取方只承认 CURRENT 指向且 manifest/文件摘要完整的 generation；
///   - 启动恢复：未被 CURRENT 引用的 candidate 视为 orphan 清理；残留 CURRENT.tmp
///     忽略（旧 CURRENT 继续有效）；CURRENT 损坏时沿 manifest.previous_generation
///     回退到最后一个完整 commit，否则保持原安全状态（无当前）进入 ERROR。
///
/// 布局：
///   <root>/
///   ├── CURRENT                    # 单行 generation_id（唯一线性化点）
///   ├── CURRENT.tmp                # 切换中的临时指针（崩溃残留即 orphan）
///   └── generations/<gid>/
///       ├── manifest.json          # {gid, previous_generation, version,
///       │                          #  provision_state, created_at, files:{name:{length,sha256}}}
///       ├── device_cert_chain.pem
///       └── device_cert.json
class CertificateStore {
public:
    explicit CertificateStore(std::string root);
    ~CertificateStore() = default;

    CertificateStore(const CertificateStore&) = delete;
    CertificateStore& operator=(const CertificateStore&) = delete;

    /// 打开并执行启动恢复。必须在使用前调用一次。
    /// 成功返回 true（无当前 generation 也视为成功）；恢复无法收敛时返回 false
    /// （调用方应 fail-closed，不对外提供凭据）。
    bool openAndRecover();

    /// 原子提交一次安装。成功后 CURRENT 指向新 generation；失败时旧 generation
    /// 保持有效，磁盘上不出现跨代混合状态。
    ErrorCode commit(const CertificateCommit& commit);

    /// 当前生效的客户端证书链（CURRENT 指向的 generation 的 PEM 文本；无则空串）
    std::string currentDeviceCertChain() const;

    /// 当前生效快照（无当前 generation 或不可用时返回 nullopt）
    std::optional<CertificateSnapshot> currentSnapshot() const;

    /// 当前 canonical PEM 的 SHA-256 十六进制摘要（幂等判重用；无则空串）
    std::string currentChainDigest() const;

    bool hasCurrent() const;

    const std::string& root() const { return root_; }

private:
    struct Generation {
        std::string generation_id;
        std::string previous_generation;
        std::string dir;                     ///< 绝对路径
        std::string device_cert_chain_pem;
        nlohmann::json device_cert;
        std::string provision_state;
        uint64_t version = 0;
    };

    // ---- 文件系统原语 ----
    static bool fsyncFile(const std::string& path);
    static bool fsyncDir(const std::string& path);
    /// 原子写：path.tmp -> fsync -> rename -> fsync 父目录
    static bool writeFileAtomic(const std::string& path, const std::string& content);
    static bool writeFile(const std::string& path, const std::string& content);
    static std::string readFile(const std::string& path);
    static std::string sha256Hex(const std::string& data);
    static std::string newGenerationId();

    // ---- generation 生命周期 ----
    /// 加载并校验 generation：manifest 可解析、文件清单/长度/SHA-256 全部匹配。
    std::optional<Generation> loadGeneration(const std::string& gid) const;
    /// 写入 generation 目录全部文件并 fsync（不切换 CURRENT）。
    bool writeGeneration(const Generation& g) const;
    /// 唯一线性化点：CURRENT.tmp(fsync) -> rename CURRENT -> fsync 父目录。
    bool switchCurrent(const std::string& gid);
    /// 读取 CURRENT 指向的 gid（无/损坏返回 nullopt）。
    std::optional<std::string> readCurrentPointer() const;
    /// 清理未被 current/previous 引用的 generation 目录。
    void cleanupOrphans(const std::string& keep_a, const std::string& keep_b);

    std::string root_;
    std::string generations_dir_;
    std::string current_path_;
    std::optional<Generation> current_generation_;
    bool recovered_ = false;
    mutable std::mutex mutex_;
};

} // namespace sec
} // namespace tbox
