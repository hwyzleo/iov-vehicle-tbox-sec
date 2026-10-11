#pragma once

//
// V2C 业务密钥件内提供者抽象（TBOX-SEC-DSN-CR-019 §4/§5/§8）。
//
// BusinessKeyProvider 是"件内解封装 + 双槽批次事务 + 持钥证明"的安全边界：
//   - unwrapToStaging：在 HSM/eSE 内执行 unwrap-to-slot，明文不返回主机普通内存；
//   - commitBatch / rollbackStaging：原子切换 ACTIVE 或回滚 staging；
//   - querySlot：读取权威 slot 状态（供 ledger 交叉校验）；
//   - generateProof：使用实际导入密钥做 HMAC/CMAC 或设备证明密钥签名。
//
// production 缺少可信 HSM/eSE 能力时 provider 保持 NOT_READY（fail-closed），
// 禁止软件明文降级；SoftFile provider 仅允许显式非生产 profile。
//

#include "tbox/sec/business_key.h"
#include "error_codes.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

/// 件内 slot 权威状态（不含 key bytes / slot handle）
struct BusinessKeySlotInfo {
    bool present = false;
    BusinessKeyState state = BusinessKeyState::MISSING;
    uint64_t business_key_version = 0;
    std::string key_id_digest;
    std::string algorithm;
    int64_t valid_from_ms = 0;
    int64_t valid_to_ms = 0;
    uint64_t active_generation = 0;
};

/// 当前设备解封装身份绑定（来自设备证书 / 专用 key-encipherment 身份）。
/// Wrapped Key 必须绑定该身份；未就绪时 provider 返回 NOT_READY。
struct BusinessKeyDeviceBinding {
    bool ready = false;
    std::string device_identity;             ///< hsm_uid / ecu_uid
    std::string device_key_id;               ///< HSM 内设备密钥 key_id
    std::vector<uint8_t> device_public_key;  ///< 未压缩 EC 公钥（65B，P-256）

    void clearPublicKey() {
        if (!device_public_key.empty()) {
            volatile uint8_t* p = device_public_key.data();
            for (size_t i = 0; i < device_public_key.size(); ++i) p[i] = 0;
            device_public_key.clear();
        }
    }
};

/// 当前设备解封装身份提供者（由组合根注入）。
using BusinessKeyDeviceBindingProvider = std::function<BusinessKeyDeviceBinding()>;

/// 导入 journal 条目（掉电安全 + 防篡改；按 request_id_digest 索引）。
struct BusinessKeyJournalEntry {
    std::string request_id_digest;  ///< 不可逆摘要（journal 主键）
    std::string request_digest;     ///< 覆盖域/完整 item 元数据/Wrapped Key 摘要/算法参数的规范化摘要
    BusinessKeyImportState state = BusinessKeyImportState::UNKNOWN;
    uint64_t generation = 0;
    std::vector<BusinessKeyStatus> items;  ///< 非敏感结果元数据
    int64_t created_at_ms = 0;
    int64_t committed_at_ms = 0;
    std::string provider_version_digest;
    std::string last_error;  ///< 符号名；仅内部恢复使用
};

class BusinessKeyProvider {
public:
    virtual ~BusinessKeyProvider() = default;

    /// 打开 secure journal / slot 存储；失败则 provider NOT_READY。
    virtual ErrorCode initialize() = 0;

    /// 是否具备可用的可信 provider + 设备解封装身份（production fail-closed）。
    virtual bool isReady() const = 0;

    /// provider 非秘密版本摘要（进入 importProof / 结果）。
    virtual std::string providerVersionDigest() const = 0;

    /// 在 HSM/eSE 内 unwrap-to-slot（STAGING），明文不返回主机普通内存。
    /// @param aad       由 SEC 依据 requestId/purpose/version/device identity 构造
    /// @param binding   当前设备解封装身份
    /// @param generation 本次批次 generation（用于 staging 隔离）
    virtual ErrorCode unwrapToStaging(const std::string& domain,
                                      const WrappedKeyItem& item,
                                      const std::vector<uint8_t>& aad,
                                      const BusinessKeyDeviceBinding& binding,
                                      uint64_t generation) = 0;

    /// 分别验证 staging 槽的算法/长度/用途/可用性。
    virtual ErrorCode verifyStaging(const std::string& domain,
                                    const std::string& purpose) = 0;

    /// 原子提交本 generation 的双 staging 为 ACTIVE。
    /// 提交前旧 ACTIVE 必须保持可用；任一失败不得形成单用途 ACTIVE。
    virtual ErrorCode commitBatch(const std::string& domain, uint64_t generation) = 0;

    /// 回滚本 generation 的 staging，保留旧 ACTIVE。
    virtual ErrorCode rollbackStaging(const std::string& domain, uint64_t generation) = 0;

    /// 查询指定用途的权威 slot 状态。
    virtual ErrorCode querySlot(const std::string& domain,
                                const std::string& purpose,
                                BusinessKeySlotInfo& out) = 0;

    /// 使用实际导入的 ACTIVE 密钥生成非敏感持钥证明。
    virtual ErrorCode generateProof(const std::string& domain,
                                    const std::string& purpose,
                                    uint64_t business_key_version,
                                    const std::string& request_id,
                                    const std::string& key_id_digest,
                                    std::vector<uint8_t>& proof,
                                    std::string& algorithm) = 0;

    // ---- Import journal（掉电安全 + 防篡改；authoritative requestId 幂等）----
    /// 读取 journal 条目；不存在返回 false。
    virtual bool loadJournal(const std::string& request_id_digest,
                             BusinessKeyJournalEntry& out) = 0;
    /// 写入/覆盖 journal 条目（原子、防篡改）。
    virtual ErrorCode saveJournal(const BusinessKeyJournalEntry& entry) = 0;
    /// 列出全部 journal 条目（用于启动恢复）。
    virtual std::vector<BusinessKeyJournalEntry> listJournal() = 0;
    /// 是否存在任何未终结（REQUESTED/STAGED/UNKNOWN）的 staging。
    virtual bool hasPendingStaging() const = 0;
};

} // namespace sec
} // namespace tbox
