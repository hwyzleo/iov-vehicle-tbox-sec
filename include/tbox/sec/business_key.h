#pragma once

//
// V2C 业务密钥开通公共契约（TBOX-SEC-DSN-CR-019 §2）
//
// 调用方（TBOX-TSP）通过 <tbox/sec/client.h> 使用 getBusinessKeyStatus /
// importWrappedBusinessKeys / getBusinessKeyImportResult。本头文件只定义 DTO、
// 状态枚举和 SecureBuffer，不泄漏 framework-ipc / HSM / OpenSSL 细节。
//
// 安全不变量：
//   - SEC 不返回明文业务密钥、可导出私钥引用或 HSM/slot handle；
//   - Wrapped Key 与 parameters 只在调用方有界缓冲与 SEC 安全路径短暂存在；
//   - SecureBuffer 不可复制，析构/clear 清零，成功与异常路径均清理。
//

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

/// 业务密钥件内状态（US-008）
enum class BusinessKeyState : uint8_t {
    MISSING = 0,  ///< 件内无该用途密钥
    STAGED = 1,   ///< 已解封装到 staging，尚未激活
    ACTIVE = 2,   ///< 已激活可用
    INVALID = 3,  ///< ledger 与 slot 不一致或材料失效
    UNKNOWN = 4   ///< 无法判定（provider/journal 不可用）
};

/// 批次导入状态（US-011）
enum class BusinessKeyImportState : uint8_t {
    REQUESTED = 0,  ///< 已受理，尚未完成解封装
    STAGED = 1,     ///< 两用途 staging 完整，未 commit
    COMMITTED = 2,  ///< 已原子激活
    FAILED = 3,     ///< 失败并已回滚
    UNKNOWN = 4     ///< 结果未知，需按 requestId 查询
};

/// 不可复制、可清零的有界敏感缓冲。
///
/// 仅提供移动语义；析构与 clear() 先清零再释放。调用方完成使用后应立即 clear()。
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(std::vector<uint8_t> data);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    bool empty() const noexcept { return bytes_.empty(); }
    std::size_t size() const noexcept { return bytes_.size(); }
    const uint8_t* data() const noexcept { return bytes_.data(); }
    uint8_t* data() noexcept { return bytes_.data(); }

    /// 调整大小（新字节清零）。可能重新分配。
    void resize(std::size_t n);

    /// 用给定字节替换内容。
    void assign(const uint8_t* data, std::size_t n);
    void assign(const std::vector<uint8_t>& data);

    /// 清零并释放。
    void clear();

    /// 只读视图（不复制）。
    const std::vector<uint8_t>& bytes() const noexcept { return bytes_; }

private:
    std::vector<uint8_t> bytes_;
};

/// 单用途业务密钥状态（不含 key bytes / 可导出句柄 / 完整 keyId / slotRef）
struct BusinessKeyStatus {
    std::string business_domain;
    std::string purpose;
    uint64_t business_key_version = 0;
    BusinessKeyState state = BusinessKeyState::UNKNOWN;
    std::string key_id_digest;  ///< 不可逆摘要
    std::string algorithm;
    int64_t valid_from_ms = 0;
    int64_t valid_to_ms = 0;
};

struct BusinessKeyStatusSet {
    std::vector<BusinessKeyStatus> items;
};

/// Wrapped Key 导入项（US-009）。
///
/// - wrapped_key：密文（含 AEAD tag），不可复制、使用后清零；
/// - parameters：非秘密封装参数（封装套件、ephemeral 公钥、IV、AAD 摘要等）；
/// - algorithm：业务密钥算法（受版本化 allowlist 约束）。
struct WrappedKeyItem {
    std::string purpose;
    std::string key_id;
    uint64_t business_key_version = 0;
    std::string algorithm;
    SecureBuffer wrapped_key;
    SecureBuffer parameters;
    int64_t valid_from_ms = 0;
    int64_t valid_to_ms = 0;
};

/// 导入/结果查询返回（非敏感）。
struct ImportResult {
    std::string request_id;
    std::string business_domain;
    BusinessKeyImportState state = BusinessKeyImportState::UNKNOWN;
    std::vector<BusinessKeyStatus> items;
    int64_t committed_at_ms = 0;
    std::string provider_version_digest;
    SecureBuffer import_proof;  ///< 非敏感持钥证明原文（仅返回调用方，不入日志/Store）
    std::string proof_algorithm;
};

std::string business_key_state_to_string(BusinessKeyState s);
BusinessKeyState string_to_business_key_state(const std::string& s);
std::string business_key_import_state_to_string(BusinessKeyImportState s);
BusinessKeyImportState string_to_business_key_import_state(const std::string& s);

/// 首期固定业务域与用途（US-009）
constexpr const char* kBusinessDomainV2c = "V2C_COMM";
constexpr const char* kBusinessPurposeUplinkAead = "UPLINK_AEAD";
constexpr const char* kBusinessPurposeDownlinkAead = "DOWNLINK_AEAD";

} // namespace sec
} // namespace tbox
