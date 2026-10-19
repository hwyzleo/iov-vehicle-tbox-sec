#pragma once

//
// V2C 业务密钥开通公共契约（TBOX-SEC-DSN-CR-019 §2；CR-020 §4 增量修订）
//
// 调用方（TBOX-TSP）通过 <tbox/sec/client.h> 使用 getBusinessKeyStatus /
// importWrappedBusinessKeys / getBusinessKeyImportResult。本头文件只定义 DTO、
// 状态枚举和 SecureBuffer，不泄漏 framework-ipc / HSM / OpenSSL / protobuf 细节。
//
// 安全不变量：
//   - SEC 不返回明文业务密钥、可导出私钥引用或 HSM/slot handle；
//   - Wrapped Key 与 parameters 只在调用方有界缓冲与 SEC 安全路径短暂存在；
//   - SecureBuffer 不可复制，析构/clear 清零，成功与异常路径均清理。
//
// TBOX-SEC-DSN-CR-020：
//   - 首期只接受 KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1（§US-015）；
//   - parameters 为 EcdhEsP256EnvelopeParametersV1 的 deterministic Protobuf bytes，
//     其原始 bytes MUST 保留用于 envelopeDigest 重算，禁止 parse 后重新序列化替换原字节；
//   - ACK 回传 envelopeFormat / envelopeDigest / keyCheckValue（§US-020）。
//

#include <array>
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

/// 批次导入状态（US-011；结果查询/IPC 返回粒度的公开态）
enum class BusinessKeyImportState : uint8_t {
    REQUESTED = 0,  ///< 已受理，尚未完成解封装
    STAGED = 1,     ///< 两用途 staging 完整，未 commit
    COMMITTED = 2,  ///< 已原子激活（IMPORTED）
    FAILED = 3,     ///< 失败并已回滚
    UNKNOWN = 4     ///< 结果未知，需按 requestId 查询
};

/// 信封格式（TBOX-SEC-DSN-CR-020 §4 / PAR-PROTO-DSN-CR-007 §3）。
enum class KeyEnvelopeFormat : uint32_t {
    UNSPECIFIED = 0,
    ECDH_ES_P256_V1 = 1,  ///< 首期唯一受支持格式
};

/// 事务/恢复状态机阶段（TBOX-SEC-DSN-CR-020 §9）。
///
/// 与公开的 BusinessKeyImportState 分离：phase 是 journal 权威阶段，
/// state 是对调用方暴露的粗粒度结果。
enum class BusinessKeyImportPhase : uint8_t {
    NEW = 0,            ///< 已受理，尚未校验
    VALIDATED = 1,      ///< 全部前置校验通过
    PROCESSING = 2,     ///< 正在执行安全硬件解封
    UPLINK_STAGED = 3,  ///< UPLINK 已 staging
    BOTH_STAGED = 4,    ///< 两用途 staging 完整
    COMMITTING = 5,     ///< 正在提交
    SUCCEEDED = 6,      ///< 已原子激活（可返回 IMPORTED ACK）
    ROLLING_BACK = 7,   ///< 正在回滚
    FAILED = 8,         ///< 失败并已回滚
    OUTCOME_UNKNOWN = 9,///< 安全调用结果未知，需对账
    RECOVERING = 10,    ///< 启动恢复中
    UNKNOWN = 11        ///< 无法判定
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
    // ---- ACK 绑定字段（TBOX-SEC-DSN-CR-020 §7 / §US-020，非敏感）----
    KeyEnvelopeFormat envelope_format = KeyEnvelopeFormat::UNSPECIFIED;
    std::vector<uint8_t> envelope_digest;      ///< 32B canonical envelope SHA-256
    std::array<uint8_t, 3> key_check_value{};  ///< 3B KCV = first_3(SHA-256(businessKey))
    bool key_check_value_present = false;
    // ---- 逐 item Import Attestation（§7.3 / US-020）----
    std::vector<uint8_t> import_proof;         ///< 64B ECDSA P-256 P1363 low-S 原文
    std::string proof_algorithm;               ///< 固定 ECDSA_P256_SHA256_P1363
};

struct BusinessKeyStatusSet {
    std::vector<BusinessKeyStatus> items;
};

/// Wrapped Key 导入项（US-009；CR-020 §4 模型调整）。
///
/// - wrapped_key：AES-256-GCM 密文（仅 ciphertext，tag 在 parameters 中）；
/// - parameters：EcdhEsP256EnvelopeParametersV1 的 deterministic Protobuf bytes
///   （原始 bytes 保留用于 envelopeDigest 重算）；
/// - algorithm：业务密钥算法（受版本化 allowlist 约束）；
/// - wrapping_suite：版本化封装套件（首期 ECDH_ES_P256_HKDF_SHA256_AES256GCM）；
/// - envelope_format：首期 KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1；
/// - envelope_digest：由请求方按 canonical framing 计算的 32B 摘要（SEC 重算比对）；
/// - key_check_value：3B KCV（first_3(SHA-256(businessKey))），SEC 在 staging 校验。
struct WrappedKeyItem {
    std::string purpose;
    std::string key_id;
    uint64_t business_key_version = 0;
    std::string algorithm;
    SecureBuffer wrapped_key;
    SecureBuffer parameters;
    int64_t valid_from_ms = 0;
    int64_t valid_to_ms = 0;
    // ---- CR-020 增量字段 ----
    std::string wrapping_suite;
    KeyEnvelopeFormat envelope_format = KeyEnvelopeFormat::UNSPECIFIED;
    std::vector<uint8_t> envelope_digest;
    std::array<uint8_t, 3> key_check_value{};
    bool key_check_value_present = false;
};

/// 导入/结果查询返回（非敏感）。
struct ImportResult {
    std::string request_id;
    std::string business_domain;
    BusinessKeyImportState state = BusinessKeyImportState::UNKNOWN;
    std::vector<BusinessKeyStatus> items;
    int64_t committed_at_ms = 0;
    std::string provider_version_digest;
    SecureBuffer import_proof;  ///< 兼容/聚合位；首期 proof 逐 item 见 items[].import_proof
    std::string proof_algorithm;
    std::vector<uint8_t> binding_certificate_digest;  ///< ACK 绑定设备证书摘要 SHA-256(leaf DER)
};

std::string business_key_state_to_string(BusinessKeyState s);
BusinessKeyState string_to_business_key_state(const std::string& s);
std::string business_key_import_state_to_string(BusinessKeyImportState s);
BusinessKeyImportState string_to_business_key_import_state(const std::string& s);
std::string key_envelope_format_to_string(KeyEnvelopeFormat f);
KeyEnvelopeFormat string_to_key_envelope_format(const std::string& s);
std::string business_key_import_phase_to_string(BusinessKeyImportPhase p);
BusinessKeyImportPhase string_to_business_key_import_phase(const std::string& s);

/// 首期固定业务域与用途（US-009）
constexpr const char* kBusinessDomainV2c = "V2C_COMM";
constexpr const char* kBusinessPurposeUplinkAead = "UPLINK_AEAD";
constexpr const char* kBusinessPurposeDownlinkAead = "DOWNLINK_AEAD";

/// 首期唯一受支持的封装套件与信封格式（TBOX-SEC-DSN-CR-020 §4）。
constexpr const char* kKeyEnvelopeFormatEcdhEsP256V1 = "ECDH_ES_P256_V1";
constexpr const char* kWrappingSuiteEcdhEsP256 = "ECDH_ES_P256_HKDF_SHA256_AES256GCM";
constexpr const char* kDefaultKeyAlgorithm = "AES-256";
constexpr const char* kDefaultHkdfContextVersion = "v1";
constexpr const char* kProofContextV1 = "openiov|keyprov-ack|v1";

/// 首期固定 Import Attestation 算法（TBOX-SEC-DSN-CR-020 §7.3 / US-020）。
/// ECDSA P-256/SHA-256，IEEE-P1363 r(32)||s(32)、low-S、共 64 字节。
constexpr const char* kImportProofAlgorithmP1363 = "ECDSA_P256_SHA256_P1363";
constexpr std::size_t kImportProofSizeP1363 = 64;


} // namespace sec
} // namespace tbox
