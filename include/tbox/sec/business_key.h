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
///
/// TBOX-SEC-DSN-CR-021：底层类型为 std::uint32_t；NOT_FOUND 为 additive 值
/// （下一个未使用数值），不得重排或复用既有 wire 数值。
enum class BusinessKeyImportState : uint32_t {
    REQUESTED = 0,  ///< 已受理，尚未完成解封装
    STAGED = 1,     ///< 两用途 staging 完整，未 commit
    COMMITTED = 2,  ///< 已原子激活（IMPORTED）
    FAILED = 3,     ///< 失败并已回滚
    UNKNOWN = 4,    ///< 结果未知，需按 requestId 查询
    NOT_FOUND = 5   ///< 无该 requestId 记录且无事务残留（仅结构化 journal 证明无痕迹时返回）
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
    // ---- ACK 绑定字段（TBOX-SEC-DSN-CR-022 §4 / VEH-PROTO §7.2.2，非敏感）----
    KeyEnvelopeFormat envelope_format = KeyEnvelopeFormat::UNSPECIFIED;
    // wireEnvelopeDigest = PAR_PROTO_KEYPROV_ECDH_ES_P256_V1 9 字段 SHA-256；
    // 不是 FW-SEC 18 字段 coreEnvelopeDigest。
    std::vector<uint8_t> envelope_digest;      ///< 32B wireEnvelopeDigest
    std::array<uint8_t, 3> key_check_value{};  ///< 3B 实际 KCV = first_3(SHA-256(businessKey))（非透传）
    bool key_check_value_present = false;
    // ---- 逐 item Import Attestation（§7.3 / US-020）----
    std::vector<uint8_t> import_proof;         ///< 64B ECDSA P-256 P1363 low-S 原文
    std::string proof_algorithm;               ///< 固定 ECDSA_P256_SHA256_P1363
    // ---- 原 ACK 重建材料（TBOX-TSP-DSN-CR-012 Q3：journal/result 事实源）----
    // key_id 为 OperationalMetadata（非秘密），由 SEC journal 在结果查询时原样返回，
    // 使 TSP 重启后无需第二套事实源即可重建 ack.key_id == response.key_id；
    // 该字段不进入 ledger（ledger 仍只保存 key_id_digest）。
    std::string key_id;                              ///< 完整 keyId（非敏感）
    std::vector<uint8_t> recipient_certificate_digest;  ///< 32B 绑定证书策略摘要（逐 item）
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
/// - envelope_digest：9 字段 wireEnvelopeDigest（SEC 以原始 wrappedKey/parameters 重算比对；
///   非 FW coreEnvelopeDigest）；
/// - key_check_value：3B 期望 KCV；SEC 在 staging 从实际密钥重算并常量时间比较（非透传）。
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

/// V2C 密钥开通能力上报（TBOX-SEC-DSN-CR-020 §11 / US-022；
/// TBOX-TSP-DSN-CR-012 §8 增量）。
///
/// READY = 以下全部合取。任一缺失时仅允许状态查询/诊断，不接受新信封。
/// PKI 未签发兼容 `keyAgreement` 证书时，代码/测试可发布，但 capability 不上报 v1、
/// 导入返回 BUSINESS_KEY_NOT_READY。
///
/// 契约版本语义（TBOX-SEC-DSN-CR-020 §11 修订）：
///   - kContractVersion=2 为当前完整字段集合；消费者必须按整值 allowlist 精确匹配，
///     缺失/未知版本一律判 NOT_READY（fail-closed）；
///   - v1 不得被解释为 ECDH-ES v1 READY：旧消费者收到 v2（未知）按 fail-closed
///     判定 Keyprov 不可用；新消费者识别 v1（旧结构）只能判定新 Keyprov 不可用；
///   - 禁止缺字段默认 true、版本别名或静默降级；
///   - 状态查询/诊断可在版本不匹配时保留，但不得接受新的 ECDH-ES 导入。
///
/// 本结构位于公开 SDK 头，供 TSP 通过 SecClient 只读查询。
struct V2cKeyProvisioningCapability {
    /// capability 契约版本；消费者按整值 allowlist 精确匹配，缺失/未知判 NOT_READY。
    static constexpr uint32_t kContractVersion = 2;
    uint32_t capability_contract_version = kContractVersion;

    // ---- TBOX-TSP-DSN-CR-012 §8 显式门禁（TSP 侧 readiness 直接消费）----
    bool envelope_v1_import_ready = false;              ///< ECDH_ES_P256_V1 导入能力
    bool atomic_dual_purpose_commit_ready = false;      ///< 双用途原子提交能力
    bool import_proof_sign_ecdsa_p256_v1_ready = false; ///< 每用途 P1363 Import Attestation 签名能力
    bool secure_journal_replay_ready = false;           ///< 安全 journal 原 proof 重放能力

    // ---- 证书生产闭环 / 逻辑 Profile 门禁（TBOX-SEC-DSN-CR-020 §2.1/§11 修订）----
    bool identity_key_template_sign_derive = false;     ///< 设备密钥模板/句柄支持 sign+derive（不可导出）
    bool csr_key_usage_request_matched = false;         ///< CSR 请求 KU=digitalSignature+keyAgreement
    bool certificate_profile_matched = false;           ///< 逻辑 Profile TBOX_DEVICE_ECDH_ES_P256_V1 匹配
    bool certificate_chain_and_key_match = false;       ///< 链/证书公钥与本地句柄公钥匹配
    bool certificate_critical_extensions_allowed = false; ///< 关键扩展满足 allowlist（未知关键扩展 fail-closed）
    bool leaf_certificate_digest_bound = false;         ///< 原始 leaf DER SHA-256 已绑定

    // ---- 详细能力（诊断 / 内部合取）----
    bool proto_release_matched = false;          ///< PAR-PROTO release/DescriptorSet 锁定已安装
    bool envelope_format_v1 = false;             ///< 本构建已实现 ECDH_ES_P256_V1
    bool p256_ecdh = false;                      ///< HSM/eSE 支持 P-256 ECDH
    bool hkdf_sha256 = false;                    ///< HSM/eSE 支持 HKDF-SHA-256
    bool aes256_gcm_decrypt_to_slot = false;     ///< 支持 AES-256-GCM decrypt-to-slot
    bool atomic_dual_slot_commit = false;        ///< 支持双槽原子提交
    bool active_certificate_key_agreement = false;    ///< ACTIVE 证书 KU 含 keyAgreement
    bool active_certificate_digital_signature = false;///< ACTIVE 证书 KU 含 digitalSignature
    bool active_private_key_can_derive = false;  ///< 私钥句柄支持 ECDH derive（不可导出）
    bool active_private_key_can_sign = false;    ///< 同一私钥句柄支持 ECDSA sign（不可导出）
    bool ecdsa_p256_sha256_p1363 = false;        ///< HSM/eSE 支持 ECDSA P-256/SHA-256 P1363
    bool secure_journal_ready = false;           ///< 安全 journal / ledger 可用
    bool trusted_time_ready = false;             ///< 可信时间可用

    // ---- TBOX-SEC-DSN-CR-021：NOT_FOUND 结果查询能力（仅可观测/灰度）----
    // 该字段不参与 all() 合取，也不得被调用方用于在 capability 缺失时把
    // UNKNOWN 转换为 NOT_FOUND；只用于可观测性与灰度发布比对。
    bool business_key_import_result_not_found_v1 = false;

    bool all() const {
        return envelope_v1_import_ready && atomic_dual_purpose_commit_ready &&
               import_proof_sign_ecdsa_p256_v1_ready && secure_journal_replay_ready &&
               identity_key_template_sign_derive && csr_key_usage_request_matched &&
               certificate_profile_matched && certificate_chain_and_key_match &&
               certificate_critical_extensions_allowed && leaf_certificate_digest_bound &&
               proto_release_matched && envelope_format_v1 && p256_ecdh && hkdf_sha256 &&
               aes256_gcm_decrypt_to_slot && atomic_dual_slot_commit &&
               active_certificate_key_agreement && active_certificate_digital_signature &&
               active_private_key_can_derive && active_private_key_can_sign &&
               ecdsa_p256_sha256_p1363 && secure_journal_ready && trusted_time_ready;
    }
};

std::string business_key_state_to_string(BusinessKeyState s);
BusinessKeyState string_to_business_key_state(const std::string& s);
std::string business_key_import_state_to_string(BusinessKeyImportState s);
BusinessKeyImportState string_to_business_key_import_state(const std::string& s);
/// 数值 → 枚举（TBOX-SEC-DSN-CR-021 IPC additive 编码；未知数值映射 UNKNOWN，禁止零值）。
BusinessKeyImportState import_state_from_code(uint32_t code);
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

// ============================================================================
// KL1 契约快照与租约准入（TBOX-SEC-DSN-CR-023 §12.11.1/§12.11.3）
//
// - 快照字段以 typed 结构原值透传：SDK 不得把缺失/未识别版本当作 0=可用，
//   缺省值（version=0/epoch=0/flag=false）一律表示 UNAVAILABLE，不是支持；
// - capability_epoch 由 SEC 生成，绑定当前 daemon 与存储恢复世代；
//   重启/恢复/存储更换都会更换 epoch；epoch=0 表示未知/不可判定；
// - result_contract_version 只表明结果编码版本，不能替代完整能力检查
//   （capability=0 / result=2 不一致时契约视为 UNKNOWN，禁止版本比较自动修复）；
// - 本类型为新增 additive 契约，不改动既有 ImportResult/WrappedKeyItem 等
//   旧结构的内存布局与 wire 字段。
// ============================================================================

/// KL1 契约快照（服务端权威值；SDK 原值透传，不做版本别名/缺省可用推断）。
struct KeyprovContractSnapshot {
    uint32_t result_contract_version = 0;   ///< 导入/结果编码契约版本（服务实际值；0=UNAVAILABLE）
    uint32_t query_semantics_version = 0;   ///< 查询语义版本（NOT_FOUND/UNKNOWN 分类；0=UNAVAILABLE）
    uint64_t capability_epoch = 0;          ///< SEC 生成；重启/恢复/存储更换换 epoch；0=未知
    bool storage_ready = false;             ///< journal/ledger 存储健康可读；false=不可判定/不健康
    bool supports_atomic_dual_commit = false;   ///< 双用途原子提交能力
    bool supports_lease_admission = false;      ///< KL1 租约准入能力；false 时新 TSP 不得调用 KL1 接口
    uint32_t kl1_profile_version = 0;       ///< 本地 KL1 profile 版本；0=UNAVAILABLE
    std::string daemon_build_id;            ///< daemon 构建标识（可观测；非敏感）
    std::string sdk_build_id;               ///< SDK 构建标识（可观测；非敏感）
};

/// KL1 导入准入上下文（仅用于准入，不是可变业务内容；
/// 不进入既有 material/wire digest 与 operation idempotency）。
struct KeyprovImportContext {
    int64_t admission_expire_at_ms = 0;     ///< 外层 bundle 接受截止 E（外层 field4）；非 item.validTo、非 ACK deadline
    uint64_t capability_epoch = 0;          ///< 调用方 probe 快照所见 epoch；不匹配 → KL1_CAPABILITY_EPOCH_MISMATCH
    uint32_t kl1_profile_version = 0;       ///< 调用方 KL1 profile 版本；未知/缺失 → 拒绝
};

/// KL1 查询/导入结果附加事实（additive 封装：不改 ImportResult 布局，
/// 由新 SDK 方法返回；服务端经 IPC JSON additive 字段承载）。
struct KeyprovResultAttachment {
    KeyprovContractSnapshot snapshot;       ///< 与本次结果同一快照（epoch/contract/存储健康）
    std::string request_identity_digest;    ///< 已存在请求身份/证据摘要（requestDigest，hex；仅 FOUND 时非空）
    int64_t queried_at_ms = 0;              ///< 服务端判定时刻（可信时间）
};

/// KL1 profile 常量（与 PAR-PROTO 共享向量 case_set 一致）。
constexpr const char* kKeyprovKl1ProfileName = "keyprov-lifecycle-kl1-v1";
constexpr uint32_t kKeyprovKl1ProfileVersion = 1;



} // namespace sec
} // namespace tbox
