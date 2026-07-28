#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace tbox {
namespace sec {

/// SEC 个性化状态信息（通过 IPC 返回给调用方）
struct SecProvisionStatus {
    std::string vin;
    std::string ecu_uid;
    std::string state;
    std::string last_error;
    int retry_count = 0;
};

// ============================================================
// MQTT TLS Credential Provider 类型（TBOX-SEC-DSN-CR-010）
// ============================================================

/// TLS 凭据状态
enum class TlsCredentialStatus : uint8_t {
    READY = 0,      ///< 就绪，允许 MQTT 发起 mTLS
    NOT_READY = 1,  ///< 未就绪（缺材料/未校验）
    EXPIRED = 2,    ///< 已过期
    REVOKED = 3,    ///< 已撤销
    ERROR = 4       ///< 校验/加载错误
};

/// 私钥算法
enum class KeyAlgorithm : uint8_t {
    UNKNOWN = 0,
    ECDSA_P256 = 1  ///< secp256r1
};

/// TLS 签名算法
enum class SignatureAlgorithm : uint8_t {
    UNKNOWN = 0,
    ECDSA_SECP256R1_SHA256 = 1  ///< ecdsa_secp256r1_sha256
};

/// 不透明私钥引用
///
/// 由 SEC 生成，使用进程内密钥进行完整性/机密性保护，
/// 绑定 caller/profile/credential/version/key_id/allowed_algorithms/
/// boot_epoch/expiry。
/// 不含 HSM handle 或私钥材料；调用方视为不透明字节，不得解析或持久化。
struct OpaqueKeyRef {
    std::vector<uint8_t> data;

    bool empty() const { return data.empty(); }
};

/// TLS 凭据 bundle
///
/// root_ca_bundle_der / client_cert_chain_der 为公开凭据材料，可受控返回；
/// private_key_ref 不可导出，签名在 SEC/HSM 内完成。
struct TlsCredentialBundle {
    std::string credential_id;
    uint64_t version = 0;
    std::vector<uint8_t> root_ca_bundle_der;      ///< 一个或多个受信根/中间 CA
    std::vector<uint8_t> client_cert_chain_der;    ///< 顺序: leaf -> intermediate
    OpaqueKeyRef private_key_ref;
    KeyAlgorithm key_algorithm = KeyAlgorithm::UNKNOWN;
    int64_t not_before = 0;  ///< unix epoch 秒
    int64_t not_after = 0;   ///< unix epoch 秒
    TlsCredentialStatus status = TlsCredentialStatus::NOT_READY;
};

/// TLS 凭据状态摘要（不含凭据内容）
struct TlsCredentialState {
    std::string credential_id;
    uint64_t version = 0;
    TlsCredentialStatus status = TlsCredentialStatus::NOT_READY;
    int32_t reason_code = 0;  ///< SEC-10xx 业务错误码，0 表示无
};

/// TLS 签名请求
struct TlsSignRequest {
    OpaqueKeyRef private_key_ref;
    SignatureAlgorithm algorithm = SignatureAlgorithm::UNKNOWN;
    std::vector<uint8_t> digest;       ///< 待签名摘要
    std::vector<uint8_t> context;      ///< 签名上下文（如 TLS transcript hash），可选
    std::string request_id;            ///< 调用方请求标识，用于日志关联
};

/// TLS 凭据变更事件 payload（不携带证书内容或 key reference）
struct TlsCredentialChangedEvent {
    std::string profile;
    std::string credential_id;
    uint64_t version = 0;
    TlsCredentialStatus status = TlsCredentialStatus::NOT_READY;
    int32_t reason_code = 0;
};

// ============================================================
// 辅助：枚举与字符串互转（供日志/JSON 使用）
// ============================================================

std::string tls_credential_status_to_string(TlsCredentialStatus s);
TlsCredentialStatus string_to_tls_credential_status(const std::string& s);
std::string key_algorithm_to_string(KeyAlgorithm a);
KeyAlgorithm string_to_key_algorithm(const std::string& s);
std::string signature_algorithm_to_string(SignatureAlgorithm a);
SignatureAlgorithm string_to_signature_algorithm(const std::string& s);

} // namespace sec
} // namespace tbox
