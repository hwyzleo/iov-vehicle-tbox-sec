#pragma once

#include <cstdint>
#include <string>

namespace tbox {
namespace sec {

enum class ErrorCode : uint32_t {
    SUCCESS = 0,

    // Key generation errors (SEC-1001)
    KEY_GENERATION_FAILED = 1001,
    KEY_ALREADY_EXISTS = 1002,
    KEY_NOT_FOUND = 1003,

    // CSR construction errors (SEC-1002)
    CSR_BUILD_FAILED = 2001,
    CSR_INVALID_SUBJECT = 2002,
    CSR_SIGN_FAILED = 2003,

    // PKI errors (SEC-1003, SEC-1004)
    PKI_REJECTED = 3001,
    PKI_TIMEOUT = 3002,
    PKI_CONNECTION_FAILED = 3003,
    PKI_INVALID_RESPONSE = 3004,

    // Certificate errors (SEC-1005)
    CERT_VALIDATION_FAILED = 4001,
    CERT_KEY_MISMATCH = 4002,
    CERT_EXPIRED = 4003,
    CERT_INSTALL_FAILED = 4004,

    // HSM/Secure Element errors
    HSM_INIT_FAILED = 5001,
    HSM_COMMUNICATION_FAILED = 5002,
    HSM_KEY_GENERATION_FAILED = 5003,
    HSM_SIGN_FAILED = 5004,
    HSM_VERIFICATION_FAILED = 5005,

    // Storage errors
    STORAGE_WRITE_FAILED = 6001,
    STORAGE_READ_FAILED = 6002,
    STORAGE_CORRUPTION = 6003,

    // UDS errors
    UDS_SESSION_TIMEOUT = 7001,
    UDS_SECURITY_DENIED = 7002,
    UDS_INVALID_REQUEST = 7003,

    // Seed-Key errors (SEC-1007, SEC-1008)
    SEED_GENERATION_FAILED = 7007,
    KEY_VERIFICATION_FAILED = 7008,

    // Soft key errors (SEC-1009)
    SOFT_KEY_MODE_NOT_ALLOWED = 1009,

    // MQTT TLS credential errors (SEC-1010..1014, TBOX-SEC-DSN-CR-010)
    TLS_CREDENTIAL_NOT_READY = 1010,          ///< SEC-1010: TLS 凭据未就绪
    TLS_CREDENTIAL_INVALID = 1011,            ///< SEC-1011: 凭据无效、过期或撤销
    TLS_KEY_REF_INVALID = 1012,               ///< SEC-1012: 私钥引用无效或已失效
    TLS_SIGN_ALGORITHM_NOT_ALLOWED = 1013,    ///< SEC-1013: 签名算法或用途不允许
    TLS_HSM_SIGN_FAILED = 1014,               ///< SEC-1014: HSM/SE TLS 签名失败

    // TLS 材料明细错误码 (SEC-1015..1020, TBOX-SEC-DSN-CR-014)
    TLS_MATERIAL_KEY_MISSING = 1015,          ///< SEC-1015: TLS 材料键缺失 (MATERIAL_KEY_MISSING)
    TLS_MATERIAL_FORMAT_INVALID = 1016,       ///< SEC-1016: TLS 材料格式非法 (MATERIAL_FORMAT_INVALID)
    TLS_CHAIN_INVALID = 1017,                 ///< SEC-1017: TLS 证书链无效 (CHAIN_INVALID)
    TLS_KEY_MISMATCH = 1018,                  ///< SEC-1018: TLS 客户端证书与私钥不匹配 (KEY_MISMATCH)
    TLS_CERT_EXPIRED = 1019,                  ///< SEC-1019: TLS 客户端证书已过期 (CERT_EXPIRED)
    TLS_CA_INVALID = 1020,                    ///< SEC-1020: Broker 信任 CA 无效 (CA_INVALID)

    // V2C 业务密钥错误码 (SEC-1021..1026, TBOX-SEC-DSN-CR-019 §12.7)
    BUSINESS_KEY_UNSUPPORTED = 1021,      ///< SEC-1021: 业务域/用途/算法/封装套件不支持
    BUSINESS_KEY_CONFLICT = 1022,         ///< SEC-1022: requestId 摘要冲突或版本冲突
    WRAPPED_KEY_INVALID = 1023,           ///< SEC-1023: Wrapped Key 绑定/AAD/完整性校验失败
    BUSINESS_KEY_IMPORT_UNKNOWN = 1024,   ///< SEC-1024: 结果未知，必须按 requestId 查询
    BUSINESS_KEY_NOT_READY = 1025,        ///< SEC-1025: HSM/eSE、解封装身份、journal 或元数据未就绪
    BUSINESS_KEY_PARTIAL_ROLLBACK = 1026, ///< SEC-1026: 批次未提交且存在需恢复的 staging 状态
    BUSINESS_KEY_OUTCOME_UNKNOWN = 1028,  ///< SEC-1028: 安全调用结果未知，需按 requestId 对账

    // KL1 租约准入（TBOX-SEC-DSN-CR-023；SEC-1029/1030 均不是强 NOT_FOUND，
    // 不得被 TSP 解释为 NO_SIDE_EFFECT_PROVEN 或“该 rid 历史上无副作用”）
    KL1_ADMISSION_REJECTED = 1029,        ///< SEC-1029: 已确认新 operation、可信时间健康，但入口或锁内重检发现 U≥E
                                        ///< （租约到期）。仅证明本次调用未启动新操作（未建 journal、未启动密码
                                        ///< 操作、未创建 staging）。TSP 进入既定过期处置分支；获取新 E 仍受一次
                                        ///< freshen 与持久预算限制，不能无限续租重试。
    KL1_CAPABILITY_EPOCH_MISMATCH = 1030, ///< SEC-1030: 已确认新 operation，调用方携带的 capability_epoch 与当前
                                        ///< SEC epoch 不一致（daemon 重启/恢复/存储更换）。未启动本次新操作。
                                        ///< TSP 重新 probe 快照、清零跨 epoch NF 稳定化计数、按原 rid 查询并判断
                                        ///< 能力与有效期；不能仅凭重新 probe 成功就自动重发 import。

    // ACL errors（CR-019 让位 1021..1026 给业务密钥错误，ACL 顺延到 1027）
    ACL_DENIED = 1027,                        ///< 调用方未授权访问该 profile

    // Configuration errors
    CONFIG_ERROR = 1100,

    // General errors
    INVALID_PARAMETER = 8001,
    NOT_INITIALIZED = 8002,
    OPERATION_IN_PROGRESS = 8003,
    NOT_IMPLEMENTED = 8004,
    CONNECTION_FAILED = 8005,
    PROV_NOT_CONFIGURED = 8006,
    INTERNAL_ERROR = 9999
};

std::string error_code_to_string(ErrorCode code);
std::string error_code_to_description(ErrorCode code);

} // namespace sec
} // namespace tbox
