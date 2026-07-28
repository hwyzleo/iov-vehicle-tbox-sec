#pragma once

#include <cstdint>

namespace tbox {
namespace sec {
namespace ipc {

/// SEC IPC 方法 ID（与 framework-ipc RequestHeader.method_id 一致）。
///
/// 传输层由 framework-ipc 负责，序列化/编解码在 SecIpcDispatcher 中完成。
/// 此枚举仅定义方法号，供 dispatcher、retry policy、client facade 共享。
enum class MethodId : uint32_t {
    INITIALIZE = 1,
    GENERATE_KEY_PAIR = 2,
    GET_CSR = 3,
    SUBMIT_CSR = 4,
    INJECT_CERTIFICATE = 5,
    APPLY_CERTIFICATE = 6,
    SET_CA_CERTIFICATE = 7,
    GET_SEED = 8,
    VERIFY_KEY = 9,
    GET_STATUS = 10,
    GET_DEVICE_INFO = 11,
    RESET_STATUS = 12,
    EXPORT_PRIVATE_KEY = 13,

    // MQTT TLS Credential Provider (TBOX-SEC-DSN-CR-010)
    GET_TLS_CREDENTIAL = 14,                  ///< 获取根 CA + 客户端证书链 + opaque private_key_ref
    GET_TLS_CREDENTIAL_STATE = 15,            ///< 查询凭据状态摘要
    SIGN_TLS = 16,                            ///< 远程 TLS 签名（禁止自动重放）
    SUBSCRIBE_TLS_CREDENTIAL_CHANGED = 17,    ///< 订阅凭据变更事件
};

/// SEC IPC 事件类型（与 framework-ipc EventHeader.event_type 一致）。
enum class EventId : uint32_t {
    TLS_CREDENTIAL_CHANGED = 1,  ///< sec.tls_credential.changed
};

/// TLS 凭据 profile 名称约定
constexpr const char* kTlsProfileMqtt = "mqtt";

} // namespace ipc
} // namespace sec
} // namespace tbox
