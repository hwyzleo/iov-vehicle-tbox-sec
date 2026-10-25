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
    /// @deprecated TBOX-SEC-DSN-CR-016 §4.3: 写入口已移除。数值保留以维持
    /// wire/ABI 兼容，但 dispatcher 不再路由——旧调用固定失败且不产生任何写入。
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

    // V2C 业务密钥开通 (TBOX-SEC-DSN-CR-019)
    GET_BUSINESS_KEY_STATUS = 18,             ///< 查询 V2C 业务密钥件内状态
    IMPORT_WRAPPED_BUSINESS_KEYS = 19,        ///< 导入 Wrapped Key 批次（原子激活，禁止自动重放）
    GET_BUSINESS_KEY_IMPORT_RESULT = 20,      ///< 按 requestId 查询导入结果
    // TBOX-TSP-DSN-CR-012 §8 / Q1：只读 V2C keyprov 能力查询（TSP readiness 门禁）
    GET_V2C_KEY_PROVISIONING_CAPABILITY = 21, ///< 查询 V2C keyprov capability（只读）

    // KL1 契约快照与租约导入（TBOX-SEC-DSN-CR-023；additive，旧编号/旧布局不变）。
    // 方法号 22/23 已按仓库核验登记（framework-ipc 传输层 method_id 为不透明 uint32，
    // 无全局登记；SEC 自持协议契约为本文件；其他 TBOX 服务无引用）。
    IMPORT_WRAPPED_BUSINESS_KEYS_KL1 = 22,    ///< KL1 租约准入导入（带 admission_expire_at_ms/epoch/profile）
    GET_KEYPROV_CONTRACT_SNAPSHOT = 23,       ///< 查询 KL1 契约快照（epoch/contract/存储健康/双用途原子/租约准入；只读）
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
