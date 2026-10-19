#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>
#include <functional>
#include "tbox/sec/types.h"
#include "tbox/sec/errors.h"
#include "tbox/sec/business_key.h"

namespace tbox {
namespace sec {

/// 订阅句柄（RAII，析构取消订阅）
class TlsCredentialSubscription {
public:
    TlsCredentialSubscription() = default;
    ~TlsCredentialSubscription();
    TlsCredentialSubscription(TlsCredentialSubscription&&) noexcept;
    TlsCredentialSubscription& operator=(TlsCredentialSubscription&&) noexcept;
    TlsCredentialSubscription(const TlsCredentialSubscription&) = delete;
    TlsCredentialSubscription& operator=(const TlsCredentialSubscription&) = delete;

    void cancel();
    bool isActive() const;
private:
    friend class SecClient;
    struct Impl;
    std::shared_ptr<Impl> impl_;
    explicit TlsCredentialSubscription(std::shared_ptr<Impl> impl);
};

/// SEC 客户端 facade
///
/// 调用方（DIAG / RSMS / TSP 等）通过此接口与 SEC daemon 交互。
/// IPC 传输细节封装在库内部，对调用方不可见。
/// 内部使用 framework-ipc Client + SecRetryPolicy。
class SecClient {
public:
    SecClient(const std::string& socket_path = "/tmp/tbox-sec.sock");
    ~SecClient();

    // 连接到 SEC 服务
    bool connect();
    void disconnect();
    bool is_connected() const;

    // 初始化服务
    ErrorCode initialize();

    // 密钥操作
    ErrorCode generate_key_pair();
    ErrorCode export_private_key(std::vector<uint8_t>& private_key);

    // CSR 操作
    ErrorCode get_csr(std::vector<uint8_t>& csr_der);
    ErrorCode submit_csr();

    // 证书操作
    ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);
    ErrorCode apply_certificate();

    // 安全访问（Seed-Key）
    ErrorCode get_seed(uint8_t level, std::vector<uint8_t>& seed);
    ErrorCode verify_key(uint8_t level, const std::vector<uint8_t>& key);

    // 状态查询
    SecProvisionStatus get_provision_status();
    std::string get_device_info();

    // 重置状态
    ErrorCode reset_provision_status();

    // ---- MQTT TLS Credential Provider（TBOX-SEC-DSN-CR-010）----
    /// 获取完整凭据 bundle（根 CA + 客户端证书链 + opaque private_key_ref）
    ErrorCode get_tls_credential(const std::string& profile,
                                 TlsCredentialBundle& bundle);
    /// 查询凭据状态摘要（不含凭据内容）
    ErrorCode get_tls_credential_state(const std::string& profile,
                                       TlsCredentialState& state);
    /// 远程 TLS 签名（禁止自动重放；超时为 unknown outcome）
    ErrorCode sign_tls(const TlsSignRequest& request,
                       std::vector<uint8_t>& signature);
    /// 订阅凭据变更事件（独立连接，RAII 句柄）
    TlsCredentialSubscription subscribe_tls_credential_changed(
        const std::string& profile,
        std::function<void(const TlsCredentialChangedEvent&)> callback);

    // ---- V2C 业务密钥开通（TBOX-SEC-DSN-CR-019）----
    /// 查询 V2C 业务密钥件内状态（只读，可重试）
    ErrorCode get_business_key_status(const std::string& business_domain,
                                      const std::vector<std::string>& purposes,
                                      BusinessKeyStatusSet& out);
    /// 导入 Wrapped Key 批次（写入型；禁止自动重放，超时按 unknown outcome 处理）
    ErrorCode import_wrapped_business_keys(const std::string& request_id,
                                           const std::string& business_domain,
                                           const std::vector<WrappedKeyItem>& items,
                                           ImportResult& out);
    /// 按 requestId 查询导入结果（只读，可重试）
    ErrorCode get_business_key_import_result(const std::string& request_id,
                                             ImportResult& out);

    /// TBOX-TSP-DSN-CR-012 §8 / Q1：只读 V2C keyprov capability 查询。
    /// 不触发密码操作；供 TSP 在发起 Request 前完成 readiness 门禁。
    ErrorCode get_v2c_key_provisioning_capability(V2cKeyProvisioningCapability& out);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sec
} // namespace tbox
