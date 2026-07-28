#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <functional>

namespace tbox {
namespace sec {

class SecService;
class TlsCredentialProvider;
class PeerCredentialResolver;
struct PeerIdentity;

/// SEC IPC 请求分发适配器
///
/// 将 framework-ipc 的 RequestHandler 签名适配到 SEC 业务 handler。
/// 只负责 JSON 解码/编码、调用业务 handler 及业务状态映射，
/// 不复制 socket 逻辑（由 framework-ipc Server 负责）。
///
/// 响应 JSON 中嵌入 `status` 字段（SEC-10xx 业务状态码），
/// framework 在 ResponseHeader.status_code 中写入 0（传输成功）或 FW-03xx（传输失败）。
///
/// 适配层不接触密钥明文日志：IPC logger 只记录 method_id、status、payload_bytes、duration。
class SecIpcDispatcher {
public:
    explicit SecIpcDispatcher(SecService* service);
    ~SecIpcDispatcher();

    /// 注入 TLS 凭据提供者与 peer credential 解析器（用于 TLS method ACL）
    void setTlsCredentialProvider(TlsCredentialProvider* provider);
    void setPeerCredentialResolver(std::shared_ptr<PeerCredentialResolver> resolver);

    /// 注入订阅注册回调（由 SecService 接线到 framework-ipc Server::add_subscription）
    void setAddSubscriptionCallback(std::function<bool(int, uint32_t)> cb);

    /// framework RequestHandler 回调入口
    /// @param method_id   SEC method ID
    /// @param params_json 请求参数 JSON
    /// @param client_fd   客户端 fd（用于订阅管理，当前预留）
    /// @return 响应 JSON 字符串
    std::string dispatch(uint32_t method_id,
                         std::string_view params_json,
                         int client_fd);

private:
    SecService* service_;
    TlsCredentialProvider* tls_provider_ = nullptr;
    std::shared_ptr<PeerCredentialResolver> peer_resolver_;
    std::function<bool(int, uint32_t)> add_subscription_fn_;

    /// 解析 client_fd 的调用方身份
    PeerIdentity resolvePeer(int client_fd);

    // 各 method handler，返回 (status_code, response_json)
    std::pair<int32_t, std::string> handle_initialize();
    std::pair<int32_t, std::string> handle_generate_key_pair();
    std::pair<int32_t, std::string> handle_export_private_key();
    std::pair<int32_t, std::string> handle_get_csr();
    std::pair<int32_t, std::string> handle_submit_csr();
    std::pair<int32_t, std::string> handle_inject_certificate(std::string_view params);
    std::pair<int32_t, std::string> handle_apply_certificate();
    std::pair<int32_t, std::string> handle_set_ca_certificate(std::string_view params);
    std::pair<int32_t, std::string> handle_get_seed(std::string_view params);
    std::pair<int32_t, std::string> handle_verify_key(std::string_view params);
    std::pair<int32_t, std::string> handle_get_status();
    std::pair<int32_t, std::string> handle_get_device_info();
    std::pair<int32_t, std::string> handle_reset_status();

    // TLS Credential Provider handlers (TBOX-SEC-DSN-CR-010)
    std::pair<int32_t, std::string> handle_get_tls_credential(std::string_view params, int client_fd);
    std::pair<int32_t, std::string> handle_get_tls_credential_state(std::string_view params);
    std::pair<int32_t, std::string> handle_sign_tls(std::string_view params, int client_fd);
    std::pair<int32_t, std::string> handle_subscribe_tls_credential_changed(std::string_view params, int client_fd);
};

} // namespace sec
} // namespace tbox
