#include "tbox/sec/client.h"
#include "sec_retry_policy.h"
#include "ipc_protocol.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstring>

#include "ipc.h"
#include <memory>

namespace tbox {
namespace sec {

// ============================================================
// SecClient::Impl
// ============================================================
class SecClient::Impl {
public:
    explicit Impl(const std::string& socket_path)
        : socket_path_(socket_path),
          fw_client_(std::make_unique<::tbox::fw::ipc::Client>(socket_path_)) {
    }

    ~Impl() {
        disconnect();
    }

    bool connect() {
        return fw_client_->connect();
    }

    void disconnect() {
        fw_client_->disconnect();
    }

    bool is_connected() const {
        return fw_client_->is_connected();
    }

    /// Send request and receive response
    /// @return (ok, biz_status_code, response_json)
    std::tuple<bool, int32_t, std::string>
    send_request(uint32_t method_id, const std::string& params_json) {
        // SecRetryPolicy: decide whether to allow auto-retry
        bool retry_allowed = SecRetryPolicy::should_retry(method_id);

        std::pair<int32_t, std::string> result;
        if (retry_allowed) {
            result = fw_client_->call(method_id, params_json);
        } else {
            // callOnce: no auto-retry, transport failure = unknown outcome
            result = fw_client_->callOnce(method_id, params_json);
        }

        auto [fw_status, response_json] = result;

        if (fw_status < 0) {
            // Client transport error
            // For non-retryable methods: unknown outcome (server may have executed)
            return {false, 0, ""};
        }

        if (fw_status > 0) {
            // Server transport/handler error (FW-03xx)
            return {false, 0, ""};
        }

        // fw_status == 0: transport success, extract business status from JSON
        int32_t biz_status = 0;
        try {
            auto j = nlohmann::json::parse(response_json);
            biz_status = j.value("status", 0);
        } catch (...) {
            // JSON parse failure, keep biz_status = 0
        }
        return {true, biz_status, response_json};
    }

    /// base64 encode for framework mode (uses framework Utils)
    std::string b64_encode(const std::vector<uint8_t>& data) {
        return ::hwyz::Utils::base64_encode(
            std::string(reinterpret_cast<const char*>(data.data()), data.size()));
    }

    /// base64 decode for framework mode
    std::vector<uint8_t> b64_decode(const std::string& encoded) {
        std::string decoded = ::hwyz::Utils::base64_decode(encoded);
        return std::vector<uint8_t>(decoded.begin(), decoded.end());
    }

    /// 订阅包装（framework Client::subscribe 使用独立连接）
    ::tbox::fw::ipc::Subscription subscribe(uint32_t method_id,
                                             uint32_t event_type,
                                             ::tbox::fw::ipc::EventCallback cb) {
        return fw_client_->subscribe(method_id, event_type, std::move(cb));
    }

private:
    std::string socket_path_;
    std::unique_ptr<::tbox::fw::ipc::Client> fw_client_;
};

// ============================================================
// SecClient facade
// ============================================================

SecClient::SecClient(const std::string& socket_path)
    : impl_(std::make_unique<Impl>(socket_path)) {
}

SecClient::~SecClient() = default;

bool SecClient::connect() {
    return impl_->connect();
}

void SecClient::disconnect() {
    impl_->disconnect();
}

bool SecClient::is_connected() const {
    return impl_->is_connected();
}

ErrorCode SecClient::initialize() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::INITIALIZE), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::generate_key_pair() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GENERATE_KEY_PAIR), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::export_private_key(std::vector<uint8_t>& private_key) {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::EXPORT_PRIVATE_KEY), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;

    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string priv_b64 = j.value("private_key", "");
            private_key = impl_->b64_decode(priv_b64);
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::get_csr(std::vector<uint8_t>& csr_der) {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_CSR), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;

    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string csr_b64 = j.value("csr", "");
            csr_der = impl_->b64_decode(csr_b64);
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::submit_csr() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::SUBMIT_CSR), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::inject_certificate(const std::vector<uint8_t>& cert_der) {
    nlohmann::json params;
    params["cert"] = impl_->b64_encode(cert_der);
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::apply_certificate() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::APPLY_CERTIFICATE), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::set_ca_certificate(const std::vector<uint8_t>& ca_cert_der) {
    nlohmann::json params;
    params["cert"] = impl_->b64_encode(ca_cert_der);
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::SET_CA_CERTIFICATE), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::get_seed(uint8_t level, std::vector<uint8_t>& seed) {
    nlohmann::json params;
    params["level"] = level;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_SEED), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;

    if (status == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string seed_b64 = j.value("seed", "");
            seed = impl_->b64_decode(seed_b64);
            // Security: clear temporary sensitive buffer after use
            // (seed_b64 is local, will be destructed)
        } catch (const std::exception&) {
            return ErrorCode::INTERNAL_ERROR;
        }
    }
    return static_cast<ErrorCode>(status);
}

ErrorCode SecClient::verify_key(uint8_t level, const std::vector<uint8_t>& key) {
    nlohmann::json params;
    params["level"] = level;
    params["key"] = impl_->b64_encode(key);
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

SecProvisionStatus SecClient::get_provision_status() {
    SecProvisionStatus status;
    auto [ok, biz_status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_STATUS), "{}");
    if (!ok) return status;

    try {
        auto j = nlohmann::json::parse(response_json);
        status.vin = j.value("vin", "");
        status.ecu_uid = j.value("ecu_uid", "");
        status.state = j.value("state", "NONE");
        status.last_error = j.value("last_error", "");
        status.retry_count = j.value("retry_count", 0);
    } catch (const std::exception&) {
        // Return default status
    }
    return status;
}

std::string SecClient::get_device_info() {
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_DEVICE_INFO), "{}");
    if (!ok) return "";

    try {
        auto j = nlohmann::json::parse(response_json);
        return j.value("device_info", "");
    } catch (const std::exception&) {
        return "";
    }
}

ErrorCode SecClient::reset_provision_status() {
    auto [ok, status, json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::RESET_STATUS), "{}");
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    return static_cast<ErrorCode>(status);
}

// ============================================================
// MQTT TLS Credential Provider（TBOX-SEC-DSN-CR-010）
// ============================================================

ErrorCode SecClient::get_tls_credential(const std::string& profile,
                                        TlsCredentialBundle& bundle) {
    nlohmann::json params;
    params["profile"] = profile;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    if (status != 0) return static_cast<ErrorCode>(status);

    try {
        auto j = nlohmann::json::parse(response_json);
        bundle.credential_id = j.value("credential_id", "");
        bundle.version = j.value("version", 0ULL);
        bundle.root_ca_bundle_der = impl_->b64_decode(j.value("root_ca_bundle", ""));
        bundle.client_cert_chain_der = impl_->b64_decode(j.value("client_cert_chain", ""));
        bundle.private_key_ref.data = impl_->b64_decode(j.value("private_key_ref", ""));
        bundle.key_algorithm = string_to_key_algorithm(j.value("key_algorithm", ""));
        bundle.not_before = j.value("not_before", 0LL);
        bundle.not_after = j.value("not_after", 0LL);
        bundle.status = string_to_tls_credential_status(j.value("credential_status", "NOT_READY"));
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::INTERNAL_ERROR;
    }
}

ErrorCode SecClient::get_tls_credential_state(const std::string& profile,
                                              TlsCredentialState& state) {
    nlohmann::json params;
    params["profile"] = profile;
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::GET_TLS_CREDENTIAL_STATE), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    if (status != 0) return static_cast<ErrorCode>(status);

    try {
        auto j = nlohmann::json::parse(response_json);
        state.credential_id = j.value("credential_id", "");
        state.version = j.value("version", 0ULL);
        state.status = string_to_tls_credential_status(j.value("credential_status", "NOT_READY"));
        state.reason_code = j.value("reason_code", 0);
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::INTERNAL_ERROR;
    }
}

ErrorCode SecClient::sign_tls(const TlsSignRequest& request,
                              std::vector<uint8_t>& signature) {
    nlohmann::json params;
    params["private_key_ref"] = impl_->b64_encode(request.private_key_ref.data);
    params["algorithm"] = signature_algorithm_to_string(request.algorithm);
    params["digest"] = impl_->b64_encode(request.digest);
    if (!request.context.empty()) {
        params["context"] = impl_->b64_encode(request.context);
    }
    params["request_id"] = request.request_id;

    // SIGN_TLS 禁止自动重放：send_request 内部根据 retry policy 使用 callOnce
    auto [ok, status, response_json] = impl_->send_request(
        static_cast<uint32_t>(ipc::MethodId::SIGN_TLS), params.dump());
    if (!ok) return ErrorCode::CONNECTION_FAILED;
    if (status != 0) return static_cast<ErrorCode>(status);

    try {
        auto j = nlohmann::json::parse(response_json);
        signature = impl_->b64_decode(j.value("signature", ""));
        return ErrorCode::SUCCESS;
    } catch (const std::exception&) {
        return ErrorCode::INTERNAL_ERROR;
    }
}

// 订阅句柄实现：持有 framework Subscription 以维持独立连接生命周期
struct TlsCredentialSubscription::Impl {
    bool active = false;
    std::function<void(const TlsCredentialChangedEvent&)> callback;
    ::tbox::fw::ipc::Subscription fw_sub;
};

TlsCredentialSubscription::TlsCredentialSubscription(std::shared_ptr<Impl> impl)
    : impl_(std::move(impl)) {}
TlsCredentialSubscription::~TlsCredentialSubscription() { cancel(); }
TlsCredentialSubscription::TlsCredentialSubscription(TlsCredentialSubscription&&) noexcept = default;
TlsCredentialSubscription& TlsCredentialSubscription::operator=(TlsCredentialSubscription&&) noexcept = default;
void TlsCredentialSubscription::cancel() {
    if (impl_) {
        impl_->active = false;
        impl_->fw_sub.cancel();
        impl_.reset();
    }
}
bool TlsCredentialSubscription::isActive() const {
    return impl_ && impl_->active;
}

TlsCredentialSubscription SecClient::subscribe_tls_credential_changed(
        const std::string& profile,
        std::function<void(const TlsCredentialChangedEvent&)> callback) {
    auto sub_impl = std::make_shared<TlsCredentialSubscription::Impl>();
    sub_impl->active = true;
    sub_impl->callback = std::move(callback);
    (void)profile;  // framework subscribe 不支持传 params，server 缺省 mqtt

    // 订阅使用独立 framework-ipc 连接（SUBSCRIBE 握手后进入 event-only）
    // profile 由 server 端缺省为 mqtt（framework subscribe 不支持传 params）
    sub_impl->fw_sub = impl_->subscribe(
        static_cast<uint32_t>(ipc::MethodId::SUBSCRIBE_TLS_CREDENTIAL_CHANGED),
        static_cast<uint32_t>(ipc::EventId::TLS_CREDENTIAL_CHANGED),
        [sub_impl](uint32_t event_type, std::string_view payload_json) {
            (void)event_type;
            if (!sub_impl->active || !sub_impl->callback) return;
            try {
                auto j = nlohmann::json::parse(payload_json);
                TlsCredentialChangedEvent ev;
                ev.profile = j.value("profile", "");
                ev.credential_id = j.value("credential_id", "");
                ev.version = j.value("version", 0ULL);
                ev.status = string_to_tls_credential_status(j.value("status", "NOT_READY"));
                ev.reason_code = j.value("reason_code", 0);
                sub_impl->callback(ev);
            } catch (const std::exception&) {
                // 忽略畸形事件
            }
        });

    return TlsCredentialSubscription(sub_impl);
}

} // namespace sec
} // namespace tbox
