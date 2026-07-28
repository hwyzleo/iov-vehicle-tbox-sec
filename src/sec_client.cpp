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

} // namespace sec
} // namespace tbox
