#include "tbox/sec/client.h"
#include "sec_retry_policy.h"
#include "ipc_protocol.h"
#include "utils.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstring>

#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
#include "ipc.h"
#include <memory>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#endif

namespace tbox {
namespace sec {

// ============================================================
// SecClient::Impl
// ============================================================
class SecClient::Impl {
public:
    explicit Impl(const std::string& socket_path)
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
        : socket_path_(socket_path),
          fw_client_(std::make_unique<::tbox::fw::ipc::Client>(socket_path_))
#else
        : socket_path_(socket_path), socket_fd_(-1), connected_(false)
#endif
    {
    }

    ~Impl() {
        disconnect();
    }

    bool connect() {
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
        return fw_client_->connect();
#else
        if (connected_) return true;

        socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd_ < 0) return false;

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

        if (::connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(socket_fd_);
            socket_fd_ = -1;
            return false;
        }

        connected_ = true;
        return true;
#endif
    }

    void disconnect() {
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
        fw_client_->disconnect();
#else
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
        connected_ = false;
#endif
    }

    bool is_connected() const {
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
        return fw_client_->is_connected();
#else
        return connected_;
#endif
    }

    /// Send request and receive response
    /// @return (ok, biz_status_code, response_json)
    std::tuple<bool, int32_t, std::string>
    send_request(uint32_t method_id, const std::string& params_json) {
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
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
#else
        // Legacy implementation: direct socket send/recv
        if (!connected_) {
            if (!connect()) {
                return {false, 0, ""};
            }
        }

        auto request_data = ipc::IpcSerializer::serialize_request(
            static_cast<ipc::MethodId>(method_id), params_json);

        size_t total_sent = 0;
        while (total_sent < request_data.size()) {
            ssize_t bytes_sent = send(socket_fd_, request_data.data() + total_sent,
                                       request_data.size() - total_sent, 0);
            if (bytes_sent <= 0) {
                disconnect();
                if (!connect()) return {false, 0, ""};
                total_sent = 0;
                continue;
            }
            total_sent += bytes_sent;
        }

        ipc::ResponseHeader header;
        memset(&header, 0, sizeof(header));
        size_t header_received = 0;
        while (header_received < sizeof(header)) {
            ssize_t bytes_read = recv(socket_fd_,
                reinterpret_cast<uint8_t*>(&header) + header_received,
                sizeof(header) - header_received, 0);
            if (bytes_read <= 0) {
                disconnect();
                return {false, 0, ""};
            }
            header_received += bytes_read;
        }

        if (header.data_length > 10 * 1024 * 1024) {
            disconnect();
            return {false, 0, ""};
        }

        std::vector<uint8_t> response_data(sizeof(header) + header.data_length);
        memcpy(response_data.data(), &header, sizeof(header));

        size_t data_received = 0;
        while (data_received < header.data_length) {
            ssize_t bytes_read = recv(socket_fd_,
                response_data.data() + sizeof(header) + data_received,
                header.data_length - data_received, 0);
            if (bytes_read <= 0) {
                disconnect();
                return {false, 0, ""};
            }
            data_received += bytes_read;
        }

        int32_t status_code = 0;
        std::string response_json;
        if (!ipc::IpcSerializer::deserialize_response(response_data, status_code, response_json)) {
            return {false, 0, ""};
        }
        // Legacy: status_code IS the business status code (no separate FW status)
        return {true, status_code, response_json};
#endif
    }

#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
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
#endif

private:
    std::string socket_path_;
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
    std::unique_ptr<::tbox::fw::ipc::Client> fw_client_;
#else
    int socket_fd_;
    bool connected_;
#endif
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
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
            private_key = impl_->b64_decode(priv_b64);
#else
            private_key = ipc::IpcSerializer::base64_decode(priv_b64);
#endif
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
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
            csr_der = impl_->b64_decode(csr_b64);
#else
            csr_der = ipc::IpcSerializer::base64_decode(csr_b64);
#endif
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
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
    nlohmann::json params;
    params["cert"] = impl_->b64_encode(cert_der);
#else
    nlohmann::json params;
    params["cert"] = ipc::IpcSerializer::base64_encode(cert_der);
#endif
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
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
    nlohmann::json params;
    params["cert"] = impl_->b64_encode(ca_cert_der);
#else
    nlohmann::json params;
    params["cert"] = ipc::IpcSerializer::base64_encode(ca_cert_der);
#endif
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
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
            seed = impl_->b64_decode(seed_b64);
#else
            seed = ipc::IpcSerializer::base64_decode(seed_b64);
#endif
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
#if defined(TBOX_SEC_USE_FRAMEWORK_IPC)
    params["key"] = impl_->b64_encode(key);
#else
    params["key"] = ipc::IpcSerializer::base64_encode(key);
#endif
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
