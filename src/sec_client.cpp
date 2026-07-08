#include "sec_client.h"
#include "ipc_protocol.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <nlohmann/json.hpp>

namespace tbox {
namespace sec {

SecClient::SecClient(const std::string& socket_path)
    : socket_path_(socket_path), socket_fd_(-1), connected_(false) {
}

SecClient::~SecClient() {
    disconnect();
}

bool SecClient::connect() {
    if (connected_) {
        return true;
    }

    socket_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd_ < 0) {
        std::cerr << "Failed to create socket: " << strerror(errno) << std::endl;
        return false;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "Failed to connect to SEC service: " << strerror(errno) << std::endl;
        close(socket_fd_);
        socket_fd_ = -1;
        return false;
    }

    connected_ = true;
    return true;
}

void SecClient::disconnect() {
    if (socket_fd_ >= 0) {
        close(socket_fd_);
        socket_fd_ = -1;
    }
    connected_ = false;
}

bool SecClient::is_connected() const {
    return connected_;
}

ErrorCode SecClient::initialize() {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::INITIALIZE), "{}", status_code, response_json)) {
        return ErrorCode::INVALID_PARAMETER;
    }
    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::generate_key_pair() {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::GENERATE_KEY_PAIR), "{}", status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::export_private_key(std::vector<uint8_t>& private_key) {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::EXPORT_PRIVATE_KEY), "{}", status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }

    if (status_code == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string priv_b64 = j.value("private_key", "");
            private_key = ipc::IpcSerializer::base64_decode(priv_b64);
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse private key response: " << e.what() << std::endl;
            return ErrorCode::INTERNAL_ERROR;
        }
    }

    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::get_csr(std::vector<uint8_t>& csr_der) {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::GET_CSR), "{}", status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }

    if (status_code == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string csr_b64 = j.value("csr", "");
            csr_der = ipc::IpcSerializer::base64_decode(csr_b64);
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse CSR response: " << e.what() << std::endl;
            return ErrorCode::INTERNAL_ERROR;
        }
    }

    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::submit_csr() {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::SUBMIT_CSR), "{}", status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::inject_certificate(const std::vector<uint8_t>& cert_der) {
    int32_t status_code;
    std::string response_json;
    nlohmann::json params;
    params["cert"] = ipc::IpcSerializer::base64_encode(cert_der);
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE), params.dump(), status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::apply_certificate() {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::APPLY_CERTIFICATE), "{}", status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::set_ca_certificate(const std::vector<uint8_t>& ca_cert_der) {
    int32_t status_code;
    std::string response_json;
    nlohmann::json params;
    params["cert"] = ipc::IpcSerializer::base64_encode(ca_cert_der);
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::SET_CA_CERTIFICATE), params.dump(), status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::get_seed(uint8_t level, std::vector<uint8_t>& seed) {
    int32_t status_code;
    std::string response_json;
    nlohmann::json params;
    params["level"] = level;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::GET_SEED), params.dump(), status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }

    if (status_code == 0) {
        try {
            auto j = nlohmann::json::parse(response_json);
            std::string seed_b64 = j.value("seed", "");
            seed = ipc::IpcSerializer::base64_decode(seed_b64);
        } catch (const std::exception& e) {
            std::cerr << "Failed to parse seed response: " << e.what() << std::endl;
            return ErrorCode::INTERNAL_ERROR;
        }
    }

    return static_cast<ErrorCode>(status_code);
}

ErrorCode SecClient::verify_key(uint8_t level, const std::vector<uint8_t>& key) {
    int32_t status_code;
    std::string response_json;
    nlohmann::json params;
    params["level"] = level;
    params["key"] = ipc::IpcSerializer::base64_encode(key);
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY), params.dump(), status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

SecProvisionStatus SecClient::get_provision_status() {
    SecProvisionStatus status;
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::GET_STATUS), "{}", status_code, response_json)) {
        return status;
    }

    try {
        auto j = nlohmann::json::parse(response_json);
        status.vin = j.value("vin", "");
        status.ecu_uid = j.value("ecu_uid", "");
        status.state = j.value("state", "NONE");
        status.last_error = j.value("last_error", "");
        status.retry_count = j.value("retry_count", 0);
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse provision status: " << e.what() << std::endl;
    }

    return status;
}

std::string SecClient::get_device_info() {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::GET_DEVICE_INFO), "{}", status_code, response_json)) {
        return "";
    }

    try {
        auto j = nlohmann::json::parse(response_json);
        return j.value("device_info", "");
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse device info: " << e.what() << std::endl;
        return "";
    }
}

ErrorCode SecClient::reset_provision_status() {
    int32_t status_code;
    std::string response_json;
    if (!send_request(static_cast<uint32_t>(ipc::MethodId::RESET_STATUS), "{}", status_code, response_json)) {
        return ErrorCode::CONNECTION_FAILED;
    }
    return static_cast<ErrorCode>(status_code);
}

bool SecClient::send_request(uint32_t method_id, const std::string& params_json,
                             int32_t& status_code, std::string& response_json) {
    if (!connected_) {
        if (!connect()) {
            return false;
        }
    }

    auto request_data = ipc::IpcSerializer::serialize_request(static_cast<ipc::MethodId>(method_id), params_json);

    size_t total_sent = 0;
    while (total_sent < request_data.size()) {
        ssize_t bytes_sent = send(socket_fd_, request_data.data() + total_sent, request_data.size() - total_sent, 0);
        if (bytes_sent <= 0) {
            std::cerr << "Failed to send request: " << strerror(errno) << std::endl;
            disconnect();
            if (!connect()) {
                return false;
            }
            total_sent = 0;
            continue;
        }
        total_sent += bytes_sent;
    }

    ipc::ResponseHeader header;
    memset(&header, 0, sizeof(header));
    size_t header_received = 0;
    while (header_received < sizeof(header)) {
        ssize_t bytes_read = recv(socket_fd_, reinterpret_cast<uint8_t*>(&header) + header_received, sizeof(header) - header_received, 0);
        if (bytes_read <= 0) {
            std::cerr << "Failed to receive response header: " << strerror(errno) << std::endl;
            disconnect();
            return false;
        }
        header_received += bytes_read;
    }

    if (header.data_length > 10 * 1024 * 1024) {
        std::cerr << "Response too large: " << header.data_length << std::endl;
        disconnect();
        return false;
    }

    std::vector<uint8_t> response_data(sizeof(header) + header.data_length);
    memcpy(response_data.data(), &header, sizeof(header));

    size_t data_received = 0;
    while (data_received < header.data_length) {
        ssize_t bytes_read = recv(socket_fd_, response_data.data() + sizeof(header) + data_received, header.data_length - data_received, 0);
        if (bytes_read <= 0) {
            std::cerr << "Failed to receive response data: " << strerror(errno) << std::endl;
            disconnect();
            return false;
        }
        data_received += bytes_read;
    }

    return ipc::IpcSerializer::deserialize_response(response_data, status_code, response_json);
}

} // namespace sec
} // namespace tbox
