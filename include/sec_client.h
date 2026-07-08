#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "error_codes.h"

namespace tbox {
namespace sec {

struct SecProvisionStatus {
    std::string vin;
    std::string ecu_uid;
    std::string state;
    std::string last_error;
    int retry_count = 0;
};

class SecClient {
public:
    SecClient(const std::string& socket_path = "/tmp/tbox-sec.sock");
    ~SecClient();

    bool connect();
    void disconnect();
    bool is_connected() const;

    ErrorCode initialize();
    ErrorCode generate_key_pair();
    ErrorCode export_private_key(std::vector<uint8_t>& private_key);
    ErrorCode get_csr(std::vector<uint8_t>& csr_der);
    ErrorCode submit_csr();
    ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);
    ErrorCode apply_certificate();
    ErrorCode set_ca_certificate(const std::vector<uint8_t>& ca_cert_der);
    ErrorCode get_seed(uint8_t level, std::vector<uint8_t>& seed);
    ErrorCode verify_key(uint8_t level, const std::vector<uint8_t>& key);
    SecProvisionStatus get_provision_status();
    std::string get_device_info();
    ErrorCode reset_provision_status();

private:
    std::string socket_path_;
    int socket_fd_;
    bool connected_;

    bool send_request(uint32_t method_id, const std::string& params_json,
                      int32_t& status_code, std::string& response_json);
};

} // namespace sec
} // namespace tbox
