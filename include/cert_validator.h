#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "key_engine.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

struct CertificateInfo {
    std::string serial_number;
    std::string issuer;
    std::string subject;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<uint8_t> public_key;
    std::string key_usage;
    std::string extended_key_usage;
};

class CertValidator {
public:
    CertValidator(KeyEngine* key_engine);

    // Validate certificate against device key
    ErrorCode validate_certificate(const std::string& vin,
                                   const std::string& ecu_uid,
                                   const std::vector<uint8_t>& cert_der,
                                   bool& valid);

    // Extract certificate information
    ErrorCode extract_certificate_info(const std::vector<uint8_t>& cert_der,
                                       CertificateInfo& info);

    // Check if certificate is expired
    bool is_certificate_expired(const std::vector<uint8_t>& cert_der);

    // Check certificate chain
    ErrorCode validate_certificate_chain(const std::vector<std::vector<uint8_t>>& chain,
                                         bool& valid);

    // Set CA certificate for signature verification
    void set_ca_certificate(const std::vector<uint8_t>& ca_cert_der);

private:
    KeyEngine* key_engine_;
    std::vector<uint8_t> ca_cert_der_;  // CA certificate for signature verification

    // Internal validation methods
    ErrorCode verify_certificate_signature(const std::vector<uint8_t>& cert_der,
                                          bool& valid);

    ErrorCode check_certificate_validity(const std::vector<uint8_t>& cert_der,
                                        bool& valid);

    ErrorCode match_certificate_key(const std::vector<uint8_t>& cert_der,
                                   const std::string& vin,
                                   const std::string& ecu_uid,
                                   bool& match);
};

} // namespace sec
} // namespace tbox
