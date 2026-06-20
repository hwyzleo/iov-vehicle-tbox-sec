#include "uds_handler.h"
#include <algorithm>

namespace tbox {
namespace sec {

UdsHandler::UdsHandler(std::shared_ptr<SecService> sec_service)
    : sec_service_(sec_service),
      initialized_(false),
      current_security_level_(UdsSecurityLevel::LEVEL_0),
      current_session_(0x01) {} // Default session

ErrorCode UdsHandler::initialize() {
    if (!sec_service_) {
        return ErrorCode::INVALID_PARAMETER;
    }
    
    initialized_ = true;
    return ErrorCode::SUCCESS;
}

UdsResponse UdsHandler::handle_request(const UdsRequest& request) {
    if (!initialized_) {
        UdsResponse response;
        response.is_negative = true;
        response.negative_response_code = 0x22; // Conditions not correct
        return response;
    }
    
    switch (request.service) {
        case UdsService::DIAGNOSTIC_SESSION_CONTROL:
            return handle_diagnostic_session_control(request);
        case UdsService::SECURITY_ACCESS:
            return handle_security_access(request);
        case UdsService::READ_DATA_BY_IDENTIFIER:
            return handle_read_data_by_identifier(request);
        case UdsService::WRITE_DATA_BY_IDENTIFIER:
            return handle_write_data_by_identifier(request);
        case UdsService::ROUTINE_CONTROL:
            return handle_routine_control(request);
        default:
            UdsResponse response;
            response.is_negative = true;
            response.negative_response_code = 0x11; // Service not supported
            return response;
    }
}

bool UdsHandler::is_security_access_granted(UdsSecurityLevel level) const {
    return current_security_level_ >= level;
}

uint8_t UdsHandler::get_current_session() const {
    return current_session_;
}

UdsResponse UdsHandler::handle_diagnostic_session_control(const UdsRequest& request) {
    UdsResponse response;
    
    // Check if session type is valid
    if (request.sub_function != 0x01 && // Default session
        request.sub_function != 0x02 && // Programming session
        request.sub_function != 0x03) { // Extended session
        response.is_negative = true;
        response.negative_response_code = 0x12; // Sub-function not supported
        return response;
    }
    
    current_session_ = request.sub_function;
    
    // Reset security level when changing session
    current_security_level_ = UdsSecurityLevel::LEVEL_0;
    
    response.is_negative = false;
    response.data = {request.sub_function};
    return response;
}

UdsResponse UdsHandler::handle_security_access(const UdsRequest& request) {
    // Check if security level is supported (0x29 for seed, 0x2A for key)
    if (request.sub_function != 0x29 && request.sub_function != 0x2A) {
        UdsResponse response;
        response.is_negative = true;
        response.negative_response_code = 0x12; // Sub-function not supported
        return response;
    }
    
    // Check if request is for seed (odd) or key (even)
    if (request.sub_function % 2 == 1) {
        return process_security_access_request(request);
    } else {
        return process_security_access_response(request);
    }
}

UdsResponse UdsHandler::handle_read_data_by_identifier(const UdsRequest& request) {
    UdsResponse response;
    
    // Check security access for sensitive DIDs
    if (request.did == 0xF100 || // Provision state
        request.did == 0xF101) { // CSR
        if (!is_security_access_granted(UdsSecurityLevel::LEVEL_29)) {
            response.is_negative = true;
            response.negative_response_code = 0x33; // Security access denied
            return response;
        }
    }
    
    switch (request.did) {
        case 0xF100: // Provision state
            return read_provision_state(request.did);
        case 0xF101: // CSR
            return read_csr(request.did);
        default:
            response.is_negative = true;
            response.negative_response_code = 0x31; // Request out of range
            return response;
    }
}

UdsResponse UdsHandler::handle_write_data_by_identifier(const UdsRequest& request) {
    UdsResponse response;
    
    // Check security access for certificate injection
    if (request.did == 0xF102) { // Certificate
        if (!is_security_access_granted(UdsSecurityLevel::LEVEL_29)) {
            response.is_negative = true;
            response.negative_response_code = 0x33; // Security access denied
            return response;
        }
    }
    
    switch (request.did) {
        case 0xF102: // Certificate
            return write_certificate(request.did, request.data);
        default:
            response.is_negative = true;
            response.negative_response_code = 0x31; // Request out of range
            return response;
    }
}

UdsResponse UdsHandler::handle_routine_control(const UdsRequest& request) {
    UdsResponse response;
    
    // Check security access for key generation
    if (request.rid == 0xFF00) { // Generate key pair
        if (!is_security_access_granted(UdsSecurityLevel::LEVEL_29)) {
            response.is_negative = true;
            response.negative_response_code = 0x33; // Security access denied
            return response;
        }
    }
    
    switch (request.rid) {
        case 0xFF00: // Generate key pair
            return generate_key_pair(request.rid);
        default:
            response.is_negative = true;
            response.negative_response_code = 0x31; // Request out of range
            return response;
    }
}

UdsResponse UdsHandler::process_security_access_request(const UdsRequest& request) {
    UdsResponse response;
    
    // Generate seed (in real implementation, use random seed)
    std::vector<uint8_t> seed = {0x01, 0x02, 0x03, 0x04};
    
    response.is_negative = false;
    response.data = seed;
    return response;
}

UdsResponse UdsHandler::process_security_access_response(const UdsRequest& request) {
    UdsResponse response;
    
    // Verify key (in real implementation, verify against HSM)
    bool key_valid = true; // Simplified for now
    
    if (key_valid) {
        current_security_level_ = UdsSecurityLevel::LEVEL_29;
        response.is_negative = false;
        response.data = {0x01}; // Success
    } else {
        response.is_negative = true;
        response.negative_response_code = 0x35; // Invalid key
    }
    
    return response;
}

UdsResponse UdsHandler::read_provision_state(uint16_t did) {
    UdsResponse response;
    
    // Get provision state from SEC service
    ProvisionStatus status = sec_service_->get_provision_status();
    
    // Encode provision state
    response.is_negative = false;
    response.data = {static_cast<uint8_t>(status.state)};
    return response;
}

UdsResponse UdsHandler::read_csr(uint16_t did) {
    UdsResponse response;
    
    // Get CSR from SEC service
    std::vector<uint8_t> csr;
    ErrorCode result = sec_service_->get_csr(csr);
    
    if (result == ErrorCode::SUCCESS) {
        response.is_negative = false;
        response.data = csr;
    } else {
        response.is_negative = true;
        response.negative_response_code = 0x22; // Conditions not correct
    }
    
    return response;
}

UdsResponse UdsHandler::write_certificate(uint16_t did, const std::vector<uint8_t>& data) {
    UdsResponse response;
    
    // Inject certificate via SEC service
    ErrorCode result = sec_service_->inject_certificate(data);
    
    if (result == ErrorCode::SUCCESS) {
        response.is_negative = false;
        response.data = {0x01}; // Success
    } else {
        response.is_negative = true;
        response.negative_response_code = 0x72; // General programming failure
    }
    
    return response;
}

UdsResponse UdsHandler::generate_key_pair(uint16_t rid) {
    UdsResponse response;
    
    // Generate key pair via SEC service
    ErrorCode result = sec_service_->generate_key_pair();
    
    if (result == ErrorCode::SUCCESS) {
        response.is_negative = false;
        response.data = {0x01}; // Success
    } else {
        response.is_negative = true;
        response.negative_response_code = 0x72; // General programming failure
    }
    
    return response;
}

} // namespace sec
} // namespace tbox
