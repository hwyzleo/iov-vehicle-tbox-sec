#pragma once

#include <string>
#include <vector>
#include <functional>
#include "sec_service.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

enum class UdsService : uint8_t {
    DIAGNOSTIC_SESSION_CONTROL = 0x10,
    SECURITY_ACCESS = 0x29,
    READ_DATA_BY_IDENTIFIER = 0x22,
    WRITE_DATA_BY_IDENTIFIER = 0x2E,
    ROUTINE_CONTROL = 0x31
};

enum class UdsSecurityLevel : uint8_t {
    LEVEL_0 = 0x00,
    LEVEL_1 = 0x01,
    LEVEL_29 = 0x29
};

struct UdsRequest {
    UdsService service;
    uint8_t sub_function;
    std::vector<uint8_t> data;
    uint16_t did;
    uint16_t rid;
};

struct UdsResponse {
    uint8_t negative_response_code;
    std::vector<uint8_t> data;
    bool is_negative;
};

class UdsHandler {
public:
    UdsHandler(std::shared_ptr<SecService> sec_service);
    
    // Initialize UDS handler
    ErrorCode initialize();
    
    // Handle UDS request
    UdsResponse handle_request(const UdsRequest& request);
    
    // Check security access status
    bool is_security_access_granted(UdsSecurityLevel level) const;
    
    // Get current session
    uint8_t get_current_session() const;
    
private:
    std::shared_ptr<SecService> sec_service_;
    bool initialized_;
    UdsSecurityLevel current_security_level_;
    uint8_t current_session_;
    
    // Service handlers
    UdsResponse handle_diagnostic_session_control(const UdsRequest& request);
    UdsResponse handle_security_access(const UdsRequest& request);
    UdsResponse handle_read_data_by_identifier(const UdsRequest& request);
    UdsResponse handle_write_data_by_identifier(const UdsRequest& request);
    UdsResponse handle_routine_control(const UdsRequest& request);
    
    // Security access helpers
    UdsResponse process_security_access_request(const UdsRequest& request);
    UdsResponse process_security_access_response(const UdsRequest& request);
    
    // DID/RID handlers
    UdsResponse read_provision_state(uint16_t did);
    UdsResponse read_csr(uint16_t did);
    UdsResponse write_certificate(uint16_t did, const std::vector<uint8_t>& data);
    UdsResponse generate_key_pair(uint16_t rid);
};

} // namespace sec
} // namespace tbox
