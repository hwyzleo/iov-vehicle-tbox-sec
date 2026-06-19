#pragma once

#include <string>
#include <vector>
#include <memory>
#include "key_engine.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

struct CsrConfig {
    std::string common_name;      // CN = ECU_UID
    std::string vin;              // SAN: VIN
    std::string ecu_uid;          // SAN: ECU_UID
    std::string key_usage;        // digitalSignature
    std::string extended_key_usage; // clientAuth
};

class CsrBuilder {
public:
    CsrBuilder(std::shared_ptr<KeyEngine> key_engine);
    
    // Build CSR for device
    ErrorCode build_csr(const CsrConfig& config,
                       std::vector<uint8_t>& csr_der);
    
    // Build CSR with existing key
    ErrorCode build_csr_with_key(const CsrConfig& config,
                                const KeyPair& key_pair,
                                std::vector<uint8_t>& csr_der);
    
private:
    std::shared_ptr<KeyEngine> key_engine_;
    
    // Internal CSR construction methods
    ErrorCode create_csr_structure(const CsrConfig& config,
                                  const KeyPair& key_pair,
                                  std::vector<uint8_t>& csr_data);
    
    ErrorCode sign_csr(const std::vector<uint8_t>& csr_data,
                      const std::string& vin,
                      const std::string& ecu_uid,
                      std::vector<uint8_t>& signature);
    
    ErrorCode assemble_csr(const std::vector<uint8_t>& csr_data,
                          const std::vector<uint8_t>& signature,
                          std::vector<uint8_t>& csr_der);
};

} // namespace sec
} // namespace tbox