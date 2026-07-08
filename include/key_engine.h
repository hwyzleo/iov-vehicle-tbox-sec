#pragma once

#include <string>
#include <memory>
#include "hsm_interface.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

class KeyEngine {
public:
    KeyEngine(std::unique_ptr<HsmInterface> hsm);
    
    // Initialize key engine
    ErrorCode initialize();
    
    // Generate device key pair
    ErrorCode generate_device_key(const std::string& vin, 
                                 const std::string& ecu_uid,
                                 KeyPair& key_pair);
    
    // Get existing key pair
    ErrorCode get_device_key(const std::string& vin,
                            const std::string& ecu_uid,
                            KeyPair& key_pair);
    
    // Check if device key exists
    bool device_key_exists(const std::string& vin, const std::string& ecu_uid);
    
    // Sign data using device key
    ErrorCode sign(const std::string& vin,
                  const std::string& ecu_uid,
                  const std::vector<uint8_t>& data,
                  std::vector<uint8_t>& signature);
    
    // Export device private key (only available in SOFT_FILE mode)
    ErrorCode export_device_private_key(const std::string& vin,
                                        const std::string& ecu_uid,
                                        std::vector<uint8_t>& private_key);
    
    // Delete device key
    ErrorCode delete_device_key(const std::string& vin, const std::string& ecu_uid);
    
private:
    std::unique_ptr<HsmInterface> hsm_;
    bool initialized_;
    
    std::string make_key_id(const std::string& device_sn, const std::string& key_id) const;
};

} // namespace sec
} // namespace tbox
