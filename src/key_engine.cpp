#include "key_engine.h"
#include "constants.h"
#include <iostream>
#include <stdexcept>

namespace tbox {
namespace sec {

KeyEngine::KeyEngine(std::unique_ptr<HsmInterface> hsm)
    : hsm_(std::move(hsm)), initialized_(false) {}

ErrorCode KeyEngine::initialize() {
    if (!hsm_) {
        return ErrorCode::INVALID_PARAMETER;
    }
    
    ErrorCode result = hsm_->initialize();
    if (result == ErrorCode::SUCCESS) {
        initialized_ = true;
    }
    return result;
}

ErrorCode KeyEngine::generate_device_key(const std::string& vin,
                                        const std::string& ecu_uid,
                                        KeyPair& key_pair) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    std::string key_id = make_key_id(vin, ecu_uid);
    
    // Check if key already exists
    if (hsm_->key_exists(key_id)) {
        // Key already exists, return success and export existing key
        std::cerr << "[SEC] Key already exists for " << key_id << ", returning existing key" << std::endl;
        key_pair.key_id = key_id;
        key_pair.algorithm = KEY_ALGORITHM_ECDSA_P256;
        key_pair.private_key_exists = true;
        return hsm_->export_public_key(key_id, key_pair.public_key);
    }
    
    // Generate key pair in HSM
    return hsm_->generate_key_pair(key_id, KEY_ALGORITHM_ECDSA_P256, key_pair);
}

ErrorCode KeyEngine::get_device_key(const std::string& vin,
                                   const std::string& ecu_uid,
                                   KeyPair& key_pair) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    std::string key_id = make_key_id(vin, ecu_uid);
    
    if (!hsm_->key_exists(key_id)) {
        return ErrorCode::KEY_NOT_FOUND;
    }
    
    // Get key information from HSM
    key_pair.key_id = key_id;
    key_pair.algorithm = KEY_ALGORITHM_ECDSA_P256;
    key_pair.created_at = std::chrono::system_clock::now();
    key_pair.private_key_exists = true;
    
    // Export public key
    return hsm_->export_public_key(key_id, key_pair.public_key);
}

bool KeyEngine::device_key_exists(const std::string& vin, const std::string& ecu_uid) {
    if (!initialized_) {
        return false;
    }
    
    std::string key_id = make_key_id(vin, ecu_uid);
    return hsm_->key_exists(key_id);
}

ErrorCode KeyEngine::sign(const std::string& vin,
                         const std::string& ecu_uid,
                         const std::vector<uint8_t>& data,
                         std::vector<uint8_t>& signature) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    std::string key_id = make_key_id(vin, ecu_uid);
    
    if (!hsm_->key_exists(key_id)) {
        return ErrorCode::KEY_NOT_FOUND;
    }
    
    return hsm_->sign(key_id, data, signature);
}

ErrorCode KeyEngine::delete_device_key(const std::string& vin, const std::string& ecu_uid) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    std::string key_id = make_key_id(vin, ecu_uid);
    return hsm_->delete_key(key_id);
}

std::string KeyEngine::make_key_id(const std::string& vin, const std::string& ecu_uid) const {
    return vin + ":" + ecu_uid;
}

} // namespace sec
} // namespace tbox
