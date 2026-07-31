#include "key_engine.h"
#include "constants.h"
#include "sec_log_adapter.h"
#include "log_types.h"
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
        SecLogAdapter::service().debug(
            "sec.keypair.already_exists", "密钥已存在，返回既有密钥",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_id)}});
        key_pair.key_id = key_id;
        key_pair.algorithm = KEY_ALGORITHM_ECDSA_P256;
        key_pair.private_key_exists = true;
        return hsm_->export_public_key(key_id, key_pair.public_key);
    }
    
    // Generate key pair in HSM
    auto start_time = std::chrono::steady_clock::now();
    ErrorCode result = hsm_->generate_key_pair(key_id, KEY_ALGORITHM_ECDSA_P256, key_pair);
    auto end_time = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    
    if (result == ErrorCode::SUCCESS) {
        SecLogAdapter::service().info(
            "sec.keypair.generate.succeeded",
            "密钥对生成成功",
            {
                {"algorithm", tbox::fw::log::FieldValue::makeString(KEY_ALGORITHM_ECDSA_P256)},
                {"storage_mode", tbox::fw::log::FieldValue::makeString("hsm")},
                {"key_id_hash", tbox::fw::log::FieldValue::makeString(key_id)},
                {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)}
            }
        );
    } else {
        SecLogAdapter::service().error(
            "sec.keypair.generate.failed",
            "密钥对生成失败",
            {
                {"algorithm", tbox::fw::log::FieldValue::makeString(KEY_ALGORITHM_ECDSA_P256)},
                {"storage_mode", tbox::fw::log::FieldValue::makeString("hsm")},
                {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)},
                {"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(result))}
            }
        );
    }
    
    return result;
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

ErrorCode KeyEngine::export_device_private_key(const std::string& vin,
                                                const std::string& ecu_uid,
                                                std::vector<uint8_t>& private_key) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    std::string key_id = make_key_id(vin, ecu_uid);

    if (!hsm_->key_exists(key_id)) {
        return ErrorCode::KEY_NOT_FOUND;
    }

    return hsm_->export_private_key(key_id, private_key);
}

std::string KeyEngine::make_key_id(const std::string& device_sn, const std::string& key_id) const {
    return device_sn + "+" + key_id;
}

} // namespace sec
} // namespace tbox
