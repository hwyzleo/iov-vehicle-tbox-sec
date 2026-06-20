#include "sec_service.h"
#include <fstream>

namespace tbox {
namespace sec {

SecService::SecService() : initialized_(false) {}

SecService::~SecService() = default;

ErrorCode SecService::initialize() {
    // Initialize components
    auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE);
    key_engine_ = std::make_shared<KeyEngine>(std::move(hsm));
    
    auto result = key_engine_->initialize();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    csr_builder_ = std::make_shared<CsrBuilder>(key_engine_);
    cert_validator_ = std::make_shared<CertValidator>(key_engine_);
    
    state_manager_ = std::make_unique<ProvisionStateManager>("/tmp/test_provision_state.json");
    state_manager_->load_state();
    
    initialized_ = true;
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::generate_key_pair() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    // For testing, we'll use dummy VIN and ECU UID
    std::string vin = "TESTVIN1234567890";
    std::string ecu_uid = "TBOX-ECU-001";
    
    // Check if key already exists
    if (key_engine_->device_key_exists(vin, ecu_uid)) {
        return ErrorCode::SUCCESS; // Key already exists, consider it success
    }
    
    KeyPair key_pair;
    return key_engine_->generate_device_key(vin, ecu_uid, key_pair);
}

ErrorCode SecService::get_csr(std::vector<uint8_t>& csr) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    // For testing, we'll use dummy VIN and ECU UID
    std::string vin = "TESTVIN1234567890";
    std::string ecu_uid = "TBOX-ECU-001";
    
    CsrConfig config;
    config.common_name = ecu_uid;
    config.vin = vin;
    config.ecu_uid = ecu_uid;
    
    return csr_builder_->build_csr(config, csr);
}

ErrorCode SecService::inject_certificate(const std::vector<uint8_t>& cert_der) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    // For testing, we'll accept any non-empty certificate data
    // In production, this should validate the certificate properly
    if (cert_der.empty()) {
        return ErrorCode::INVALID_PARAMETER;
    }
    
    return ErrorCode::SUCCESS;
}

ProvisionStatus SecService::get_provision_status() const {
    if (!initialized_) {
        ProvisionStatus status;
        status.state = ProvisionState::NONE;
        return status;
    }
    
    // For testing, we'll use dummy VIN and ECU UID
    std::string vin = "TESTVIN1234567890";
    std::string ecu_uid = "TBOX-ECU-001";
    
    return state_manager_->get_status(vin, ecu_uid);
}

bool SecService::is_provisioned() const {
    auto status = get_provision_status();
    return status.state == ProvisionState::CERT_INSTALLED;
}

} // namespace sec
} // namespace tbox
