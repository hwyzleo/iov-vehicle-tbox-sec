#include "sec_service.h"
#include "hsm_interface.h"
#include <sstream>
#include <iomanip>

namespace tbox {
namespace sec {

SecService::SecService() : initialized_(false) {}

SecService::SecService(const SecServiceConfig& config)
    : config_(config), initialized_(false) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service)
    : config_(config), initialized_(false), diag_service_(diag_service) {}

ErrorCode SecService::initialize() {
    ErrorCode result = initialize_hsm();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    result = initialize_cloud_client();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    result = load_provision_state();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (diag_service_) {
        result = diag_service_->initialize();
        if (result != ErrorCode::SUCCESS) {
            return result;
        }
    }

    initialized_ = true;
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::generate_key_pair() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ProvisionStatus status = get_provision_status();

    if (status.state != ProvisionState::NONE &&
        status.state != ProvisionState::FAILED) {
        return ErrorCode::KEY_ALREADY_EXISTS;
    }

    if (diag_service_) {
        DiagResponse response;
        ErrorCode result = handle_diag_request(DiagRequestType::GENERATE_KEY_PAIR, {}, response);
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "Key pair generation via DIAG failed");
            return result;
        }
        
        if (response.error_code == ErrorCode::SUCCESS) {
            update_provision_state(ProvisionState::KEY_GENERATED);
        }
        return response.error_code;
    }

    ErrorCode result = generate_and_store_key_pair();
    if (result != ErrorCode::SUCCESS) {
        handle_error(result, "Key pair generation failed");
        return result;
    }

    update_provision_state(ProvisionState::KEY_GENERATED);
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::get_csr(std::vector<uint8_t>& csr_der) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ProvisionStatus status = get_provision_status();

    if (status.state == ProvisionState::NONE) {
        return ErrorCode::KEY_NOT_FOUND;
    }

    if (diag_service_) {
        DiagResponse response;
        ErrorCode result = handle_diag_request(DiagRequestType::READ_CSR, {}, response);
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "Read CSR via DIAG failed");
            return result;
        }
        
        if (response.error_code == ErrorCode::SUCCESS) {
            csr_der = response.data;
            
            if (status.state == ProvisionState::KEY_GENERATED) {
                update_provision_state(ProvisionState::CSR_BUILT);
            }
        }
        return response.error_code;
    }

    if (status.state == ProvisionState::KEY_GENERATED) {
        ErrorCode result = build_and_store_csr();
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "CSR building failed");
            return result;
        }

        update_provision_state(ProvisionState::CSR_BUILT);
    }

    csr_der = {0x30, 0x82, 0x01, 0x00};
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::submit_csr() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ProvisionStatus status = get_provision_status();

    if (status.state != ProvisionState::CSR_BUILT) {
        return ErrorCode::INVALID_PARAMETER;
    }

    ErrorCode result = submit_csr_to_cloud();
    if (result != ErrorCode::SUCCESS) {
        handle_error(result, "CSR submission failed");
        return result;
    }

    update_provision_state(ProvisionState::CSR_SUBMITTED);
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::inject_certificate(const std::vector<uint8_t>& cert_der) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ProvisionStatus status = get_provision_status();

    if (status.state != ProvisionState::CSR_SUBMITTED) {
        return ErrorCode::INVALID_PARAMETER;
    }

    if (diag_service_) {
        DiagResponse response;
        ErrorCode result = handle_diag_request(DiagRequestType::INJECT_CERTIFICATE, 
                                              cert_der, response);
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "Certificate injection via DIAG failed");
            return result;
        }
        
        if (response.error_code == ErrorCode::SUCCESS) {
            update_provision_state(ProvisionState::CERT_INSTALLED);
        }
        return response.error_code;
    }

    ErrorCode result = validate_and_store_certificate(cert_der);
    if (result != ErrorCode::SUCCESS) {
        handle_error(result, "Certificate injection failed");
        return result;
    }

    update_provision_state(ProvisionState::CERT_INSTALLED);
    return ErrorCode::SUCCESS;
}

ProvisionStatus SecService::get_provision_status() const {
    if (!state_manager_) {
        ProvisionStatus status;
        status.state = ProvisionState::NONE;
        return status;
    }

    return state_manager_->get_status(config_.vin, config_.ecu_uid);
}

ErrorCode SecService::reset_provision_status() {
    if (!initialized_ || !state_manager_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    return state_manager_->reset_status(config_.vin, config_.ecu_uid)
        ? ErrorCode::SUCCESS : ErrorCode::STORAGE_WRITE_FAILED;
}

std::string SecService::get_device_info() const {
    std::stringstream ss;
    ss << "VIN: " << config_.vin << "\n";
    ss << "ECU UID: " << config_.ecu_uid << "\n";
    ss << "HSM Type: " << config_.hsm_type << "\n";
    ss << "Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    ss << "DIAG Service: " << (diag_service_ ? "Connected" : "Not available") << "\n";

    if (initialized_) {
        ProvisionStatus status = get_provision_status();
        ss << "Provision State: " << provision_state_to_string(status.state) << "\n";
        ss << "Retry Count: " << status.retry_count << "\n";
    }

    return ss.str();
}

bool SecService::is_initialized() const {
    return initialized_;
}

ErrorCode SecService::initialize_hsm() {
    try {
        HsmFactory::HsmType hsm_type;
        if (config_.hsm_type == "software") {
            hsm_type = HsmFactory::HsmType::SOFTWARE;
        } else if (config_.hsm_type == "pkcs11") {
            hsm_type = HsmFactory::HsmType::PKCS11;
        } else if (config_.hsm_type == "trustzone") {
            hsm_type = HsmFactory::HsmType::TRUSTZONE;
        } else {
            return ErrorCode::INVALID_PARAMETER;
        }

        auto hsm = HsmFactory::create(hsm_type, config_.hsm_config_path);
        key_engine_ = std::make_unique<KeyEngine>(std::move(hsm));

        return key_engine_->initialize();
    } catch (const std::exception& e) {
        return ErrorCode::HSM_INIT_FAILED;
    }
}

ErrorCode SecService::initialize_cloud_client() {
    cloud_client_ = std::make_unique<CloudClient>(config_.cloud_config);
    return cloud_client_->initialize();
}

ErrorCode SecService::load_provision_state() {
    state_manager_ = std::make_unique<ProvisionStateManager>(config_.state_file_path);
    return state_manager_->load_state() ? ErrorCode::SUCCESS : ErrorCode::STORAGE_READ_FAILED;
}

ErrorCode SecService::generate_and_store_key_pair() {
    KeyPair key_pair;
    return key_engine_->generate_device_key(config_.vin, config_.ecu_uid, key_pair);
}

ErrorCode SecService::build_and_store_csr() {
    if (!csr_builder_) {
        csr_builder_ = std::make_unique<CsrBuilder>(key_engine_.get());
    }

    CsrConfig csr_config;
    csr_config.common_name = "ECU:" + config_.ecu_uid;
    csr_config.vin = config_.vin;
    csr_config.ecu_uid = config_.ecu_uid;
    csr_config.key_usage = "digitalSignature";
    csr_config.extended_key_usage = "clientAuth";

    std::vector<uint8_t> csr_der;
    return csr_builder_->build_csr(csr_config, csr_der);
}

ErrorCode SecService::submit_csr_to_cloud() {
    CertificateRequest request;
    request.vin = config_.vin;
    request.ecu_uid = config_.ecu_uid;
    request.csr_der = {0x30, 0x82, 0x01, 0x00};

    CertificateResponse response;
    return cloud_client_->submit_csr(request, response);
}

ErrorCode SecService::validate_and_store_certificate(const std::vector<uint8_t>& cert_der) {
    if (!cert_validator_) {
        cert_validator_ = std::make_unique<CertValidator>(key_engine_.get());
    }

    bool valid = false;
    ErrorCode result = cert_validator_->validate_certificate(config_.vin, config_.ecu_uid, cert_der, valid);

    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (!valid) {
        return ErrorCode::CERT_KEY_MISMATCH;
    }

    return ErrorCode::SUCCESS;
}

void SecService::update_provision_state(ProvisionState state, const std::string& error) {
    if (!state_manager_) {
        return;
    }

    ProvisionStatus status = get_provision_status();
    status.state = state;
    status.last_error = error;
    status.last_updated = std::chrono::system_clock::now();

    if (state == ProvisionState::FAILED) {
        status.retry_count++;
    }

    state_manager_->update_status(status);
}

void SecService::handle_error(ErrorCode error, const std::string& context) {
    update_provision_state(ProvisionState::FAILED, context + ": " + error_code_to_string(error));
}

void SecService::set_diag_service(std::shared_ptr<DiagServiceInterface> diag_service) {
    diag_service_ = diag_service;
}

ErrorCode SecService::handle_diag_request(DiagRequestType request_type,
                                         const std::vector<uint8_t>& request_data,
                                         DiagResponse& response) {
    if (!diag_service_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    
    if (!diag_service_->is_connected()) {
        return ErrorCode::CONNECTION_FAILED;
    }
    
    return diag_service_->send_request_sync(request_type, request_data, response);
}

} // namespace sec
} // namespace tbox
