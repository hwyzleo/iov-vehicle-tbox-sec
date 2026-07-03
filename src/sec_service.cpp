#include "sec_service.h"
#include "hsm_interface.h"
#include "constants.h"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <iostream>
#include <fstream>
#include <openssl/rand.h>

#ifdef USE_YAML_CPP
#include <yaml-cpp/yaml.h>
#endif

namespace tbox {
namespace sec {

SecService::SecService() : initialized_(false) {}

SecService::SecService(const SecServiceConfig& config)
    : config_(config), initialized_(false) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service)
    : config_(config), initialized_(false), diag_service_(diag_service) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service,
                      std::shared_ptr<ProvServiceInterface> prov_service)
    : config_(config), initialized_(false), diag_service_(diag_service), prov_service_(prov_service) {}

SecService::SecService(const SecServiceConfig& config, hwyz::store::Store store)
    : config_(config), initialized_(false), store_(std::move(store)) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service,
                      std::shared_ptr<ProvServiceInterface> prov_service,
                      hwyz::store::Store store)
    : config_(config), initialized_(false), diag_service_(diag_service), prov_service_(prov_service), store_(std::move(store)) {}

ErrorCode SecService::initialize() {
    // Validate required config
    if (config_.get_hsm_type().empty() &&
        config_.get_key_provisioning_mode() != KEY_PROVISIONING_MODE_SOFT_FILE) {
        std::cerr << "[SEC] hsm.type is required" << std::endl;
        return ErrorCode::CONFIG_ERROR;
    }

    auto cloud_config = config_.get_cloud_config();
    if (cloud_config.timeout_ms <= 0) {
        std::cerr << "[SEC] cloud.timeout_ms must be positive" << std::endl;
        return ErrorCode::CONFIG_ERROR;
    }
    if (cloud_config.retry_count < 0) {
        std::cerr << "[SEC] cloud.retry_count must be non-negative" << std::endl;
        return ErrorCode::CONFIG_ERROR;
    }
    if (cloud_config.retry_delay_ms < 0) {
        std::cerr << "[SEC] cloud.retry_delay_ms must be non-negative" << std::endl;
        return ErrorCode::CONFIG_ERROR;
    }

    ErrorCode result = fetch_vehicle_info();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    result = initialize_hsm();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    result = initialize_cloud_client();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    // Load provision state - prefer store over state_manager
    if (store_.isReady()) {
        result = load_provision_state_from_store();
    } else {
        result = load_provision_state();
    }
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    // Load CA certificate
    std::string ca_cert_path = config_.get_ca_cert_path();

    std::cerr << "[SEC] Initializing CA cert, ca_cert_path='" << ca_cert_path << "'" << std::endl;

    // If ca_cert_path is empty, try to load from default config
    if (ca_cert_path.empty()) {
        ca_cert_path = find_ca_cert_from_config();
        std::cerr << "[SEC] find_ca_cert_from_config returned: '" << ca_cert_path << "'" << std::endl;
    }

    if (!ca_cert_path.empty()) {
        std::ifstream ca_file(ca_cert_path, std::ios::binary);
        if (ca_file.is_open()) {
            std::vector<uint8_t> ca_cert_der(
                (std::istreambuf_iterator<char>(ca_file)),
                std::istreambuf_iterator<char>());
            ca_file.close();

            if (!ca_cert_der.empty()) {
                result = set_ca_certificate(ca_cert_der);
                if (result != ErrorCode::SUCCESS) {
                    std::cerr << "[SEC] Failed to load CA certificate from: "
                              << ca_cert_path << std::endl;
                    // Continue initialization - CA cert is optional for self-signed certs
                } else {
                    std::cerr << "[SEC] CA certificate loaded from: "
                              << ca_cert_path << std::endl;
                }
            }
        } else {
            std::cerr << "[SEC] Cannot open CA certificate file: "
                      << ca_cert_path << std::endl;
            // Continue initialization - CA cert is optional
        }
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

    // 检查密钥是否真正存在于 HSM 中
    if (status.state != ProvisionState::NONE &&
        status.state != ProvisionState::FAILED) {
        // 检查 HSM 中是否真的有密钥
        if (key_engine_ && key_engine_->device_key_exists(vin_, device_sn_)) {
            // 密钥确实存在，静默返回成功
            return ErrorCode::SUCCESS;
        }
        // 状态说有密钥但 HSM 中没有，继续生成
        std::cout << "[SEC] State says key exists but not in HSM, regenerating..." << std::endl;
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
    std::cout << "[SEC] get_csr: state=" << static_cast<int>(status.state) << std::endl;

    if (status.state == ProvisionState::NONE) {
        return ErrorCode::KEY_NOT_FOUND;
    }

    // 如果 CSR 尚未构建或 csr_der_ 为空，重新构建
    if (status.state == ProvisionState::KEY_GENERATED || csr_der_.empty()) {
        std::cout << "[SEC] Building CSR (state=" << static_cast<int>(status.state)
                  << " csr_der_.empty()=" << csr_der_.empty() << ")..." << std::endl;
        ErrorCode result = build_and_store_csr();
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "CSR building failed");
            return result;
        }

        update_provision_state(ProvisionState::CSR_BUILT);
    }

    csr_der = csr_der_;
    std::cout << "[SEC] get_csr: returning csr_der_.size()=" << csr_der_.size() << std::endl;
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

    if (diag_service_) {
        DiagResponse response;
        ErrorCode result = handle_diag_request(DiagRequestType::SUBMIT_CSR, {}, response);
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "CSR submission via DIAG failed");
            return result;
        }
        
        if (response.error_code == ErrorCode::SUCCESS) {
            update_provision_state(ProvisionState::CSR_SUBMITTED);
        }
        return response.error_code;
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

    // 允许在 CSR_BUILT 或 CSR_SUBMITTED 状态下注入证书
    // CSR_BUILT: 工位自己走 MES→OAPI→PKI 提交 CSR，不经过 DIAG
    // CSR_SUBMITTED: 通过 DIAG 提交了 CSR
    if (status.state != ProvisionState::CSR_BUILT &&
        status.state != ProvisionState::CSR_SUBMITTED) {
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

ErrorCode SecService::apply_certificate() {
    if (!initialized_) {
        std::cerr << "[SEC] apply_certificate: not initialized" << std::endl;
        return ErrorCode::NOT_INITIALIZED;
    }

    ProvisionStatus status = get_provision_status();
    std::cerr << "[SEC] apply_certificate: state=" << static_cast<int>(status.state) << std::endl;

    // 如果已经完成，直接返回
    if (status.state == ProvisionState::CERT_INSTALLED) {
        return ErrorCode::SUCCESS;
    }

    // 如果是失败状态，重置为NONE重新开始
    if (status.state == ProvisionState::FAILED) {
        status.state = ProvisionState::NONE;
        status.retry_count = 0;
        status.last_error.clear();
        // Save the reset state
        if (store_.isReady()) {
            try {
                store_.save("provision_state", status);
            } catch (const hwyz::store::StoreException& e) {
                std::cerr << "[SEC] Failed to reset state in store: " << e.what() << std::endl;
            }
        } else if (state_manager_) {
            state_manager_->update_status(status);
        }
    }

    // 如果有DIAG服务，通过DIAG服务执行整个流程
    if (diag_service_) {
        std::cerr << "[SEC] apply_certificate: using diag_service" << std::endl;
        DiagResponse response;
        ErrorCode result = handle_diag_request(DiagRequestType::APPLY_CERTIFICATE, {}, response);
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "Certificate application via DIAG failed");
            return result;
        }
        return response.error_code;
    }

    // 步骤1：生成密钥对
    if (status.state == ProvisionState::NONE) {
        std::cerr << "[SEC] apply_certificate: generating key pair" << std::endl;
        ErrorCode result = generate_key_pair();
        if (result != ErrorCode::SUCCESS) {
            std::cerr << "[SEC] apply_certificate: generate_key_pair failed: " << static_cast<int>(result) << std::endl;
            return result;
        }
        status.state = ProvisionState::KEY_GENERATED;
    }

    // 步骤2：构建CSR
    if (status.state == ProvisionState::KEY_GENERATED) {
        std::vector<uint8_t> csr_der;
        ErrorCode result = get_csr(csr_der);
        if (result != ErrorCode::SUCCESS) {
            return result;
        }
        status.state = ProvisionState::CSR_BUILT;
    }

    // 步骤3：提交CSR到云端
    if (status.state == ProvisionState::CSR_BUILT) {
        std::cerr << "[SEC] apply_certificate: submitting CSR" << std::endl;
        ErrorCode result = submit_csr();
        if (result != ErrorCode::SUCCESS) {
            std::cerr << "[SEC] apply_certificate: submit_csr failed: " << static_cast<int>(result) << std::endl;
            return result;
        }
        status.state = ProvisionState::CSR_SUBMITTED;
    }

    // 步骤4：注入证书（这里需要外部提供证书，或者等待云端返回）
    // 注意：在实际流程中，证书可能需要从云端异步获取
    // 这里暂时返回SUCCESS，表示CSR已提交成功
    // 证书注入需要通过inject_certificate()单独调用
    std::cerr << "[SEC] apply_certificate: success" << std::endl;
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::get_seed(uint8_t level, std::vector<uint8_t>& seed) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    // UDS security level validation:
    // - requestSeed uses odd security levels (0x01, 0x03, 0x05, ..., 0x27, etc.)
    // - sendKey uses even security levels (0x02, 0x04, 0x06, ..., 0x28, etc.)
    // - requestSeed level must be odd (bit 0 = 1)
    if ((level & 0x01) == 0 || level == 0) {
        return ErrorCode::INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(seed_mutex_);

    // Check if in lockout period
    if (is_in_lockout()) {
        return ErrorCode::UDS_SECURITY_DENIED;
    }

    // Generate new seed
    ErrorCode result = generate_random_seed(seed);
    if (result != ErrorCode::SUCCESS) {
        handle_error(result, "Seed generation failed");
        return ErrorCode::SEED_GENERATION_FAILED;
    }

    // Store seed state with security level
    current_seed_.seed = seed;
    current_seed_.security_level = level;
    current_seed_.generated = true;
    current_seed_.consumed = false;
    current_seed_.generated_at = std::chrono::steady_clock::now();

    return ErrorCode::SUCCESS;
}

ErrorCode SecService::verify_key(uint8_t level, const std::vector<uint8_t>& key) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    // UDS security level validation:
    // - sendKey uses even security levels (0x02, 0x04, 0x06, ..., 0x28, etc.)
    // - sendKey level must be even (bit 0 = 0)
    if ((level & 0x01) != 0 || level == 0) {
        return ErrorCode::INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(seed_mutex_);

    // Check if in lockout period
    if (is_in_lockout()) {
        return ErrorCode::UDS_SECURITY_DENIED;
    }

    // Check if seed is valid
    if (!is_seed_valid()) {
        std::cerr << "[SEC] verify_key: seed not valid" << std::endl;
        return ErrorCode::KEY_VERIFICATION_FAILED;
    }

    // Validate that sendKey level = requestSeed level + 1
    if (level != current_seed_.security_level + 1) {
        return ErrorCode::INVALID_PARAMETER;
    }

    // Compute expected key
    std::vector<uint8_t> expected_key;
    ErrorCode result = compute_expected_key(current_seed_.seed, expected_key);
    if (result != ErrorCode::SUCCESS) {
        handle_error(result, "Key computation failed");
        return ErrorCode::KEY_VERIFICATION_FAILED;
    }

    // Debug logging
    std::cerr << "[SEC] verify_key debug:" << std::endl;
    std::cerr << "  seed(" << current_seed_.seed.size() << "): ";
    for (auto b : current_seed_.seed) std::cerr << std::hex << (int)b << " ";
    std::cerr << std::endl;
    std::cerr << "  expected(" << expected_key.size() << "): ";
    for (auto b : expected_key) std::cerr << std::hex << (int)b << " ";
    std::cerr << std::endl;
    std::cerr << "  received(" << key.size() << "): ";
    for (auto b : key) std::cerr << std::hex << (int)b << " ";
    std::cerr << std::endl;

    // Compare keys (constant-time comparison to prevent timing attacks)
    bool key_valid = (key.size() == expected_key.size());
    if (key_valid) {
        volatile uint8_t diff = 0;
        for (size_t i = 0; i < key.size(); ++i) {
            diff |= key[i] ^ expected_key[i];
        }
        key_valid = (diff == 0);
    }

    if (key_valid) {
        // Key verification successful
        invalidate_seed();
        reset_failed_attempts();
        return ErrorCode::SUCCESS;
    } else {
        // Key verification failed
        increment_failed_attempts();
        invalidate_seed();
        return ErrorCode::KEY_VERIFICATION_FAILED;
    }
}

ProvisionStatus SecService::get_provision_status() const {
    // Try store first
    if (store_.isReady()) {
        try {
            auto status = store_.load<ProvisionStatus>("provision_state");
            return status;
        } catch (const hwyz::store::StoreException& e) {
            if (e.getError().code == hwyz::store::StoreError::kKeyNotFound) {
                // No state saved yet, return default
                ProvisionStatus status;
                status.vin = vin_;
                status.ecu_uid = device_sn_;
                status.state = ProvisionState::NONE;
                status.retry_count = 0;
                status.last_updated = std::chrono::system_clock::now();
                return status;
            }
            // Other errors - fall through to state_manager
        }
    }

    // Fallback to state_manager
    if (!state_manager_) {
        ProvisionStatus status;
        status.state = ProvisionState::NONE;
        return status;
    }

    return state_manager_->get_status(vin_, device_sn_);
}

ErrorCode SecService::reset_provision_status() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    // Try store first
    if (store_.isReady()) {
        try {
            store_.remove("provision_state");
            return ErrorCode::SUCCESS;
        } catch (const hwyz::store::StoreException& e) {
            std::cerr << "[SEC] Failed to reset provision state from store: " << e.what() << std::endl;
            return ErrorCode::STORAGE_WRITE_FAILED;
        }
    }

    // Fallback to state_manager
    if (!state_manager_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    return state_manager_->reset_status(vin_, device_sn_)
        ? ErrorCode::SUCCESS : ErrorCode::STORAGE_WRITE_FAILED;
}

std::string SecService::get_device_info() const {
    std::stringstream ss;
    ss << "VIN: " << vin_ << "\n";
    ss << "Device SN: " << device_sn_ << "\n";
    ss << "HSM Type: " << config_.get_hsm_type() << "\n";
    ss << "Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    ss << "DIAG Service: " << (diag_service_ ? (diag_service_->is_connected() ? "Connected" : "Disconnected") : "Not available") << "\n";
    ss << "PROV Service: " << (prov_service_ ? (prov_service_->is_connected() ? "Connected" : "Disconnected") : "Not available") << "\n";

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
        // 检查是否允许 soft_file 模式
        if (config_.get_key_provisioning_mode() == KEY_PROVISIONING_MODE_SOFT_FILE) {
            if (config_.get_is_production()) {
                // 量产环境禁止使用 soft_file 模式
                std::cerr << "[SEC] Software key file mode is not allowed in production environment" << std::endl;
                return ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED;
            }
            std::cout << "[SEC] Initializing in software file mode (test only)" << std::endl;
        }

        // 根据密钥生成模式选择 HSM 类型
        HsmFactory::HsmType hsm_type;
        std::string config_path;

        if (config_.get_key_provisioning_mode() == KEY_PROVISIONING_MODE_SOFT_FILE) {
            // 软件落盘模式
            hsm_type = HsmFactory::HsmType::SOFT_FILE;
            config_path = config_.get_soft_key_path();
        } else {
            // HSM 模式（默认）
            std::string hsm_type_str = config_.get_hsm_type();
            if (hsm_type_str == "software") {
                hsm_type = HsmFactory::HsmType::SOFTWARE;
            } else if (hsm_type_str == "pkcs11") {
                hsm_type = HsmFactory::HsmType::PKCS11;
            } else if (hsm_type_str == "trustzone") {
                hsm_type = HsmFactory::HsmType::TRUSTZONE;
            } else {
                return ErrorCode::INVALID_PARAMETER;
            }
            config_path = config_.get_hsm_library_path();
        }

        auto hsm = HsmFactory::create(hsm_type, config_path);
        key_engine_ = std::make_unique<KeyEngine>(std::move(hsm));

        return key_engine_->initialize();
    } catch (const std::exception& e) {
        return ErrorCode::HSM_INIT_FAILED;
    }
}

ErrorCode SecService::initialize_cloud_client() {
    cloud_client_ = std::make_unique<CloudClient>(config_.get_cloud_config());
    return cloud_client_->initialize();
}

ErrorCode SecService::load_provision_state() {
    state_manager_ = std::make_unique<ProvisionStateManager>(config_.get_state_file_path());
    return state_manager_->load_state() ? ErrorCode::SUCCESS : ErrorCode::STORAGE_READ_FAILED;
}

ErrorCode SecService::load_provision_state_from_store() {
    try {
        auto status = store_.load<ProvisionStatus>("provision_state");
        std::cerr << "[SEC] Loaded provision state from store: "
                  << provision_state_to_string(status.state) << std::endl;
        return ErrorCode::SUCCESS;
    } catch (const hwyz::store::StoreException& e) {
        if (e.getError().code == hwyz::store::StoreError::kKeyNotFound) {
            // No state saved yet - this is normal for first run
            std::cerr << "[SEC] No provision state in store, starting fresh" << std::endl;
            return ErrorCode::SUCCESS;
        }
        std::cerr << "[SEC] Failed to load provision state from store: " << e.what() << std::endl;
        return ErrorCode::STORAGE_READ_FAILED;
    }
}

ErrorCode SecService::fetch_vehicle_info() {
    if (!prov_service_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    VehicleInfo info;
    ErrorCode result = prov_service_->get_vehicle_info(info);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    vin_ = info.vin;
    device_sn_ = info.device_sn;
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::generate_and_store_key_pair() {
    KeyPair key_pair;
    std::cout << "[SEC] Generating key pair with vin=" << vin_ << " device_sn=" << device_sn_ << std::endl;

    auto err = key_engine_->generate_device_key(vin_, device_sn_, key_pair);
    if (err != ErrorCode::SUCCESS) {
        return err;
    }

    // 记录存储模式
    if (key_pair.storage_mode == KeyStorageMode::SOFT_FILE) {
        std::cout << "[SEC] Key generated in software file mode (test only): " << key_pair.key_id << std::endl;
    } else {
        std::cout << "[SEC] Key generated in HSM mode: " << key_pair.key_id << std::endl;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SecService::build_and_store_csr() {
    if (!csr_builder_) {
        csr_builder_ = std::make_unique<CsrBuilder>(key_engine_.get());
    }

    CsrConfig csr_config;
    csr_config.device_sn = device_sn_;
    csr_config.key_id = device_sn_;  // key_id 暂时使用 device_sn
    csr_config.algorithm = "ecdsa-p256";

    std::cout << "[SEC] Building CSR with vin=" << vin_ << " device_sn=" << device_sn_ << std::endl;
    ErrorCode result = csr_builder_->build_csr(vin_, csr_config, csr_der_);
    std::cout << "[SEC] build_csr result=" << static_cast<int>(result)
              << " csr_der_.size()=" << csr_der_.size() << std::endl;
    return result;
}

ErrorCode SecService::submit_csr_to_cloud() {
    CertificateRequest request;
    request.device_sn = device_sn_;
    request.csr_der = {0x30, 0x82, 0x01, 0x00};

    CertificateResponse response;
    return cloud_client_->submit_csr(request, response);
}

ErrorCode SecService::validate_and_store_certificate(const std::vector<uint8_t>& cert_der) {
    if (!cert_validator_) {
        cert_validator_ = std::make_unique<CertValidator>(key_engine_.get());
    }

    bool valid = false;
    ErrorCode result = cert_validator_->validate_certificate(vin_, device_sn_, cert_der, valid);

    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (!valid) {
        return ErrorCode::CERT_KEY_MISMATCH;
    }

    // Store certificate to file system
    result = store_certificate_to_file(cert_der);
    if (result != ErrorCode::SUCCESS) {
        std::cerr << "[SEC] Failed to store certificate" << std::endl;
        return result;
    }

    std::cout << "[SEC] Certificate validated and stored successfully" << std::endl;
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::store_certificate_to_file(const std::vector<uint8_t>& cert_der) {
    // Try store first
    if (store_.isReady()) {
        try {
            std::string cert_key = "device_cert:" + vin_ + ":" + device_sn_;
            store_.save(cert_key, cert_der);
            std::cout << "[SEC] Certificate stored in store with key: " << cert_key << std::endl;
            return ErrorCode::SUCCESS;
        } catch (const hwyz::store::StoreException& e) {
            std::cerr << "[SEC] Failed to store certificate in store: " << e.what() << std::endl;
            // Fall through to file-based storage
        }
    }

    // Fallback to file-based storage
    // Determine certificate store path
    std::string cert_dir = config_.get_cert_store_path();
    if (cert_dir.empty()) {
        // Try to find from config file
        cert_dir = find_cert_store_from_config();
    }
    if (cert_dir.empty()) {
        cert_dir = "./data/certs";  // Default path
    }

    // Create directory if it doesn't exist
    std::string mkdir_cmd = "mkdir -p " + cert_dir;
    if (std::system(mkdir_cmd.c_str()) != 0) {
        std::cerr << "[SEC] Failed to create cert directory: " << cert_dir << std::endl;
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    // Generate certificate filename: {vin}_{ecu_uid}.der
    std::string cert_path = cert_dir + "/" + vin_ + "_" + device_sn_ + ".der";

    // Write certificate to file
    std::ofstream cert_file(cert_path, std::ios::binary);
    if (!cert_file.is_open()) {
        std::cerr << "[SEC] Failed to open cert file for writing: " << cert_path << std::endl;
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    cert_file.write(reinterpret_cast<const char*>(cert_der.data()), cert_der.size());
    cert_file.close();

    if (!cert_file.good()) {
        std::cerr << "[SEC] Failed to write certificate to file: " << cert_path << std::endl;
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    std::cout << "[SEC] Certificate stored at: " << cert_path << std::endl;
    return ErrorCode::SUCCESS;
}

std::string SecService::find_cert_store_from_config() {
    std::vector<std::string> config_paths = {
        "config/config.yaml",
        "config/config.dev.yaml",
        "/etc/tbox/config.yaml",
        "/var/lib/tbox/config.yaml"
    };

#ifdef USE_YAML_CPP
    for (const auto& config_path : config_paths) {
        try {
            YAML::Node config = YAML::LoadFile(config_path);
            YAML::Node tbox = config["tbox"];
            if (tbox && tbox["storage"] && tbox["storage"]["cert_store"]) {
                std::string cert_store = tbox["storage"]["cert_store"].as<std::string>();
                if (!cert_store.empty()) {
                    return cert_store;
                }
            }
        } catch (const std::exception&) {
            continue;
        }
    }
#endif

    return "";
}

void SecService::update_provision_state(ProvisionState state, const std::string& error) {
    ProvisionStatus status = get_provision_status();
    status.state = state;
    status.last_error = error;
    status.last_updated = std::chrono::system_clock::now();

    if (state == ProvisionState::FAILED) {
        status.retry_count++;
    }

    // Try store first
    if (store_.isReady()) {
        try {
            store_.save("provision_state", status);
            return;
        } catch (const hwyz::store::StoreException& e) {
            std::cerr << "[SEC] Failed to save provision state to store: " << e.what() << std::endl;
            // Fall through to state_manager
        }
    }

    // Fallback to state_manager
    if (state_manager_) {
        state_manager_->update_status(status);
    }
}

void SecService::handle_error(ErrorCode error, const std::string& context) {
    update_provision_state(ProvisionState::FAILED, context + ": " + error_code_to_string(error));
}

void SecService::set_diag_service(std::shared_ptr<DiagServiceInterface> diag_service) {
    diag_service_ = diag_service;
}

void SecService::set_prov_service(std::shared_ptr<ProvServiceInterface> prov_service) {
    prov_service_ = prov_service;
}

ErrorCode SecService::set_ca_certificate(const std::vector<uint8_t>& ca_cert_der) {
    if (ca_cert_der.empty()) {
        return ErrorCode::INVALID_PARAMETER;
    }

    // Create or update cert validator with CA certificate
    if (!cert_validator_) {
        cert_validator_ = std::make_unique<CertValidator>(key_engine_.get());
    }
    cert_validator_->set_ca_certificate(ca_cert_der);
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::generate_random_seed(std::vector<uint8_t>& seed) {
    seed.resize(SEED_KEY_SIZE);
    
    // Use OpenSSL for cryptographically secure random generation
    if (RAND_bytes(seed.data(), SEED_KEY_SIZE) != 1) {
        return ErrorCode::SEED_GENERATION_FAILED;
    }
    
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::compute_expected_key(const std::vector<uint8_t>& seed, std::vector<uint8_t>& expected_key) {
    if (seed.size() != SEED_KEY_SIZE) {
        return ErrorCode::INVALID_PARAMETER;
    }

    // UDS standard XOR-based key computation
    // key = seed XOR shared_secret
    // In production, shared_secret should come from HSM/secure element
    
    // Shared secret (placeholder - in production from HSM)
    std::vector<uint8_t> shared_secret(SEED_KEY_SIZE, 0x01);
    
    expected_key.resize(SEED_KEY_SIZE);
    
    // XOR-based computation (common UDS algorithm)
    for (size_t i = 0; i < SEED_KEY_SIZE; i++) {
        expected_key[i] = seed[i] ^ shared_secret[i];
    }
    
    return ErrorCode::SUCCESS;
}

bool SecService::is_seed_valid() const {
    if (!current_seed_.generated || current_seed_.consumed) {
        return false;
    }
    
    // Check if seed has expired (e.g., after 30 seconds)
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - current_seed_.generated_at);
    
    return elapsed.count() < 30; // 30 second validity
}

void SecService::invalidate_seed() {
    current_seed_.consumed = true;
    // Clear seed from memory
    std::fill(current_seed_.seed.begin(), current_seed_.seed.end(), 0);
}

bool SecService::is_in_lockout() const {
    if (!in_lockout_) {
        return false;
    }
    
    auto now = std::chrono::steady_clock::now();
    if (now >= lockout_until_) {
        // Lockout period has expired
        return false;
    }
    
    return true;
}

void SecService::increment_failed_attempts() {
    failed_attempts_++;
    
    if (failed_attempts_ >= MAX_FAILED_ATTEMPTS) {
        in_lockout_ = true;
        lockout_until_ = std::chrono::steady_clock::now() + 
                        std::chrono::seconds(LOCKOUT_DURATION_SEC);
        failed_attempts_ = 0; // Reset counter after lockout
    }
}

void SecService::reset_failed_attempts() {
    failed_attempts_ = 0;
    in_lockout_ = false;
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

std::string SecService::find_ca_cert_from_config() {
    // Default config paths to search
    std::vector<std::string> config_paths = {
        "config/config.yaml",
        "config/config.dev.yaml",
        "/etc/tbox/config.yaml",
        "/var/lib/tbox/config.yaml"
    };

#ifdef USE_YAML_CPP
    for (const auto& config_path : config_paths) {
        try {
            YAML::Node config = YAML::LoadFile(config_path);
            YAML::Node tbox = config["tbox"];
            if (tbox && tbox["storage"] && tbox["storage"]["ca_cert"]) {
                std::string ca_cert_path = tbox["storage"]["ca_cert"].as<std::string>();
                if (!ca_cert_path.empty()) {
                    std::cerr << "[SEC] Found CA cert path in config: " << config_path
                              << " -> " << ca_cert_path << std::endl;
                    return ca_cert_path;
                }
            }
        } catch (const std::exception&) {
            // Config file not found or parse error, try next
            continue;
        }
    }
#endif

    return "";
}

} // namespace sec
} // namespace tbox
