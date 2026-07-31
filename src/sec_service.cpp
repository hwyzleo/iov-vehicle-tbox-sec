#include "sec_service.h"
#include "hsm_interface.h"
#include "constants.h"
#include "sec_log_adapter.h"
#include "log_types.h"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <iostream>
#include <fstream>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#ifdef USE_YAML_CPP
#include <yaml-cpp/yaml.h>
#endif

#include "tls_credential_provider.h"
#include "peer_credential.h"
#include "ipc_protocol.h"

namespace tbox {
namespace sec {

SecService::SecService() : initialized_(false), store_(std::nullopt) {}

SecService::~SecService() {
    // CR-011: IPC Server 不再由 SecService 持有（由 SecApplication 组合根管理）。
    // 析构时清零待消费 seed 等瞬态秘密。
    invalidate_seed();
}

SecService::SecService(const SecServiceConfig& config)
    : config_(config), initialized_(false), store_(std::nullopt) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service)
    : config_(config), initialized_(false), diag_service_(diag_service), store_(std::nullopt) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service,
                      std::shared_ptr<ProvServiceInterface> prov_service)
    : config_(config), initialized_(false), diag_service_(diag_service), prov_service_(prov_service), store_(std::nullopt) {}

SecService::SecService(const SecServiceConfig& config, hwyz::store::Store store)
    : config_(config), initialized_(false), store_(std::make_optional(std::move(store))) {}

SecService::SecService(const SecServiceConfig& config,
                      std::shared_ptr<DiagServiceInterface> diag_service,
                      std::shared_ptr<ProvServiceInterface> prov_service,
                      hwyz::store::Store store)
    : config_(config), initialized_(false), diag_service_(diag_service), prov_service_(prov_service), store_(std::make_optional(std::move(store))) {}

ErrorCode SecService::initialize() {
    // Validate required config
    if (config_.get_hsm_type().empty() &&
        config_.get_key_provisioning_mode() != KEY_PROVISIONING_MODE_SOFT_FILE) {
        SecLogAdapter::service().error(
            "sec.config.hsm_type_required", "hsm.type 未配置");
        return ErrorCode::CONFIG_ERROR;
    }

    auto cloud_config = config_.get_cloud_config();
    if (cloud_config.timeout_ms <= 0) {
        SecLogAdapter::service().error(
            "sec.config.cloud_timeout_invalid", "cloud.timeout_ms 必须为正",
            {{"timeout_ms", tbox::fw::log::FieldValue::makeInt(cloud_config.timeout_ms)}});
        return ErrorCode::CONFIG_ERROR;
    }
    if (cloud_config.retry_count < 0) {
        SecLogAdapter::service().error(
            "sec.config.cloud_retry_count_invalid", "cloud.retry_count 不能为负",
            {{"retry_count", tbox::fw::log::FieldValue::makeInt(cloud_config.retry_count)}});
        return ErrorCode::CONFIG_ERROR;
    }
    if (cloud_config.retry_delay_ms < 0) {
        SecLogAdapter::service().error(
            "sec.config.cloud_retry_delay_invalid", "cloud.retry_delay_ms 不能为负",
            {{"retry_delay_ms", tbox::fw::log::FieldValue::makeInt(cloud_config.retry_delay_ms)}});
        return ErrorCode::CONFIG_ERROR;
    }

    ErrorCode result = initialize_hsm();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    result = initialize_cloud_client();
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    // Load provision state from store if available
    if (store_.has_value() && store_->isReady()) {
        result = load_provision_state_from_store();
        if (result != ErrorCode::SUCCESS) {
            SecLogAdapter::service().error(
                "sec.store.load_failed", "从 store 加载 provision 状态失败");
        }
    }

    // Load CA certificate
    // 优先从 SEC 受控存储读取共享信任根（key: root_ca，PEM），与 TLS provider 同源，
    // 消除 storage.ca_cert 与 tls root_ca 的重复。缺失时回退到旧的配置文件路径逻辑。
    bool ca_loaded = false;
    if (store_.has_value() && store_->isReady()) {
        try {
            if (store_->has("root_ca")) {
                std::string root_ca_pem = store_->load<std::string>("root_ca");
                if (!root_ca_pem.empty()) {
                    std::vector<uint8_t> ca_cert_bytes(root_ca_pem.begin(), root_ca_pem.end());
                    if (set_ca_certificate(ca_cert_bytes) == ErrorCode::SUCCESS) {
                        SecLogAdapter::certificate().info(
                            "sec.ca.loaded_from_store", "CA 证书从 store 加载成功 (key=root_ca)");
                        ca_loaded = true;
                    }
                }
            }
        } catch (const std::exception& e) {
            SecLogAdapter::certificate().error(
                "sec.ca.load_from_store_failed", "从 store 加载 root_ca 失败",
                {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        }
    }

    if (!ca_loaded) {
        // 回退：旧的配置文件路径（storage.ca_cert / config.yaml）
        std::string ca_cert_path = config_.get_ca_cert_path();

        SecLogAdapter::certificate().debug(
            "sec.ca.fallback_init", "回退到配置文件路径加载 CA 证书",
            {{"ca_cert_path", tbox::fw::log::FieldValue::makeString(ca_cert_path)}});

        // If ca_cert_path is empty, try to load from default config
        if (ca_cert_path.empty()) {
            ca_cert_path = find_ca_cert_from_config();
            SecLogAdapter::certificate().debug(
                "sec.ca.config_path_resolved", "find_ca_cert_from_config 解析路径",
                {{"ca_cert_path", tbox::fw::log::FieldValue::makeString(ca_cert_path)}});
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
                        SecLogAdapter::certificate().error(
                            "sec.ca.load_file_failed", "CA 证书文件加载失败",
                            {{"ca_cert_path", tbox::fw::log::FieldValue::makeString(ca_cert_path)},
                             {"error_code", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result))}});
                        // Continue initialization - CA cert is optional for self-signed certs
                    } else {
                        SecLogAdapter::certificate().info(
                            "sec.ca.loaded_from_file", "CA 证书从文件加载成功",
                            {{"ca_cert_path", tbox::fw::log::FieldValue::makeString(ca_cert_path)}});
                    }
                }
            } else {
                SecLogAdapter::certificate().error(
                    "sec.ca.file_open_failed", "无法打开 CA 证书文件",
                    {{"ca_cert_path", tbox::fw::log::FieldValue::makeString(ca_cert_path)}});
                // Continue initialization - CA cert is optional
            }
        }
    }

    if (diag_service_) {
        result = diag_service_->initialize();
        if (result != ErrorCode::SUCCESS) {
            return result;
        }
    }

    // 初始化 TLS Credential Provider（TBOX-SEC-DSN-CR-010）
    initializeTlsCredentialProvider();

    initialized_ = true;
    return ErrorCode::SUCCESS;
}

// TBOX-SEC-DSN-CR-011: IPC Server 与 SecIpcDispatcher 已上移到 SecApplication 组合根，
// SecService 不再持有传输层。以下为停机 quiesce 与事件发布解耦接口。

void SecService::beginShutdown() {
    shutting_down_.store(true, std::memory_order_relaxed);
    SecLogAdapter::service().info(
        "sec.service.shutdown_begin",
        "SEC service entering shutdown, rejecting new security operations");
}

bool SecService::is_shutting_down() const noexcept {
    return shutting_down_.load(std::memory_order_relaxed);
}

void SecService::setEventPublisher(
    std::function<void(uint32_t event_type,
                       const std::string& payload_json)> cb) {
    event_publisher_ = std::move(cb);
}

ErrorCode SecService::generate_key_pair() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    // CR-011: 停机后拒绝新安全操作（fail-closed quiesce）
    if (is_shutting_down()) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ErrorCode prov_result = ensure_vehicle_info();
    if (prov_result != ErrorCode::SUCCESS) {
        return prov_result;
    }

    ProvisionStatus status = get_provision_status();

    // 检查密钥是否真正存在于 HSM 中
    if (status.state != ProvisionState::NONE &&
        status.state != ProvisionState::FAILED) {
        // 检查 HSM 中是否真的有密钥
        if (key_engine_ && key_engine_->device_key_exists(vin_, ecu_uid_)) {
            // 密钥确实存在，静默返回成功
            return ErrorCode::SUCCESS;
        }
        // 状态说有密钥但 HSM 中没有，继续生成
        SecLogAdapter::provisioning().warn(
            "sec.keypair.regenerate", "状态显示密钥已存在但 HSM 中缺失，重新生成");
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
        SecLogAdapter::service().error(
            "sec.keypair.generate.failed",
            "密钥对生成失败",
            {
                {"algorithm", tbox::fw::log::FieldValue::makeString("ecdsa-p256")},
                {"storage_mode", tbox::fw::log::FieldValue::makeString(config_.get_hsm_type())},
                {"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(result))}
            }
        );
        return result;
    }

    update_provision_state(ProvisionState::KEY_GENERATED);
    SecLogAdapter::service().info(
        "sec.keypair.generate.succeeded",
        "密钥对生成成功",
        {
            {"algorithm", tbox::fw::log::FieldValue::makeString("ecdsa-p256")},
            {"storage_mode", tbox::fw::log::FieldValue::makeString(config_.get_hsm_type())}
        }
    );
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::get_csr(std::vector<uint8_t>& csr_der) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ErrorCode prov_result = ensure_vehicle_info();
    if (prov_result != ErrorCode::SUCCESS) {
        return prov_result;
    }

    ProvisionStatus status = get_provision_status();
    SecLogAdapter::provisioning().debug(
        "sec.csr.get", "读取 CSR",
        {{"state", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(status.state))}});

    if (status.state == ProvisionState::NONE) {
        return ErrorCode::KEY_NOT_FOUND;
    }

    // 如果 CSR 尚未构建或 csr_der_ 为空，重新构建
    if (status.state == ProvisionState::KEY_GENERATED || csr_der_.empty()) {
        SecLogAdapter::provisioning().debug(
            "sec.csr.build", "构建 CSR",
            {{"state", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(status.state))},
             {"csr_empty", tbox::fw::log::FieldValue::makeBool(csr_der_.empty())}});
        ErrorCode result = build_and_store_csr();
        if (result != ErrorCode::SUCCESS) {
            handle_error(result, "CSR building failed");
            return result;
        }

        update_provision_state(ProvisionState::CSR_BUILT);
    }

    csr_der = csr_der_;
    SecLogAdapter::provisioning().debug(
        "sec.csr.returned", "返回 CSR",
        {{"csr_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(csr_der_.size()))}});
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::submit_csr() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    // CR-011: 停机后拒绝新安全操作（fail-closed quiesce）
    if (is_shutting_down()) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ErrorCode prov_result = ensure_vehicle_info();
    if (prov_result != ErrorCode::SUCCESS) {
        return prov_result;
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
    // CR-011: 停机后拒绝新安全操作（fail-closed quiesce）
    if (is_shutting_down()) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ErrorCode prov_result = ensure_vehicle_info();
    if (prov_result != ErrorCode::SUCCESS) {
        return prov_result;
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
        SecLogAdapter::certificate().error(
            "sec.cert.apply.not_initialized", "apply_certificate 未初始化");
        return ErrorCode::NOT_INITIALIZED;
    }
    // CR-011: 停机后拒绝新安全操作（fail-closed quiesce）
    if (is_shutting_down()) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ProvisionStatus status = get_provision_status();
    SecLogAdapter::certificate().debug(
        "sec.cert.apply.start", "开始申请证书",
        {{"state", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(status.state))}});

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
        if (store_.has_value() && store_->isReady()) {
            save_provision_status_to_store(status);
        }
    }

    // 如果有DIAG服务，通过DIAG服务执行整个流程
    if (diag_service_) {
        SecLogAdapter::certificate().debug(
            "sec.cert.apply.via_diag", "经 DIAG 服务执行证书申请");
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
        SecLogAdapter::certificate().info(
            "sec.cert.apply.generate_key", "申请证书：生成密钥对");
        ErrorCode result = generate_key_pair();
        if (result != ErrorCode::SUCCESS) {
            SecLogAdapter::certificate().error(
                "sec.cert.apply.generate_key_failed", "申请证书：生成密钥对失败",
                {{"error_code", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result))}});
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
        SecLogAdapter::certificate().info(
            "sec.cert.apply.submit_csr", "申请证书：提交 CSR");
        ErrorCode result = submit_csr();
        if (result != ErrorCode::SUCCESS) {
            SecLogAdapter::certificate().error(
                "sec.cert.apply.submit_csr_failed", "申请证书：提交 CSR 失败",
                {{"error_code", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result))}});
            return result;
        }
        status.state = ProvisionState::CSR_SUBMITTED;
    }

    // 步骤4：注入证书（这里需要外部提供证书，或者等待云端返回）
    // 注意：在实际流程中，证书可能需要从云端异步获取
    // 这里暂时返回SUCCESS，表示CSR已提交成功
    // 证书注入需要通过inject_certificate()单独调用
    SecLogAdapter::certificate().info(
        "sec.cert.apply.success", "证书申请流程完成（CSR 已提交）");
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::get_seed(uint8_t level, std::vector<uint8_t>& seed) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    // CR-011: 停机后拒绝新安全操作（fail-closed quiesce）
    if (is_shutting_down()) {
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
        SecLogAdapter::seed_key().error(
            "sec.seed.generate.failed",
            "seed 生成失败",
            {
                {"security_level", tbox::fw::log::FieldValue::makeString(std::to_string(level))},
                {"error_code", tbox::fw::log::FieldValue::makeString("SEC-1007")}
            }
        );
        return ErrorCode::SEED_GENERATION_FAILED;
    }

    // Store seed state with security level
    current_seed_.seed = seed;
    current_seed_.security_level = level;
    current_seed_.generated = true;
    current_seed_.consumed = false;
    current_seed_.generated_at = std::chrono::steady_clock::now();

    SecLogAdapter::seed_key().debug(
        "sec.seed.generate.succeeded",
        "seed 生成成功",
        {
            {"security_level", tbox::fw::log::FieldValue::makeString(std::to_string(level))}
        }
    );

    return ErrorCode::SUCCESS;
}

ErrorCode SecService::verify_key(uint8_t level, const std::vector<uint8_t>& key) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    // CR-011: 停机后拒绝新安全操作（fail-closed quiesce）
    if (is_shutting_down()) {
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
        SecLogAdapter::seed_key().warn(
            "sec.seed_key.verify.seed_invalid", "verify_key 失败：seed 无效或已消费");
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

    // CR §8: seed/key 为敏感材料，禁止输出明文。仅记录长度用于诊断。
    SecLogAdapter::seed_key().debug(
        "sec.seed_key.verify.debug",
        "verify_key 校验",
        {{"seed_len", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(current_seed_.seed.size()))},
         {"expected_len", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(expected_key.size()))},
         {"received_len", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(key.size()))}});

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
        SecLogAdapter::seed_key().debug(
            "sec.seed_key.verify.succeeded",
            "key 校验通过",
            {
                {"security_level", tbox::fw::log::FieldValue::makeString(std::to_string(level))}
            }
        );
        return ErrorCode::SUCCESS;
    } else {
        // Key verification failed
        increment_failed_attempts();
        invalidate_seed();
        SecLogAdapter::seed_key().warn(
            "sec.seed_key.verify.failed",
            "key 校验失败",
            {
                {"security_level", tbox::fw::log::FieldValue::makeString(std::to_string(level))},
                {"error_code", tbox::fw::log::FieldValue::makeString("SEC-1008")}
            }
        );
        return ErrorCode::KEY_VERIFICATION_FAILED;
    }
}

ProvisionStatus SecService::get_provision_status() const {
    // Try store first
    if (store_.has_value() && store_->isReady()) {
        try {
            auto status = load_provision_status_from_store();
            if (status.state != ProvisionState::NONE || !status.vin.empty()) {
                return status;
            }
            // If status is default, check if key exists
            if (store_->has("provision_state")) {
                return status;
            }
        } catch (const std::exception& e) {
            // Fall through to default status
        }
    }

    // Return default status
    ProvisionStatus status;
    status.state = ProvisionState::NONE;
    return status;
}

DeviceProvisionState SecService::get_device_binding_state() const {
    if (!prov_service_) {
        return DeviceProvisionState::UNKNOWN;
    }
    DeviceProvisionState state = DeviceProvisionState::UNKNOWN;
    // 失败不抛出，返回 UNKNOWN 即可（PROV 不可用时不阻断）。
    prov_service_->get_provision_state(state);
    return state;
}

ErrorCode SecService::reset_provision_status() {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    if (store_.has_value() && store_->isReady()) {
        try {
            store_->remove("provision_state");
        } catch (const hwyz::store::StoreException& e) {
            SecLogAdapter::provisioning().error(
                "sec.provision.reset_store_failed", "重置 store 中 provision 状态失败",
                {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        }
    }

    return ErrorCode::SUCCESS;
}

std::string SecService::get_device_info() const {
    std::stringstream ss;
    ss << "VIN: " << (vin_.empty() ? "(not configured)" : vin_) << "\n";
    ss << "ECU UID: " << (ecu_uid_.empty() ? "(not configured)" : ecu_uid_) << "\n";
    ss << "HSM Type: " << config_.get_hsm_type() << "\n";
    ss << "Initialized: " << (initialized_ ? "Yes" : "No") << "\n";
    ss << "DIAG Service: " << (diag_service_ ? (diag_service_->is_connected() ? "Connected" : "Disconnected") : "Not available") << "\n";
    ss << "PROV Service: " << (prov_service_ ? (prov_service_->is_connected() ? "Connected" : "Disconnected") : "Not available") << "\n";

    if (initialized_) {
        ProvisionStatus status = get_provision_status();
        ss << "Binding State (PROV): "
           << device_provision_state_to_string(get_device_binding_state()) << "\n";
        ss << "Cert Provision State: " << provision_state_to_string(status.state) << "\n";
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
                SecLogAdapter::service().error(
                    "sec.hsm.soft_file_production_denied", "量产环境禁止使用 soft_file 密钥模式");
                return ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED;
            }
            SecLogAdapter::service().warn(
                "sec.hsm.soft_file_mode", "以 software file 模式初始化（仅测试）");
        }

        // 根据密钥生成模式选择 HSM 类型
        HsmFactory::HsmType hsm_type;
        std::string config_path;
        std::string enc_key_path;  // soft_file 模式下的 KEK(主加密密钥)文件路径

        if (config_.get_key_provisioning_mode() == KEY_PROVISIONING_MODE_SOFT_FILE) {
            // 软件落盘模式
            hsm_type = HsmFactory::HsmType::SOFT_FILE;
            config_path = config_.get_soft_key_path();
            std::string store_root = config_.get_store_root();
            if (!store_root.empty()) {
                config_path = store_root;
            }
            // KEK 路径：优先取 soft_key.encryption_key_path(完整文件路径)，
            // 为空则默认 {store_root|默认目录}/<默认KEK文件名>
            enc_key_path = config_.get_soft_key_encryption_key_path();
            if (enc_key_path.empty()) {
                std::string base = store_root.empty()
                    ? std::string(DEFAULT_SOFT_KEY_PATH) : store_root;
                enc_key_path = base + "/" + DEFAULT_SOFT_KEK_FILENAME;
            }
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

        auto hsm = HsmFactory::create(hsm_type, config_path, config_.get_store_root(), enc_key_path);
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

ErrorCode SecService::load_provision_state_from_store() {
    if (!store_.has_value() || !store_->isReady()) {
        return ErrorCode::SUCCESS;
    }
    try {
        auto status = load_provision_status_from_store();
        SecLogAdapter::provisioning().info(
            "sec.provision.state_loaded", "从 store 加载 provision 状态",
            {{"state", tbox::fw::log::FieldValue::makeString(provision_state_to_string(status.state))}});
        return ErrorCode::SUCCESS;
    } catch (const std::exception& e) {
        SecLogAdapter::provisioning().error(
            "sec.provision.state_load_failed", "从 store 加载 provision 状态失败",
            {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        return ErrorCode::STORAGE_READ_FAILED;
    }
}

ErrorCode SecService::ensure_vehicle_info() {
    if (!vin_.empty() && !ecu_uid_.empty()) {
        return ErrorCode::SUCCESS;
    }

    if (!prov_service_) {
        SecLogAdapter::provisioning().error(
            "sec.prov.not_configured", "无法获取车辆信息：PROV 服务未配置");
        return ErrorCode::PROV_NOT_CONFIGURED;
    }

    try {
        VehicleInfo info;
        ErrorCode result = prov_service_->get_vehicle_info(info);
        if (result != ErrorCode::SUCCESS) {
            return result;
        }

        if (info.vin.empty() || info.ecu_uid.empty()) {
            SecLogAdapter::provisioning().warn(
                "sec.prov.vehicle_info_not_ready", "PROV 中 VIN/ECU_UID 尚未配置，无法继续 provision 操作");
            return ErrorCode::PROV_NOT_CONFIGURED;
        }

        vin_ = info.vin;
        ecu_uid_ = info.ecu_uid;
        SecLogAdapter::provisioning().info(
            "sec.prov.vehicle_info_fetched", "已获取车辆信息",
            {{"vin", tbox::fw::log::FieldValue::makeString(vin_)},
             {"ecu_uid", tbox::fw::log::FieldValue::makeString(ecu_uid_)}});
    } catch (const std::exception& e) {
        SecLogAdapter::provisioning().error(
            "sec.prov.vehicle_info_exception", "获取车辆信息异常",
            {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        return ErrorCode::PROV_NOT_CONFIGURED;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SecService::generate_and_store_key_pair() {
    KeyPair key_pair;
    SecLogAdapter::provisioning().info(
        "sec.keypair.generate_start", "开始生成密钥对",
        {{"ecu_uid", tbox::fw::log::FieldValue::makeString(ecu_uid_)}});

    auto err = key_engine_->generate_device_key(vin_, ecu_uid_, key_pair);
    if (err != ErrorCode::SUCCESS) {
        return err;
    }

    // 记录存储模式（key_id 输出不可逆摘要见 CR §6，此处为内部标识，与现有事件一致）
    if (key_pair.storage_mode == KeyStorageMode::SOFT_FILE) {
        SecLogAdapter::provisioning().info(
            "sec.keypair.generated_soft", "密钥已生成（software file 模式，仅测试）",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_pair.key_id)}});
    } else {
        SecLogAdapter::provisioning().info(
            "sec.keypair.generated_hsm", "密钥已生成（HSM 模式）",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_pair.key_id)}});
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SecService::export_private_key(std::vector<uint8_t>& private_key) {
    if (!initialized_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    ErrorCode prov_result = ensure_vehicle_info();
    if (prov_result != ErrorCode::SUCCESS) {
        return prov_result;
    }

    if (!key_engine_ || !key_engine_->device_key_exists(vin_, ecu_uid_)) {
        return ErrorCode::KEY_NOT_FOUND;
    }

    return key_engine_->export_device_private_key(vin_, ecu_uid_, private_key);
}

ErrorCode SecService::build_and_store_csr() {
    if (!csr_builder_) {
        csr_builder_ = std::make_unique<CsrBuilder>(key_engine_.get());
    }

    CsrConfig csr_config;
    csr_config.hsm_uid = ecu_uid_;    // HSM 身份用于 CSR CN
    csr_config.key_id = ecu_uid_;     // key_id 使用 ecu_uid
    csr_config.algorithm = "ecdsa-p256";

    SecLogAdapter::provisioning().info(
        "sec.csr.build_start", "构建 CSR",
        {{"ecu_uid", tbox::fw::log::FieldValue::makeString(ecu_uid_)}});
    ErrorCode result = csr_builder_->build_csr(vin_, csr_config, csr_der_);
    SecLogAdapter::provisioning().debug(
        "sec.csr.build_result", "CSR 构建结果",
        {{"error_code", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(result))},
         {"csr_size", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(csr_der_.size()))}});
    
    if (result == ErrorCode::SUCCESS) {
        SecLogAdapter::service().info(
            "sec.csr.build.succeeded",
            "CSR 构造成功",
            {
                {"subject_profile", tbox::fw::log::FieldValue::makeString("device")},
                {"key_id_hash", tbox::fw::log::FieldValue::makeString(ecu_uid_)}
            }
        );
    } else {
        SecLogAdapter::service().error(
            "sec.csr.build.failed",
            "CSR 构造失败",
            {
                {"subject_profile", tbox::fw::log::FieldValue::makeString("device")},
                {"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(result))}
            }
        );
    }
    
    return result;
}

ErrorCode SecService::submit_csr_to_cloud() {
    CertificateRequest request;
    request.ecu_uid = ecu_uid_;       // HSM 身份用于云端签发
    request.csr_der = csr_der_;       // 使用存储的 CSR

    CertificateResponse response;
    return cloud_client_->submit_csr(request, response);
}

ErrorCode SecService::validate_and_store_certificate(const std::vector<uint8_t>& cert_der) {
    if (!cert_validator_) {
        cert_validator_ = std::make_unique<CertValidator>(key_engine_.get());
    }

    bool valid = false;
    ErrorCode result = cert_validator_->validate_certificate(vin_, ecu_uid_, cert_der, valid);

    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    if (!valid) {
        return ErrorCode::CERT_KEY_MISMATCH;
    }

    // Store certificate to file system
    result = store_certificate_to_file(cert_der);
    if (result != ErrorCode::SUCCESS) {
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书安装失败",
            {
                {"failure_stage", tbox::fw::log::FieldValue::makeString("storage")},
                {"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(result))}
            }
        );
        return result;
    }

    SecLogAdapter::certificate().info(
        "sec.certificate.install.succeeded",
        "证书校验并安装成功",
        {
            {"cert_serial_hash", tbox::fw::log::FieldValue::makeString("cert_hash")},
            {"issuer_id", tbox::fw::log::FieldValue::makeString("cloud")}
        }
    );
    return ErrorCode::SUCCESS;
}

ErrorCode SecService::store_certificate_to_file(const std::vector<uint8_t>& cert_der) {
    // Try store first
    if (store_.has_value() && store_->isReady()) {
        try {
            std::string cert_key = "device_cert:" + vin_ + ":" + ecu_uid_;
            std::string encoded = base64_encode(cert_der);
            store_->save(cert_key, encoded);
            SecLogAdapter::certificate().info(
                "sec.certificate.stored_in_store", "证书已存入 store",
                {{"cert_key", tbox::fw::log::FieldValue::makeString(cert_key)}});
            return ErrorCode::SUCCESS;
        } catch (const std::exception& e) {
            SecLogAdapter::certificate().error(
                "sec.certificate.store_save_failed", "存入 store 失败，回退到文件存储",
                {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
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
        SecLogAdapter::certificate().error(
            "sec.certificate.mkdir_failed", "创建证书目录失败",
            {{"cert_dir", tbox::fw::log::FieldValue::makeString(cert_dir)}});
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    // Generate certificate filename: {vin}_{ecu_uid}.der
    std::string cert_path = cert_dir + "/" + vin_ + "_" + ecu_uid_ + ".der";

    // Write certificate to file
    std::ofstream cert_file(cert_path, std::ios::binary);
    if (!cert_file.is_open()) {
        SecLogAdapter::certificate().error(
            "sec.certificate.file_open_failed", "无法打开证书文件写入",
            {{"cert_path", tbox::fw::log::FieldValue::makeString(cert_path)}});
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    cert_file.write(reinterpret_cast<const char*>(cert_der.data()), cert_der.size());
    cert_file.close();

    if (!cert_file.good()) {
        SecLogAdapter::certificate().error(
            "sec.certificate.file_write_failed", "证书文件写入失败",
            {{"cert_path", tbox::fw::log::FieldValue::makeString(cert_path)}});
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    SecLogAdapter::certificate().info(
        "sec.certificate.stored_in_file", "证书已存入文件",
        {{"cert_path", tbox::fw::log::FieldValue::makeString(cert_path)}});
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
    if (store_.has_value() && store_->isReady()) {
        save_provision_status_to_store(status);
        return;
    }

    SecLogAdapter::provisioning().error(
        "sec.provision.update_state_no_storage", "更新 provision 状态失败：无可用存储");
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

bool SecService::save_state() {
    bool success = false;

    if (store_.has_value() && store_->isReady()) {
        try {
            ProvisionStatus status = get_provision_status();
            save_provision_status_to_store(status);
            success = true;
        } catch (const std::exception& e) {
            SecLogAdapter::provisioning().error(
                "sec.provision.save_state_failed", "保存状态到 store 失败",
                {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        }
    }

    return success;
}

ErrorCode SecService::store_certificate(const std::vector<uint8_t>& cert_der) {
    return store_certificate_to_file(cert_der);
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
                    SecLogAdapter::certificate().debug(
                        "sec.ca.config_path_found", "从配置发现 CA 证书路径",
                        {{"config_path", tbox::fw::log::FieldValue::makeString(config_path)},
                         {"ca_cert_path", tbox::fw::log::FieldValue::makeString(ca_cert_path)}});
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

void SecService::save_provision_status_to_store(const ProvisionStatus& status) {
    if (!store_.has_value() || !store_->isReady()) {
        return;
    }
    try {
        std::string json_str = status.to_json().dump();
        store_->save("provision_state", json_str);
    } catch (const std::exception& e) {
        SecLogAdapter::provisioning().error(
            "sec.provision.status_save_failed", "保存 provision 状态到 store 失败",
            {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
    }
}

ProvisionStatus SecService::load_provision_status_from_store() const {
    if (!store_.has_value() || !store_->isReady()) {
        ProvisionStatus status;
        status.state = ProvisionState::NONE;
        return status;
    }
    try {
        std::string json_str = store_->load<std::string>("provision_state");
        nlohmann::json j = nlohmann::json::parse(json_str);
        return ProvisionStatus::from_json(j);
    } catch (const hwyz::store::StoreException& e) {
        if (e.getError().code != hwyz::store::StoreError::kKeyNotFound) {
            SecLogAdapter::provisioning().error(
                "sec.provision.status_load_failed", "从 store 加载 provision 状态失败",
                {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        }
        ProvisionStatus status;
        status.state = ProvisionState::NONE;
        return status;
    } catch (const std::exception& e) {
        SecLogAdapter::provisioning().error(
            "sec.provision.status_parse_failed", "解析 store 中 provision 状态失败",
            {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        ProvisionStatus status;
        status.state = ProvisionState::NONE;
        return status;
    }
}

std::string SecService::base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);

    BUF_MEM* buffer_ptr;
    BIO_get_mem_ptr(bio, &buffer_ptr);

    std::string result(buffer_ptr->data, buffer_ptr->length);
    BIO_free_all(bio);

    return result;
}

std::string provision_state_to_string(ProvisionState state) {
    switch (state) {
        case ProvisionState::NONE: return "NONE";
        case ProvisionState::KEY_GENERATED: return "KEY_GENERATED";
        case ProvisionState::CSR_BUILT: return "CSR_BUILT";
        case ProvisionState::CSR_SUBMITTED: return "CSR_SUBMITTED";
        case ProvisionState::CERT_INSTALLED: return "CERT_INSTALLED";
        case ProvisionState::FAILED: return "FAILED";
        default: return "UNKNOWN";
    }
}

ProvisionState string_to_provision_state(const std::string& str) {
    if (str == "NONE") return ProvisionState::NONE;
    if (str == "KEY_GENERATED") return ProvisionState::KEY_GENERATED;
    if (str == "CSR_BUILT") return ProvisionState::CSR_BUILT;
    if (str == "CSR_SUBMITTED") return ProvisionState::CSR_SUBMITTED;
    if (str == "CERT_INSTALLED") return ProvisionState::CERT_INSTALLED;
    if (str == "FAILED") return ProvisionState::FAILED;
    return ProvisionState::NONE;
}

nlohmann::json ProvisionStatus::to_json() const {
    nlohmann::json j;
    j["vin"] = vin;
    j["ecu_uid"] = ecu_uid;
    j["state"] = provision_state_to_string(state);
    j["last_error"] = last_error;
    j["retry_count"] = retry_count;

    auto time_t = std::chrono::system_clock::to_time_t(last_updated);
    std::tm tm_buf{};
    localtime_r(&time_t, &tm_buf);
    std::stringstream ss;
    ss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S");
    j["last_updated"] = ss.str();

    return j;
}

ProvisionStatus ProvisionStatus::from_json(const nlohmann::json& j) {
    ProvisionStatus status;
    status.vin = j["vin"].get<std::string>();
    status.ecu_uid = j["ecu_uid"].get<std::string>();
    status.state = string_to_provision_state(j["state"].get<std::string>());
    status.last_error = j["last_error"].get<std::string>();
    status.retry_count = j["retry_count"].get<int>();

    std::string time_str = j["last_updated"].get<std::string>();
    std::tm tm = {};
    std::istringstream ss(time_str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
    status.last_updated = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    return status;
}

// ============================================================
// TLS Credential Provider（TBOX-SEC-DSN-CR-010）
// ============================================================

void SecService::loadTlsProfileConfig() {
    if (!config_.config_snapshot) {
        return;
    }
    auto snap = config_.config_snapshot;
    // 遍历 sec.tls.profiles.* （本期主要 mqtt）
    // 由于 ImmutableConfigView 接口限制，这里显式读取 mqtt profile
    std::string base = "sec.tls.profiles.mqtt";
    if (!snap->has(base)) {
        return;
    }
    SecServiceConfig::TlsProfileConf pc;
    pc.enabled = true;
    pc.profile_name = "mqtt";
    pc.credential_id = snap->getString(base + ".credential_id", "mqtt-primary");
    pc.key_usage = snap->getString(base + ".key_usage", "clientAuth");
    pc.peer_service = snap->getString(base + ".peer_service", "tbox-mqtt.service");
    pc.notify_on_change = snap->getBool(base + ".notify_on_change", true);
    // 材料来源已从配置文件路径迁移到 SEC 受控存储固定 key（root_ca / device_cert_chain），
    // 不再从 profile 读取 root_ca_path / client_cert_chain_path。
    pc.ref_ttl_sec = snap->getInt(base + ".ref_ttl_sec", 3600);
    // allowed_signature_algorithms
    auto algs = snap->getStringList(base + ".allowed_signature_algorithms");
    for (auto& item : algs) {
        // 去除空白
        auto p = item.find_first_not_of(" \t");
        if (p != std::string::npos) item.erase(0, p);
        auto q = item.find_last_not_of(" \t");
        if (q != std::string::npos) item.erase(q + 1);
        if (!item.empty()) pc.allowed_signature_algorithms.push_back(item);
    }
    config_.tls_profiles["mqtt"] = pc;
}

void SecService::initializeTlsCredentialProvider() {
    loadTlsProfileConfig();
    if (config_.tls_profiles.empty()) {
        // 未配置 TLS profile，跳过（不阻断 SEC 启动）
        return;
    }
    if (!key_engine_ || !key_engine_->hsm()) {
        SecLogAdapter::tls_credential().warn(
            "sec.tls.provider.hsm_unavailable", "TLS provider：HSM 不可用，跳过");
        return;
    }

    // 加载 TLS 材料前先解析 VIN/ECU_UID（否则 key_id 解析为 "+"，材料会被判定为 NOT_READY）。
    // best-effort：PROV 不可用时不阻断 SEC 启动，后续 getTlsCredential 会按需重载（见 ensure_tls_material_ready）。
    if (vin_.empty() || ecu_uid_.empty()) {
        ErrorCode vinfo = ensure_vehicle_info();
        if (vinfo != ErrorCode::SUCCESS) {
            SecLogAdapter::tls_credential().warn(
                "sec.tls.provider.vehicle_info_unavailable",
                "TLS provider：车辆信息不可用，TLS 材料保持 NOT_READY 直至可解析 VIN/ECU_UID",
                {{"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(vinfo))}});
        }
    }

    // 设备 key_id 解析器：vin + "+" + ecu_uid（与 KeyEngine::make_key_id 一致）
    DeviceKeyIdResolver key_resolver = [this]() -> std::string {
        return vin_ + "+" + ecu_uid_;
    };

    // TLS 材料读取器：从 SEC 受控存储（framework-store，服务名 "sec"）按 key 读取 PEM 文本。
    // root_ca = 共享信任根；device_cert_chain = 设备客户端证书链。store 不可用或缺 key 时返回空串。
    TlsMaterialResolver material_resolver = [this](const std::string& key) -> std::string {
        if (!store_.has_value() || !store_->isReady()) {
            return "";
        }
        try {
            if (!store_->has(key)) return "";
            return store_->load<std::string>(key);
        } catch (const std::exception& e) {
            SecLogAdapter::tls_credential().error(
                "sec.tls.material_load_failed", "TLS 材料加载失败",
                {{"key", tbox::fw::log::FieldValue::makeString(key)},
                 {"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
            return "";
        }
    };

    // 事件通知回调：经 SecApplication 注入的 event_publisher_ 推送 sec.tls_credential.changed
    // （CR-011：IPC Server 所有权上移到 SecApplication，此处不再直接持有 fw_ipc_server_）。
    // event_publisher_ 在 SecService::initialize 之后由 SecApplication 设置；未设置时事件静默丢弃。
    TlsCredentialNotifyCallback notify = [this](const std::string& profile,
                                                const TlsCredentialChangedEvent& ev) {
        if (!event_publisher_) {
            return;
        }
        nlohmann::json payload;
        payload["profile"] = ev.profile;
        payload["credential_id"] = ev.credential_id;
        payload["version"] = ev.version;
        payload["status"] = tls_credential_status_to_string(ev.status);
        payload["reason_code"] = ev.reason_code;
        event_publisher_(
            static_cast<uint32_t>(ipc::EventId::TLS_CREDENTIAL_CHANGED),
            payload.dump());
        SecLogAdapter::tls_credential().info(
            "sec.tls_credential.changed",
            "推送凭据变更事件",
            {tbox::fw::log::Field("profile", tbox::fw::log::FieldValue::makeString(profile)),
             tbox::fw::log::Field("version", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(ev.version))),
             tbox::fw::log::Field("status", tbox::fw::log::FieldValue::makeString(tls_credential_status_to_string(ev.status)))}
        );
    };

    tls_provider_ = std::make_unique<TlsCredentialProvider>(
        key_engine_->hsm(), std::move(key_resolver),
        std::move(material_resolver), std::move(notify));

    // 配置并加载各 profile 材料
    for (auto& [name, pc] : config_.tls_profiles) {
        if (!pc.enabled) continue;
        TlsProfileConfig tpc;
        tpc.profile_name = name;
        tpc.credential_id = pc.credential_id;
        tpc.key_usage = pc.key_usage;
        for (auto& a : pc.allowed_signature_algorithms) {
            tpc.allowed_signature_algorithms.push_back(string_to_signature_algorithm(a));
        }
        tpc.peer_service = pc.peer_service;
        tpc.notify_on_change = pc.notify_on_change;
        // root_ca_key / client_cert_chain_key 使用 TlsProfileConfig 默认值
        // （root_ca / device_cert_chain），材料由 material_resolver 从 SEC 存储读取。
        tpc.ref_ttl_sec = pc.ref_ttl_sec;
        tls_provider_->configureProfile(tpc);

        // 尝试加载材料；失败不阻断 SEC 启动（状态保持 NOT_READY，MQTT 查询时返回 SEC-1010）
        ErrorCode rc = tls_provider_->loadMaterials(name);
        if (rc != ErrorCode::SUCCESS) {
            SecLogAdapter::tls_credential().warn(
                "sec.tls.profile_not_ready", "TLS profile 材料未就绪",
                {{"profile", tbox::fw::log::FieldValue::makeString(name)},
                 {"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(rc))}});
        }
    }
}

TlsCredentialProvider* SecService::tls_credential_provider() {
    return tls_provider_.get();
}

ErrorCode SecService::ensure_tls_material_ready(const std::string& profile) {
    if (!tls_provider_) {
        return ErrorCode::NOT_INITIALIZED;
    }
    // 若已就绪，直接返回，避免重复触发 PROV/材料校验
    TlsCredentialState state;
    if (tls_provider_->getTlsCredentialState(profile, state) == ErrorCode::SUCCESS &&
        state.status == TlsCredentialStatus::READY) {
        return ErrorCode::SUCCESS;
    }
    // best-effort 解析 VIN/ECU_UID（key_id = vin + "+" + ecu_uid）
    if (vin_.empty() || ecu_uid_.empty()) {
        ensure_vehicle_info();
    }
    // 仍无法解析则不重载，保持既有 NOT_READY 状态
    if (vin_.empty() || ecu_uid_.empty()) {
        return ErrorCode::TLS_CREDENTIAL_NOT_READY;
    }
    return tls_provider_->loadMaterials(profile);
}

} // namespace sec
} // namespace tbox
