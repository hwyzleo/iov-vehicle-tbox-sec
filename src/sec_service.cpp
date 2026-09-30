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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#ifdef USE_YAML_CPP
#include <yaml-cpp/yaml.h>
#endif

#include "tls_credential_provider.h"
#include "certificate_store.h"
#include "peer_credential.h"
#include "ipc_protocol.h"

namespace tbox {
namespace sec {

namespace {

// 将 32 个 hex 字符解码为 16 字节（Seed-Key AES-128 共享密钥）。
// 返回 false 表示长度非法或包含非 hex 字符。
bool decodeHexSecret(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() != 32) return false;
    out.clear();
    out.reserve(16);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

} // namespace

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

void SecService::set_trusted_time_provider(
    std::shared_ptr<TrustedTimeProvider> provider) {
    trusted_time_provider_ = std::move(provider);
}

TrustedTimeProvider* SecService::getTrustedTimeProvider() {
    if (!trusted_time_provider_) {
        // TBOX-SEC-DSN-CR-017：未注入时 fail-closed 默认（无来源 Composite，
        // 永不 TRUSTED），绝不回退墙钟/进程启动时间/文件时间。
        trusted_time_provider_ =
            std::make_shared<CompositeTrustedTimeProvider>(nullptr, nullptr);
    }
    return trusted_time_provider_.get();
}
ErrorCode SecService::initialize() {
    // Validate required config
    if (config_.get_hsm_type().empty() &&
        config_.get_key_provisioning_mode() != KEY_PROVISIONING_MODE_SOFT_FILE) {
        SecLogAdapter::service().error(
            "sec.config.hsm_type_required", "hsm.type 未配置");
        return ErrorCode::CONFIG_ERROR;
    }

    ErrorCode result = initialize_hsm();
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

    // Load CA / Broker trust root via CA Material Loader（TBOX-SEC-DSN-CR-014 / CR-016 §4.3）
    // root_ca 的唯一量产来源为 BUILD 安装的信任根文件（sec.tls.profiles.mqtt.root_ca_source，
    // 默认 /usr/share/tbox/sec/trust/mqtt-root-ca.pem）；CA Material Loader 校验后经
    // framework-store 原子导入 key=root_ca，仅供 TlsCredentialProvider 作为 trust anchor。
    // CR-016：CertValidator 不再持有/接收 CA，root_ca 不进入注入 sanity check 路径；
    // 不存在可覆盖 trust anchor 的外部写入口（SecService/IPC/CLI/client 均已移除）。
    if (store_.has_value() && store_->isReady()) {
        initializeCaMaterialLoader();
        if (store_->has("root_ca")) {
            SecLogAdapter::certificate().info(
                "sec.ca.loaded_from_store", "CA 信任根已从 store 导入 (key=root_ca, 供 Provider)");
        }
    } else {
        SecLogAdapter::certificate().warn(
            "sec.ca.store_unavailable", "store 不可用，跳过 CA Material Loader（TLS 保持 NOT_READY）");
    }

    // TBOX-SEC-DSN-CR-014: 初始化跨键原子证书存储（generation + manifest + CURRENT 指针）
    // 供证书注入原子提交 device_cert_chain/DeviceCert/version/ProvisionState 使用。
    if (store_.has_value() && store_->isReady()) {
        std::string cert_root = config_.get_store_root() + "/sec/certstore";
        cert_store_ = std::make_unique<CertificateStore>(cert_root);
        if (!cert_store_->openAndRecover()) {
            SecLogAdapter::certificate().error(
                "sec.certstore.recover_failed",
                "CertificateStore 启动恢复失败，证书/TLS 材料 fail-closed");
            cert_store_.reset();
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
        if (key_engine_ && key_engine_->device_key_exists(ecu_uid_, ecu_uid_)) {
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

    // 设计决策（DSN §2/§4）：产线证书申请走 MES → OAPI → PKI 中继，TBOX 不直连云端。
    // SEC 仅经 DIAG 提交 CSR（DiagRequestType::SUBMIT_CSR）；无 DIAG 时直接失败，
    // 不允许降级到 TBOX 直连 HTTPS 签发（旧 CloudClient 直连路径已删除）。
    SecLogAdapter::certificate().error(
        "sec.cert.submit_no_diag", "提交 CSR 需要 DIAG 诊断服务（产线 MES 中继通道）");
    return ErrorCode::NOT_IMPLEMENTED;
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

    // 同时清空内存中已构建的 CSR，避免重置后重建时旧 CSR 被追加拼接（畸形 ASN.1）
    csr_der_.clear();

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
        // HSM 后端只分两类（无内存 mock）：
        //   软件 HSM（SoftFileHsm，落盘持久化）—— 无硬件 HSM 的车机（如 Orin）使用；
        //   硬件 HSM（pkcs11 / trustzone）—— 真实安全设备。
        // 软件 HSM 由 key_provisioning.mode=soft_file 或 hsm.type=software 任一选择。
        const std::string prov_mode = config_.get_key_provisioning_mode();
        const std::string hsm_type_str = config_.get_hsm_type();
        const bool use_software_hsm =
            (prov_mode == KEY_PROVISIONING_MODE_SOFT_FILE) || (hsm_type_str == "software");

        HsmFactory::HsmType hsm_type;
        std::string config_path;
        std::string enc_key_path;  // 软件 HSM 的 KEK(主加密密钥)文件路径

        if (use_software_hsm) {
            // 量产（真实车机）必须使用硬件 HSM，软件 HSM 在量产 fail-closed 拒绝。
            if (config_.get_is_production()) {
                SecLogAdapter::service().error(
                    "sec.hsm.software_production_denied",
                    "量产环境禁止使用软件 HSM，请配置硬件 HSM（hsm.type=pkcs11/trustzone）");
                return ErrorCode::SOFT_KEY_MODE_NOT_ALLOWED;
            }
            SecLogAdapter::service().info(
                "sec.hsm.software_mode", "以软件 HSM（SoftFileHsm，落盘持久化）模式初始化");

            hsm_type = HsmFactory::HsmType::SOFT_FILE;
            const std::string store_root = config_.get_store_root();
            config_path = store_root.empty() ? config_.get_soft_key_path() : store_root;
            // KEK 路径：优先取 soft_key.encryption_key_path(完整文件路径)，
            // 为空则默认 {store_root|默认目录}/<默认KEK文件名>
            enc_key_path = config_.get_soft_key_encryption_key_path();
            if (enc_key_path.empty()) {
                const std::string base = store_root.empty()
                    ? std::string(DEFAULT_SOFT_KEY_PATH) : store_root;
                enc_key_path = base + "/" + DEFAULT_SOFT_KEK_FILENAME;
            }
        } else {
            // 硬件 HSM
            if (hsm_type_str == "pkcs11") {
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

    // key 身份维度使用 hsm_uid(ecu_uid)，不绑定 VIN（DSN §1.1 / §3）
    auto err = key_engine_->generate_device_key(ecu_uid_, ecu_uid_, key_pair);
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

    if (!key_engine_ || !key_engine_->device_key_exists(ecu_uid_, ecu_uid_)) {
        return ErrorCode::KEY_NOT_FOUND;
    }

    return key_engine_->export_device_private_key(ecu_uid_, ecu_uid_, private_key);
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

ErrorCode SecService::validate_and_store_certificate(const std::vector<uint8_t>& payload) {
    // TBOX-SEC-DSN-CR-018：严格解析完整输入（PEM 链 / legacy 单 DER），
    // 解析发生在 CertValidator 之前；CertValidator 只接收 leaf。
    ParseResult parsed = chain_parser_.parse(payload, chain_limits_);
    if (!parsed.ok) {
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书注入失败：输入解析/链形状非法",
            {{"failure_stage", tbox::fw::log::FieldValue::makeString(
                 certificate_parse_stage_to_string(parsed.stage))},
             {"error_code", tbox::fw::log::FieldValue::makeString("SEC-1004")}});
        return ErrorCode::CERT_VALIDATION_FAILED;
    }

    // Root 入链安装策略检查：禁止把 Loader 导入的信任根写入设备证书链（CR-018 §3.3）。
    // parser 不访问 store，故在此比对链内证书 digest 与 store root_ca 的证书 digest。
    ErrorCode root_rc = rejectRootInjectedIntoChain(parsed.chain);
    if (root_rc != ErrorCode::SUCCESS) {
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书注入失败：信任根证书禁止入链",
            {{"failure_stage", tbox::fw::log::FieldValue::makeString("root_in_chain")}});
        return root_rc;
    }

    // leaf sanity check（CR-018 §4）：CertValidator 只接收 leaf，
    // 不验证 CA 签名、不构建路径、不要求 root_ca 已配置。
    if (!cert_validator_) {
        cert_validator_ = std::make_unique<CertValidator>(key_engine_.get(),
                                                          *getTrustedTimeProvider());
    }

    bool valid = false;
    ErrorCode result = cert_validator_->validate_certificate(
        vin_, ecu_uid_, parsed.chain.leaf.get(), valid);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    if (!valid) {
        return ErrorCode::CERT_KEY_MISMATCH;
    }

    // canonical PEM：以解析后的 X509 重新序列化 leaf + 全部 intermediate（CR-018 §5），
    // 不复制输入 PEM 的空白/换行/header 文本；Root 永不输出。
    std::string pem;
    if (!chain_canonicalizer_.toPem(parsed.chain, pem)) {
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书安装失败：canonical PEM 序列化失败",
            {{"failure_stage", tbox::fw::log::FieldValue::makeString("format")}});
        return ErrorCode::CERT_INSTALL_FAILED;
    }

    // TBOX-SEC-DSN-CR-014: 幂等判重 + 原子 commit + reload mqtt profile
    // （commit 成功才返回成功；失败保持旧材料/旧档案/原 ProvisionState）
    result = publishDeviceCertChain(pem);
    if (result != ErrorCode::SUCCESS) {
        SecLogAdapter::certificate().error(
            "sec.certificate.install.failed",
            "证书安装失败：材料原子发布失败",
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

// ============================================================
// TBOX-SEC-DSN-CR-014: 证书材料原子发布（Certificate Material Publisher）
// ============================================================

ErrorCode SecService::publishDeviceCertChain(const std::string& canonical_pem) {
    if (!cert_store_) {
        SecLogAdapter::certificate().error(
            "sec.certificate.commit.store_unavailable", "CertificateStore 不可用，拒绝发布证书材料");
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    // 幂等判重：相同 canonical PEM digest 不提交、不递增版本、不发布无变化事件
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(canonical_pem.data()),
           canonical_pem.size(), hash);
    static const char* kHex = "0123456789abcdef";
    std::string new_digest;
    new_digest.reserve(SHA256_DIGEST_LENGTH * 2);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        new_digest += kHex[hash[i] >> 4];
        new_digest += kHex[hash[i] & 0x0F];
    }
    std::string cur_digest = cert_store_->currentChainDigest();
    if (!cur_digest.empty() && cur_digest == new_digest) {
        SecLogAdapter::certificate().info(
            "sec.certificate.install.idempotent",
            "相同证书重复注入，幂等跳过（不递增版本）");
        return ErrorCode::SUCCESS;
    }

    // 版本单调递增（持久化于 generation）
    auto snap = cert_store_->currentSnapshot();
    uint64_t version = snap ? snap->version + 1 : 1;

    // DeviceCert 档案快照（非权威密钥来源；当前有效链投影到 device_cert_chain）
    nlohmann::json dc;
    dc["cert_id"] = vin_ + ":" + ecu_uid_;
    dc["bound_vin"] = vin_;
    dc["bound_ecu_uid"] = ecu_uid_;
    dc["status"] = "ACTIVE";
    dc["version"] = version;
    dc["cert_sha256"] = new_digest;

    CertificateCommit commit;
    commit.device_cert_chain_pem = canonical_pem;
    commit.device_cert_json = dc.dump();
    commit.provision_state = provision_state_to_string(ProvisionState::CERT_INSTALLED);
    commit.version = version;

    // 跨键原子 commit：成功才切换 CURRENT；失败保持旧材料/旧档案/原 ProvisionState
    ErrorCode rc = cert_store_->commit(commit);
    if (rc != ErrorCode::SUCCESS) {
        SecLogAdapter::certificate().error(
            "sec.certificate.commit.failed", "证书材料原子提交失败",
            {{"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(rc))}});
        return rc;
    }

    // commit 成功后立即 reload mqtt profile：version 单调递增、重新校验材料、
    // 状态 READY 时发布 sec.tls_credential.changed（reload 失败 → NOT_READY/ERROR，证书保持已提交）
    if (tls_provider_) {
        ErrorCode rl = tls_provider_->rotateCredential("mqtt");
        if (rl != ErrorCode::SUCCESS) {
            SecLogAdapter::tls_credential().warn(
                "sec.tls_credential.reload_failed",
                "证书已提交，TLS reload 未就绪（root_ca 缺失或材料校验失败）",
                {{"error_code", tbox::fw::log::FieldValue::makeString(error_code_to_string(rl))}});
        }
    }
    return ErrorCode::SUCCESS;
}

// ============================================================
// TBOX-SEC-DSN-CR-018 §3.3: Root 入链安装策略检查
// ============================================================

ErrorCode SecService::rejectRootInjectedIntoChain(
    const ParsedCertificateChain& chain) const {
    // parser 不访问 store；此处读取 Loader 导入的信任根并计算其证书 digest。
    // 无 root_ca（未配置/读取失败）则跳过比对：可验证自签名已在 parser 拒绝，
    // 缺少信任根时 Provider 保持 NOT_READY（fail-closed 由 Provider 承担）。
    if (!store_.has_value() || !store_->isReady() || !store_->has("root_ca")) {
        return ErrorCode::SUCCESS;
    }

    std::string root_pem;
    try {
        root_pem = store_->load<std::string>("root_ca");
    } catch (const std::exception&) {
        return ErrorCode::SUCCESS;
    }
    if (root_pem.empty()) {
        return ErrorCode::SUCCESS;
    }

    std::vector<std::array<uint8_t, 32>> root_digests;
    BIO* bio = BIO_new_mem_buf(root_pem.data(), static_cast<int>(root_pem.size()));
    if (!bio) {
        return ErrorCode::SUCCESS;
    }
    X509* c = nullptr;
    while ((c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
        unsigned char* der = nullptr;
        const int len = i2d_X509(c, &der);
        if (len > 0 && der) {
            std::array<uint8_t, 32> d{};
            SHA256(der, static_cast<size_t>(len), d.data());
            root_digests.push_back(d);
        }
        OPENSSL_free(der);
        X509_free(c);
    }
    BIO_free(bio);

    if (root_digests.empty()) {
        return ErrorCode::SUCCESS;
    }

    // 该比较只用于禁止 Root 存储，不把输入证书提升为锚。
    for (const auto& d : chain.cert_der_sha256) {
        for (const auto& rd : root_digests) {
            if (d == rd) {
                return ErrorCode::CERT_VALIDATION_FAILED;  // Root 入链拒绝
            }
        }
    }
    return ErrorCode::SUCCESS;
}

// ============================================================
// TBOX-SEC-DSN-CR-014: CA Material Loader
// ============================================================

void SecService::initializeCaMaterialLoader() {
    // 找到 mqtt profile 的 root_ca_source（直接从 config_snapshot 读取，
    // 不依赖 loadTlsProfileConfig 的执行顺序）
    std::string source;
    if (config_.config_snapshot) {
        source = config_.config_snapshot->getString(
            "sec.tls.profiles.mqtt.root_ca_source",
            "/usr/share/tbox/sec/trust/mqtt-root-ca.pem");
    } else {
        auto it = config_.tls_profiles.find("mqtt");
        if (it != config_.tls_profiles.end()) {
            source = it->second.root_ca_source;
        }
    }
    if (source.empty()) {
        SecLogAdapter::tls_credential().warn(
            "sec.ca.source_unconfigured",
            "CA Material Loader：root_ca_source 未配置（TLS 保持 NOT_READY）");
        return;
    }

    // 读取 source 文件（BUILD 安装的公开信任根，非秘密）
    std::ifstream f(source, std::ios::binary);
    if (!f.is_open()) {
        SecLogAdapter::tls_credential().warn(
            "sec.ca.source_missing",
            "CA Material Loader：信任根文件缺失（TLS 保持 NOT_READY）",
            {{"root_ca_source", tbox::fw::log::FieldValue::makeString(source)}});
        return;
    }
    std::string pem((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    f.close();
    if (pem.empty()) {
        SecLogAdapter::tls_credential().warn(
            "sec.ca.source_empty", "CA Material Loader：信任根文件为空（TLS 保持 NOT_READY）");
        return;
    }

    // 校验：PEM 可解析且至少一个证书为 CA（basicConstraints CA=TRUE）
    bool parsed_ok = false;
    bool is_ca = false;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio) {
        X509* c = nullptr;
        while ((c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
            parsed_ok = true;
            BASIC_CONSTRAINTS* bc = static_cast<BASIC_CONSTRAINTS*>(
                X509_get_ext_d2i(c, NID_basic_constraints, nullptr, nullptr));
            if (bc && bc->ca) is_ca = true;
            if (bc) BASIC_CONSTRAINTS_free(bc);
            X509_free(c);
        }
        BIO_free(bio);
    }
    if (!parsed_ok || !is_ca) {
        SecLogAdapter::tls_credential().warn(
            "sec.ca.source_invalid",
            "CA Material Loader：信任根不可解析或非 CA 证书（TLS 保持 NOT_READY）",
            {{"root_ca_source", tbox::fw::log::FieldValue::makeString(source)}});
        return;
    }

    // 校验通过：经 framework-store 原子导入 key=root_ca（单键原子写即可，无跨键需求）
    try {
        store_->save("root_ca", pem);
        SecLogAdapter::tls_credential().info(
            "sec.ca.imported", "CA Material Loader：信任根已导入 store (key=root_ca)",
            {{"root_ca_source", tbox::fw::log::FieldValue::makeString(source)}});
    } catch (const std::exception& e) {
        SecLogAdapter::tls_credential().error(
            "sec.ca.import_failed", "CA Material Loader：信任根导入失败（TLS 保持 NOT_READY）",
            {{"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
    }
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

ErrorCode SecService::store_certificate(const std::vector<uint8_t>& payload) {
    // TBOX-SEC-DSN-CR-018：保持"仅存储"语义（不做 leaf sanity），
    // 统一走 严格解析 → canonical 全链 → 原子发布。
    ParseResult parsed = chain_parser_.parse(payload, chain_limits_);
    if (!parsed.ok) {
        return ErrorCode::CERT_INSTALL_FAILED;
    }
    ErrorCode root_rc = rejectRootInjectedIntoChain(parsed.chain);
    if (root_rc != ErrorCode::SUCCESS) {
        return root_rc;
    }
    std::string pem;
    if (!chain_canonicalizer_.toPem(parsed.chain, pem)) {
        return ErrorCode::CERT_INSTALL_FAILED;
    }
    return publishDeviceCertChain(pem);
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

    // TBOX-SEC-REQ-CR-003 / DSN-CR-003 §5 / US-002：AES-128 对称 Seed-Key。
    //   key = AES-128-ECB(key = shared_secret, plaintext = seed)
    // Seed/Key 均为 16 字节（128-bit）；共享密钥由 provisioning 注入
    // （配置 sec.seed_key.shared_secret，32 个 hex 字符），出厂默认模板不含该键。
    // 缺失或格式非法时 fail-closed（不允许退回 XOR/占位算法）。
    std::vector<uint8_t> shared_secret;
    if (!decodeHexSecret(config_.get_seed_key_shared_secret(), shared_secret)) {
        SecLogAdapter::seed_key().error(
            "sec.seed_key.shared_secret_missing",
            "Seed-Key 共享密钥未配置或格式非法（需 32 hex 字符），拒绝校验（fail-closed）");
        return ErrorCode::KEY_VERIFICATION_FAILED;
    }

    expected_key.resize(SEED_KEY_SIZE);
    int out_len = 0, final_len = 0;
    int ok = 1;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::KEY_VERIFICATION_FAILED;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
                           shared_secret.data(), nullptr) != 1) ok = 0;
    if (ok && EVP_CIPHER_CTX_set_padding(ctx, 0) != 1) ok = 0;  // 16 字节 = 单块，无填充
    if (ok && EVP_EncryptUpdate(ctx, expected_key.data(), &out_len,
                                seed.data(), static_cast<int>(seed.size())) != 1) ok = 0;
    if (ok && EVP_EncryptFinal_ex(ctx, expected_key.data() + out_len,
                                  &final_len) != 1) ok = 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        expected_key.clear();
        return ErrorCode::KEY_VERIFICATION_FAILED;
    }
    expected_key.resize(out_len + final_len);
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

// CR-014: 已删除 storage.ca_cert 旧回退（find_ca_cert_from_config），root_ca 仅由 CA Material Loader 导入。

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
    // TBOX-SEC-DSN-CR-014: root_ca_source 为 CA Material Loader 的信任根来源（文件路径）。
    // 量产固定指向 BUILD 安装资产 /usr/share/tbox/sec/trust/mqtt-root-ca.pem。
    pc.root_ca_source = snap->getString(
        base + ".root_ca_source", "/usr/share/tbox/sec/trust/mqtt-root-ca.pem");
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

    // 设备 key_id 解析器：hsm_uid(ecu_uid) + key_id（与 KeyEngine::make_key_id 一致，不绑定 VIN）
    DeviceKeyIdResolver key_resolver = [this]() -> std::string {
        return ecu_uid_ + "+" + ecu_uid_;
    };

    // TLS 材料读取器：root_ca 从 SEC 受控存储（framework-store，服务名 "sec"）按键读取 PEM；
    // device_cert_chain 从 CertificateStore 当前 generation 读取（CR-014：跨键原子提交产物，
    // Provider 只按逻辑键读取，不得猜测档案键/文件名/格式）。store 或 cert_store 不可用时返回空串。
    TlsMaterialResolver material_resolver = [this](const std::string& key) -> std::string {
        if (key == "device_cert_chain") {
            return cert_store_ ? cert_store_->currentDeviceCertChain() : "";
        }
        if (key != "root_ca") {
            return "";
        }
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
