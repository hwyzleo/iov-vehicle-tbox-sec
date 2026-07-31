#pragma once

#include <string>
#include <memory>
#include <optional>
#include <chrono>
#include <map>
#include <vector>
#include <atomic>
#include <functional>
#include <nlohmann/json.hpp>
#include "key_engine.h"
#include "csr_builder.h"
#include "cert_validator.h"
#include "cloud_client.h"
#include "error_codes.h"
#include "diag_service_interface.h"
#include "prov_service_interface.h"
#include "config.h"
#include "store.h"
#include "ipc_types.h"

namespace tbox {
namespace sec {

class TlsCredentialProvider;

} // namespace sec
} // namespace tbox

namespace tbox {
namespace sec {

enum class ProvisionState {
    NONE,
    KEY_GENERATED,
    CSR_BUILT,
    CSR_SUBMITTED,
    CERT_INSTALLED,
    FAILED
};

std::string provision_state_to_string(ProvisionState state);
ProvisionState string_to_provision_state(const std::string& str);

struct ProvisionStatus {
    std::string vin;
    std::string ecu_uid;
    ProvisionState state;
    std::string last_error;
    int retry_count = 0;
    std::chrono::system_clock::time_point last_updated;

    nlohmann::json to_json() const;
    static ProvisionStatus from_json(const nlohmann::json& j);
};

struct SoftKeyConfig {
    std::string key_path = "/var/lib/tbox/sec/soft_keys";
    std::string encryption_algo = "aes-256-gcm";
    std::string encryption_key_path = "";
};

struct SecServiceConfig {
    // Old field-based config (for backward compatibility)
    std::string hsm_type;
    std::string hsm_config_path;
    std::string state_file_path;
    std::string ca_cert_path;
    std::string cert_store_path;
    std::string key_provisioning_mode = "hsm";
    bool is_production = false;
    SoftKeyConfig soft_key_config;
    CloudConfig cloud_config;
    std::string store_root;  // Store root path (empty = default)

    // IPC configuration (framework-ipc)
    ::tbox::fw::ipc::IpcConfig ipc_config{};
    std::string ipc_socket_path = "/tmp/tbox-sec.sock";

    // TLS profile configuration (TBOX-SEC-DSN-CR-010)
    // 从 sec.tls.profiles.<name> 读取，启动时供 TlsCredentialProvider 加载材料
    struct TlsProfileConf {
        bool enabled = false;
        std::string profile_name;
        std::string credential_id;
        std::string key_usage;
        std::vector<std::string> allowed_signature_algorithms;
        std::string peer_service;
        bool notify_on_change = true;
        int64_t ref_ttl_sec = 3600;
    };
    std::map<std::string, TlsProfileConf> tls_profiles;

    // New config snapshot (optional, takes precedence when set)
    std::shared_ptr<const hwyz::config::ImmutableConfigView> config_snapshot;

    // Accessors that prefer config_snapshot when available
    std::string get_hsm_type() const {
        if (config_snapshot) return config_snapshot->getString("hsm.type", "");
        return hsm_type;
    }

    std::string get_hsm_library_path() const {
        if (config_snapshot) return config_snapshot->getString("hsm.library_path", "");
        return hsm_config_path;
    }

    std::string get_key_provisioning_mode() const {
        if (config_snapshot) return config_snapshot->getString("key_provisioning.mode", "hsm");
        return key_provisioning_mode;
    }

    std::string get_cloud_endpoint() const {
        if (config_snapshot) return config_snapshot->getString("cloud.endpoint", "");
        return cloud_config.oapi_endpoint;
    }

    int get_cloud_timeout_ms() const {
        if (config_snapshot) return config_snapshot->getInt("cloud.timeout_ms", 5000);
        return cloud_config.timeout_ms;
    }

    int get_cloud_retry_count() const {
        if (config_snapshot) return config_snapshot->getInt("cloud.retry_count", 3);
        return cloud_config.retry_count;
    }

    int get_cloud_retry_delay_ms() const {
        if (config_snapshot) return config_snapshot->getInt("cloud.retry_delay_ms", 1000);
        return cloud_config.retry_delay_ms;
    }

    bool get_is_production() const {
        if (config_snapshot) return config_snapshot->getBool("environment.is_production", false);
        return is_production;
    }

    /// 开发/测试用：TLS ACL 放行的固定服务名（配置 sec.tls.dev_peer_service）。
    /// 非空且非生产环境时，SEC 使用 DevPeerCredentialResolver 绕过 SO_PEERCRED 身份校验。
    /// 生产环境或未配置时返回空（保持严格 systemd 校验）。
    std::string get_tls_dev_peer_service() const {
        if (config_snapshot) return config_snapshot->getString("sec.tls.dev_peer_service", "");
        return "";
    }

    std::string get_state_file_path() const {
        if (config_snapshot) return config_snapshot->getString("storage.state_file", "/var/lib/tbox/sec/provision_state.json");
        return state_file_path;
    }

    std::string get_ca_cert_path() const {
        if (config_snapshot) return config_snapshot->getString("storage.ca_cert", "");
        return ca_cert_path;
    }

    std::string get_cert_store_path() const {
        if (config_snapshot) return config_snapshot->getString("storage.cert_store", "");
        return cert_store_path;
    }

    std::string get_soft_key_path() const {
        if (config_snapshot) return config_snapshot->getString("soft_key.path", "/var/lib/tbox/sec/soft_keys");
        return soft_key_config.key_path;
    }

    std::string get_soft_key_encryption_algo() const {
        if (config_snapshot) return config_snapshot->getString("soft_key.encryption_algo", "aes-256-gcm");
        return soft_key_config.encryption_algo;
    }

    std::string get_soft_key_encryption_key_path() const {
        if (config_snapshot) return config_snapshot->getString("soft_key.encryption_key_path", "");
        return soft_key_config.encryption_key_path;
    }

    CloudConfig get_cloud_config() const {
        CloudConfig config;
        config.oapi_endpoint = get_cloud_endpoint();
        config.timeout_ms = get_cloud_timeout_ms();
        config.retry_count = get_cloud_retry_count();
        config.retry_delay_ms = get_cloud_retry_delay_ms();
        return config;
    }

    std::string get_store_root() const {
        // 快照显式提供 common.store.root 时以快照为准（生产路径）。
        // 否则回退到显式设置的 store_root（测试常用于隔离临时目录），
        // 避免快照存在但未配置该键时错误地落到全局默认目录（会导致测试间串扰）。
        if (config_snapshot && config_snapshot->has("common.store.root")) {
            return config_snapshot->getString("common.store.root", "/var/tbox/sec");
        }
        if (!store_root.empty()) return store_root;
        if (config_snapshot) return "/var/tbox/sec";
        return "/var/lib/tbox";
    }
};

class SecService : public std::enable_shared_from_this<SecService> {
public:
    SecService();
    SecService(const SecServiceConfig& config);
    SecService(const SecServiceConfig& config, 
               std::shared_ptr<DiagServiceInterface> diag_service);
    SecService(const SecServiceConfig& config,
               std::shared_ptr<DiagServiceInterface> diag_service,
               std::shared_ptr<ProvServiceInterface> prov_service);
    SecService(const SecServiceConfig& config, hwyz::store::Store store);
    SecService(const SecServiceConfig& config,
               std::shared_ptr<DiagServiceInterface> diag_service,
               std::shared_ptr<ProvServiceInterface> prov_service,
               hwyz::store::Store store);

    virtual ~SecService();

    virtual ErrorCode initialize();

    // TBOX-SEC-DSN-CR-011: 停机 quiesce。beginShutdown 后拒绝新安全操作（fail-closed），
    // 供 SecApplication::cleanup 首步调用。
    virtual void beginShutdown();
    bool is_shutting_down() const noexcept;

    virtual ErrorCode generate_key_pair();

    virtual ErrorCode export_private_key(std::vector<uint8_t>& private_key);

    virtual ErrorCode get_csr(std::vector<uint8_t>& csr_der);

    virtual ErrorCode submit_csr();

    virtual ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);

    virtual ErrorCode apply_certificate();

    virtual ErrorCode get_seed(uint8_t level, std::vector<uint8_t>& seed);

    virtual ErrorCode verify_key(uint8_t level, const std::vector<uint8_t>& key);

    virtual ProvisionStatus get_provision_status() const;

    // 车辆绑定/个性化状态（从 PROV 查询，PROV 为权威来源）。
    // 与 get_provision_status().state（SEC 证书下发状态）是不同维度。
    virtual DeviceProvisionState get_device_binding_state() const;

    virtual ErrorCode reset_provision_status();

    virtual std::string get_device_info() const;

    virtual bool is_initialized() const;

    void set_diag_service(std::shared_ptr<DiagServiceInterface> diag_service);
    void set_prov_service(std::shared_ptr<ProvServiceInterface> prov_service);

    // TLS Credential Provider 访问（供 SecApplication 装配 dispatcher 注入）
    TlsCredentialProvider* tls_credential_provider();

    // TBOX-SEC-DSN-CR-011: 注入事件发布回调（由 SecApplication 接线到 framework-ipc
    // Server::push_event），解耦 TLS 凭据变更通知与 IPC Server 所有权。
    // 在 SecService::initialize 之后、IPC Server 启动之前设置；未设置时变更事件静默丢弃。
    void setEventPublisher(std::function<void(uint32_t event_type,
                                              const std::string& payload_json)> cb);

    /// 按需确保指定 profile 的 TLS 材料就绪：解析 VIN/ECU_UID（best-effort）后重载材料。
    /// 供 IPC 分发器在收到 getTlsCredential 且状态非 READY 时自愈调用，
    /// 避免因启动时 PROV 尚未就绪而永久停留在 NOT_READY。
    ErrorCode ensure_tls_material_ready(const std::string& profile);

    // Set CA certificate for signature verification
    virtual ErrorCode set_ca_certificate(const std::vector<uint8_t>& ca_cert_der);

    // Save current provision state to store
    bool save_state();

    // Store certificate to store
    ErrorCode store_certificate(const std::vector<uint8_t>& cert_der);

private:
    SecServiceConfig config_;
    bool initialized_;
    std::atomic<bool> shutting_down_{false};  // CR-011: beginShutdown 后拒绝新安全操作
    std::shared_ptr<DiagServiceInterface> diag_service_;
    std::shared_ptr<ProvServiceInterface> prov_service_;
    std::optional<hwyz::store::Store> store_;
    std::unique_ptr<TlsCredentialProvider> tls_provider_;
    // CR-011: TLS 凭据变更事件发布回调（由 SecApplication 注入 ipc::Server::push_event）
    std::function<void(uint32_t, const std::string&)> event_publisher_;

    std::string vin_;
    std::string ecu_uid_;

    std::unique_ptr<KeyEngine> key_engine_;
    std::unique_ptr<CsrBuilder> csr_builder_;
    std::unique_ptr<CertValidator> cert_validator_;
    std::unique_ptr<CloudClient> cloud_client_;

    std::vector<uint8_t> csr_der_;  // 存储构建的 CSR

    ErrorCode initialize_hsm();
    ErrorCode initialize_cloud_client();
    ErrorCode load_provision_state_from_store();
    ErrorCode ensure_vehicle_info();

    // TLS Credential Provider 初始化（加载 mqtt profile 配置与材料）
    void initializeTlsCredentialProvider();
    void loadTlsProfileConfig();

public:
    ErrorCode generate_and_store_key_pair();
private:
    ErrorCode build_and_store_csr();
    ErrorCode submit_csr_to_cloud();
    ErrorCode validate_and_store_certificate(const std::vector<uint8_t>& cert_der);
    ErrorCode store_certificate_to_file(const std::vector<uint8_t>& cert_der);

    void update_provision_state(ProvisionState state, const std::string& error = "");
    void handle_error(ErrorCode error, const std::string& context);
    
    ErrorCode handle_diag_request(DiagRequestType request_type,
                                 const std::vector<uint8_t>& request_data,
                                 DiagResponse& response);

    // Seed-Key security parameters
    static constexpr size_t SEED_KEY_SIZE = 16;
    static constexpr int MAX_FAILED_ATTEMPTS = 3;
    static constexpr int LOCKOUT_DURATION_SEC = 10;

    // Seed state management
    struct SeedState {
        std::vector<uint8_t> seed;
        uint8_t security_level = 0;  // UDS security level used for requestSeed
        bool generated = false;
        bool consumed = false;
        std::chrono::steady_clock::time_point generated_at;
    };
    
    SeedState current_seed_;
    std::mutex seed_mutex_;
    int failed_attempts_ = 0;
    std::chrono::steady_clock::time_point lockout_until_;
    bool in_lockout_ = false;

    // Seed-Key helper methods
    ErrorCode generate_random_seed(std::vector<uint8_t>& seed);
    ErrorCode compute_expected_key(const std::vector<uint8_t>& seed, std::vector<uint8_t>& expected_key);
    bool is_seed_valid() const;
    void invalidate_seed();
    bool is_in_lockout() const;
    void increment_failed_attempts();
    void reset_failed_attempts();

    // CA certificate loading helper
    std::string find_ca_cert_from_config();
    std::string find_cert_store_from_config();

    // Store helper methods for ProvisionStatus serialization
    void save_provision_status_to_store(const ProvisionStatus& status);
    ProvisionStatus load_provision_status_from_store() const;

    // Base64 encoding for certificate storage
    static std::string base64_encode(const std::vector<uint8_t>& data);
};

} // namespace sec
} // namespace tbox
