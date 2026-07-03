#pragma once

#include <string>
#include <memory>
#include <optional>
#include "key_engine.h"
#include "csr_builder.h"
#include "cert_validator.h"
#include "cloud_client.h"
#include "provision_state.h"
#include "error_codes.h"
#include "diag_service_interface.h"
#include "prov_service_interface.h"
#include "config.h"
#include "store.h"

namespace tbox {
namespace sec {

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

    virtual ~SecService() = default;

    virtual ErrorCode initialize();

    virtual ErrorCode generate_key_pair();

    virtual ErrorCode get_csr(std::vector<uint8_t>& csr_der);

    virtual ErrorCode submit_csr();

    virtual ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);

    virtual ErrorCode apply_certificate();

    virtual ErrorCode get_seed(uint8_t level, std::vector<uint8_t>& seed);

    virtual ErrorCode verify_key(uint8_t level, const std::vector<uint8_t>& key);

    virtual ProvisionStatus get_provision_status() const;

    virtual ErrorCode reset_provision_status();

    virtual std::string get_device_info() const;

    virtual bool is_initialized() const;

    void set_diag_service(std::shared_ptr<DiagServiceInterface> diag_service);
    void set_prov_service(std::shared_ptr<ProvServiceInterface> prov_service);

    // Set CA certificate for signature verification
    ErrorCode set_ca_certificate(const std::vector<uint8_t>& ca_cert_der);

    // Save current provision state to store
    bool save_state();

    // Store certificate to store
    ErrorCode store_certificate(const std::vector<uint8_t>& cert_der);

private:
    SecServiceConfig config_;
    bool initialized_;
    std::shared_ptr<DiagServiceInterface> diag_service_;
    std::shared_ptr<ProvServiceInterface> prov_service_;
    std::unique_ptr<ProvisionStateManager> state_manager_;
    std::optional<hwyz::store::Store> store_;

    std::string vin_;
    std::string device_sn_;

    std::unique_ptr<KeyEngine> key_engine_;
    std::unique_ptr<CsrBuilder> csr_builder_;
    std::unique_ptr<CertValidator> cert_validator_;
    std::unique_ptr<CloudClient> cloud_client_;

    std::vector<uint8_t> csr_der_;  // 存储构建的 CSR

    ErrorCode initialize_hsm();
    ErrorCode initialize_cloud_client();
    ErrorCode load_provision_state();
    ErrorCode load_provision_state_from_store();
    ErrorCode fetch_vehicle_info();

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
};

} // namespace sec
} // namespace tbox
