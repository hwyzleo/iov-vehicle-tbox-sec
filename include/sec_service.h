#pragma once

#include <string>
#include <memory>
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

struct SecServiceConfig {
    std::shared_ptr<const hwyz::config::ImmutableConfigView> config_snapshot;

    std::string get_hsm_type() const {
        return config_snapshot->getString("hsm.type", "soft_file");
    }

    std::string get_key_provisioning_mode() const {
        return config_snapshot->getString("key_provisioning.mode", "soft_file");
    }

    std::string get_cloud_endpoint() const {
        return config_snapshot->getString("cloud.endpoint");
    }

    int get_cloud_timeout_ms() const {
        return config_snapshot->getInt("cloud.timeout_ms", 5000);
    }

    bool is_production() const {
        return config_snapshot->getBool("environment.is_production", false);
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

private:
    SecServiceConfig config_;
    hwyz::store::Store store_;
    bool initialized_;
    std::shared_ptr<DiagServiceInterface> diag_service_;
    std::shared_ptr<ProvServiceInterface> prov_service_;

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
