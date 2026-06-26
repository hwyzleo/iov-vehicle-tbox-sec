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

namespace tbox {
namespace sec {

struct SoftKeyConfig {
    std::string key_path = "/var/lib/tbox/sec/soft_keys";  // 软件密钥存储路径
    std::string encryption_algo = "aes-256-gcm";           // 加密算法
    std::string encryption_key_path = "";                   // 加密密钥路径（为空则使用默认）
};

struct SecServiceConfig {
    std::string hsm_type;
    std::string hsm_config_path;
    std::string state_file_path;
    std::string ca_cert_path;
    std::string cert_store_path;
    std::string key_provisioning_mode = "hsm";  // 密钥生成模式 (hsm/soft_file)
    SoftKeyConfig soft_key_config;               // 软件落盘配置
    CloudConfig cloud_config;
    bool is_production = false;                  // 是否量产环境
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
    bool initialized_;
    std::shared_ptr<DiagServiceInterface> diag_service_;
    std::shared_ptr<ProvServiceInterface> prov_service_;

    std::string vin_;
    std::string ecu_uid_;

    std::unique_ptr<KeyEngine> key_engine_;
    std::unique_ptr<CsrBuilder> csr_builder_;
    std::unique_ptr<CertValidator> cert_validator_;
    std::unique_ptr<CloudClient> cloud_client_;
    std::unique_ptr<ProvisionStateManager> state_manager_;

    std::vector<uint8_t> csr_der_;  // 存储构建的 CSR

    ErrorCode initialize_hsm();
    ErrorCode initialize_cloud_client();
    ErrorCode load_provision_state();
    ErrorCode fetch_vehicle_info();

    ErrorCode generate_and_store_key_pair();
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
