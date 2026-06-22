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

namespace tbox {
namespace sec {

struct SecServiceConfig {
    std::string vin;
    std::string ecu_uid;
    std::string hsm_type;
    std::string hsm_config_path;
    std::string state_file_path;
    CloudConfig cloud_config;
};

class SecService {
public:
    SecService();
    SecService(const SecServiceConfig& config);
    SecService(const SecServiceConfig& config, 
               std::shared_ptr<DiagServiceInterface> diag_service);

    virtual ~SecService() = default;

    virtual ErrorCode initialize();

    virtual ErrorCode generate_key_pair();

    virtual ErrorCode get_csr(std::vector<uint8_t>& csr_der);

    virtual ErrorCode submit_csr();

    virtual ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);

    virtual ProvisionStatus get_provision_status() const;

    virtual ErrorCode reset_provision_status();

    virtual std::string get_device_info() const;

    virtual bool is_initialized() const;

    void set_diag_service(std::shared_ptr<DiagServiceInterface> diag_service);

private:
    SecServiceConfig config_;
    bool initialized_;
    std::shared_ptr<DiagServiceInterface> diag_service_;

    std::unique_ptr<KeyEngine> key_engine_;
    std::unique_ptr<CsrBuilder> csr_builder_;
    std::unique_ptr<CertValidator> cert_validator_;
    std::unique_ptr<CloudClient> cloud_client_;
    std::unique_ptr<ProvisionStateManager> state_manager_;

    ErrorCode initialize_hsm();
    ErrorCode initialize_cloud_client();
    ErrorCode load_provision_state();

    ErrorCode generate_and_store_key_pair();
    ErrorCode build_and_store_csr();
    ErrorCode submit_csr_to_cloud();
    ErrorCode validate_and_store_certificate(const std::vector<uint8_t>& cert_der);

    void update_provision_state(ProvisionState state, const std::string& error = "");
    void handle_error(ErrorCode error, const std::string& context);
    
    ErrorCode handle_diag_request(DiagRequestType request_type,
                                 const std::vector<uint8_t>& request_data,
                                 DiagResponse& response);
};

} // namespace sec
} // namespace tbox
