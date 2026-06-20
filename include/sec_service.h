#pragma once

#include <string>
#include <vector>
#include <memory>
#include "error_codes.h"
#include "provision_state.h"
#include "key_engine.h"
#include "csr_builder.h"
#include "cert_validator.h"
#include "cloud_client.h"

namespace tbox {
namespace sec {

class SecService {
public:
    SecService();
    ~SecService();

    // Initialize the security service
    ErrorCode initialize();

    // Generate key pair
    ErrorCode generate_key_pair();

    // Get CSR (Certificate Signing Request)
    ErrorCode get_csr(std::vector<uint8_t>& csr);

    // Inject certificate
    ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der);

    // Get provision status
    ProvisionStatus get_provision_status() const;

    // Check if device is provisioned
    bool is_provisioned() const;

private:
    std::shared_ptr<KeyEngine> key_engine_;
    std::shared_ptr<CsrBuilder> csr_builder_;
    std::shared_ptr<CertValidator> cert_validator_;
    std::shared_ptr<CloudClient> cloud_client_;
    std::unique_ptr<ProvisionStateManager> state_manager_;
    bool initialized_;
};

} // namespace sec
} // namespace tbox
