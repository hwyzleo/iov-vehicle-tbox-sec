#include "csr_builder.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace tbox {
namespace sec {

CsrBuilder::CsrBuilder(std::shared_ptr<KeyEngine> key_engine)
    : key_engine_(key_engine) {}

ErrorCode CsrBuilder::build_csr(const CsrConfig& config,
                               std::vector<uint8_t>& csr_der) {
    if (!key_engine_) {
        return ErrorCode::INVALID_PARAMETER;
    }
    
    // Get device key
    KeyPair key_pair;
    ErrorCode result = key_engine_->get_device_key(config.vin, config.ecu_uid, key_pair);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    return build_csr_with_key(config, key_pair, csr_der);
}

ErrorCode CsrBuilder::build_csr_with_key(const CsrConfig& config,
                                        const KeyPair& key_pair,
                                        std::vector<uint8_t>& csr_der) {
    // Create CSR structure
    std::vector<uint8_t> csr_data;
    ErrorCode result = create_csr_structure(config, key_pair, csr_data);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    // Sign CSR
    std::vector<uint8_t> signature;
    result = sign_csr(csr_data, config.vin, config.ecu_uid, signature);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }
    
    // Assemble final CSR
    return assemble_csr(csr_data, signature, csr_der);
}

ErrorCode CsrBuilder::create_csr_structure(const CsrConfig& config,
                                          const KeyPair& key_pair,
                                          std::vector<uint8_t>& csr_data) {
    // Create X.509 REQ structure
    X509_REQ* x509_req = X509_REQ_new();
    if (!x509_req) {
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Set version
    X509_REQ_set_version(x509_req, 0); // Version 1
    
    // Set subject name
    X509_NAME* subject_name = X509_REQ_get_subject_name(x509_req);
    
    // Add CN = ECU_UID
    X509_NAME_add_entry_by_txt(subject_name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(config.common_name.c_str()),
                               -1, -1, 0);
    
    // For now, we'll create a simple CSR without extensions to avoid complexity
    // In a real implementation, you would properly add SAN extensions
    
    // Create a dummy key pair for testing (in real implementation, use the actual key)
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Generate a simple EC key for testing
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Generate key pair
    if (!EC_KEY_generate_key(ec_key)) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Set the EC key to EVP_PKEY
    if (!EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Set public key
    if (!X509_REQ_set_pubkey(x509_req, pkey)) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Sign the request with the private key
    if (!X509_REQ_sign(x509_req, pkey, EVP_sha256())) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    // Convert to DER
    int len = i2d_X509_REQ(x509_req, NULL);
    if (len <= 0) {
        EVP_PKEY_free(pkey);
        X509_REQ_free(x509_req);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    
    csr_data.resize(len);
    unsigned char* p = csr_data.data();
    i2d_X509_REQ(x509_req, &p);
    
    EVP_PKEY_free(pkey);
    X509_REQ_free(x509_req);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::sign_csr(const std::vector<uint8_t>& csr_data,
                              const std::string& vin,
                              const std::string& ecu_uid,
                              std::vector<uint8_t>& signature) {
    // Sign CSR data using device key
    return key_engine_->sign(vin, ecu_uid, csr_data, signature);
}

ErrorCode CsrBuilder::assemble_csr(const std::vector<uint8_t>& csr_data,
                                  const std::vector<uint8_t>& signature,
                                  std::vector<uint8_t>& csr_der) {
    // In real implementation, this would properly assemble the DER-encoded CSR
    // For now, just combine data and signature
    csr_der = csr_data;
    csr_der.insert(csr_der.end(), signature.begin(), signature.end());
    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox