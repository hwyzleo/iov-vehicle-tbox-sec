#pragma once

#include <string>
#include <vector>
#include <memory>
#include "key_engine.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

struct CsrConfig {
    std::string common_name;      // CN = ECU_UID
    std::string vin;              // SAN: VIN
    std::string ecu_uid;          // SAN: ECU_UID
    std::string key_usage;        // digitalSignature
    std::string extended_key_usage; // clientAuth (OID 1.3.6.1.5.5.7.3.2)
};

class CsrBuilder {
public:
    CsrBuilder(std::shared_ptr<KeyEngine> key_engine);

    ErrorCode build_csr(const CsrConfig& config,
                       std::vector<uint8_t>& csr_der);

private:
    std::shared_ptr<KeyEngine> key_engine_;

    ErrorCode marshal_ec_pubkey_info(const std::vector<uint8_t>& raw_pubkey,
                                     std::vector<uint8_t>& out_der);

    ErrorCode marshal_x509_name(const std::string& cn,
                                std::vector<uint8_t>& out_der);

    ErrorCode marshal_san_extension(const std::string& vin,
                                    const std::string& ecu_uid,
                                    std::vector<uint8_t>& ext_der);

    ErrorCode marshal_ku_extension(std::vector<uint8_t>& ext_der);

    ErrorCode marshal_eku_extension(std::vector<uint8_t>& ext_der);

    ErrorCode build_csr_info(const CsrConfig& config,
                             const KeyPair& key_pair,
                             std::vector<uint8_t>& csr_info_der);
};

} // namespace sec
} // namespace tbox
