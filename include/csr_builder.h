#pragma once

#include <string>
#include <vector>
#include <memory>
#include "key_engine.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

struct CsrConfig {
    std::string device_sn;        // 设备序列号（ECU UID / 芯片UID）
    std::string key_id;           // 密钥标识
    std::string algorithm;        // 签名算法（如 SHA256withECDSA）
};

// CSR 构建器
// Subject DN 格式: CN=device_sn, OU=TBOX-TSP, O=OpenIOV, C=CN
class CsrBuilder {
public:
    CsrBuilder(KeyEngine* key_engine);

    ErrorCode build_csr(const std::string& vin,
                       const CsrConfig& config,
                       std::vector<uint8_t>& csr_der);

private:
    KeyEngine* key_engine_;

    ErrorCode marshal_ec_pubkey_info(const std::vector<uint8_t>& raw_pubkey,
                                     std::vector<uint8_t>& out_der);

    ErrorCode marshal_x509_name(const std::string& device_sn,
                                std::vector<uint8_t>& out_der);

    ErrorCode marshal_san_extension(const std::string& device_sn,
                                    std::vector<uint8_t>& ext_der);

    ErrorCode marshal_ku_extension(std::vector<uint8_t>& ext_der);

    ErrorCode marshal_eku_extension(std::vector<uint8_t>& ext_der);

    ErrorCode build_csr_info(const std::string& vin,
                             const CsrConfig& config,
                             const KeyPair& key_pair,
                             std::vector<uint8_t>& csr_info_der);
};

} // namespace sec
} // namespace tbox
