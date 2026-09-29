#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "key_engine.h"
#include "error_codes.h"

namespace tbox {
namespace sec {

struct CertificateInfo {
    std::string serial_number;
    std::string issuer;
    std::string subject;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<uint8_t> public_key;
    std::string key_usage;
    std::string extended_key_usage;
};

/// 可信时间查询结果（TBOX-SEC-DSN-CR-016 §3.2）。
/// framework/平台时间可信度接口确认前，默认实现将系统时钟视为 TRUSTED；
/// 该默认仅为过渡实现，不构成最终安全决策，须随 framework 时间接口契约收敛
/// （生产环境 UNTRUSTED/UNKNOWN 时注入必须显式失败，不得 commit）。
struct TrustedTime {
    bool trusted = false;                            ///< trust_state == TRUSTED
    std::chrono::system_clock::time_point utc_now{}; ///< 可信 UTC
    std::string source;                              ///< 时间来源标识
};

/// 可信时间提供方抽象。CR-016 阻塞项：具体提供方/同步状态接口/freshness
/// 门限属 framework/平台依赖，待确认后注入真实实现。
class TrustedTimeProvider {
public:
    virtual ~TrustedTimeProvider() = default;
    virtual TrustedTime get_trusted_time() const = 0;
};

/// 默认实现：以系统时钟作为当前可信时间源（过渡实现，待 framework 时间接口确认）。
class SystemClockTrustedTimeProvider final : public TrustedTimeProvider {
public:
    TrustedTime get_trusted_time() const override;
};

class CertValidator {
public:
    CertValidator(KeyEngine* key_engine,
                  TrustedTimeProvider* time_provider = nullptr);

    // 注入 sanity check：仅校验单个 leaf（TBOX-SEC-DSN-CR-016）。
    // 不验证 CA 签名、不构建证书路径、不要求配置 root_ca；chain 解析与
    // leaf 识别由 Certificate Install Service 完成后再调用本接口。
    ErrorCode validate_certificate(const std::string& vin,
                                   const std::string& ecu_uid,
                                   const std::vector<uint8_t>& cert_der,
                                   bool& valid);

    // Extract certificate information
    ErrorCode extract_certificate_info(const std::vector<uint8_t>& cert_der,
                                       CertificateInfo& info);

    // Check if certificate is expired
    bool is_certificate_expired(const std::vector<uint8_t>& cert_der);

private:
    KeyEngine* key_engine_;
    std::unique_ptr<TrustedTimeProvider> owned_time_provider_;
    TrustedTimeProvider* time_provider_;

    // Internal validation methods
    ErrorCode check_certificate_validity(const std::vector<uint8_t>& cert_der,
                                        bool& valid);

    ErrorCode match_certificate_key(const std::vector<uint8_t>& cert_der,
                                   const std::string& vin,
                                   const std::string& ecu_uid,
                                   bool& match);
};

} // namespace sec
} // namespace tbox
