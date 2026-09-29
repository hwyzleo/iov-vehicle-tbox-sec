#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "key_engine.h"
#include "error_codes.h"
#include "trusted_time.h"

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

/// 证书注入 leaf sanity check（TBOX-SEC-DSN-CR-016 §3.2 / CR-017 §6）。
///
/// 时间校验只接受 TrustedTimeProvider 返回 trust_state=Trusted 的采样：
/// - trust_state != Trusted → failure_stage=time_untrusted，不 commit；
/// - 闭区间 + uncertainty 比较（CR-017 §3）：utc_now-uncertainty >= notBefore
///   且 utc_now+uncertainty <= notAfter，否则 failure_stage=time；
/// - 生产构造不得提供默认 system-clock 实例（CR-017 §7），
///   真实/测试 provider 由调用方（SecApplication 装配 / 测试注入）显式传入。
///
/// 本类不验证 CA 签名、不构建证书路径、不要求配置 root_ca；chain 解析与
/// leaf 识别由 Certificate Install Service 完成后再调用本接口。
class CertValidator {
public:
    CertValidator(KeyEngine* key_engine,
                  TrustedTimeProvider& time_provider);

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

    // Check if certificate is expired（fail-closed：时间不可判定按过期处理）
    bool is_certificate_expired(const std::vector<uint8_t>& cert_der);

private:
    KeyEngine* key_engine_;
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
