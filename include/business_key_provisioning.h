#pragma once

//
// V2C 业务密钥开通服务（TBOX-SEC-DSN-CR-019 §4/§5/§6/§7/§8）。
//
// BusinessKeyProvisioningService 负责状态查询、requestId 规范化摘要与幂等事务、
// Wrapped Key bundle 校验、HSM/eSE stage/verify/commit/rollback、掉电恢复与 UNKNOWN
// 收敛、importProof 生成与非敏感结果返回。
//
// 不负责 MQTT/Cloud Ready/VMD/KMS 调用、业务 keyId/版本选择、车辆绑定判断或
// V2C payload 加解密。明文密钥不进入调用方，也不落在普通内存/Store/日志。
//

#include "business_key_provider.h"
#include "secure_metadata_ledger.h"
#include "trusted_time.h"
#include "tbox/sec/business_key.h"
#include "error_codes.h"

#include <cstdint>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace tbox {
namespace sec {

struct BusinessKeyProvisioningConfig {
    bool enabled = false;                                        ///< 默认关闭（量产显式打开）
    bool is_production = false;
    std::vector<std::string> allowed_domains;                    ///< {V2C_COMM}
    std::vector<std::string> required_purposes;                  ///< {UPLINK_AEAD,DOWNLINK_AEAD}
    std::vector<std::string> allowed_wrapping_suites;            ///< 版本化封装套件 allowlist
    std::vector<std::string> allowed_algorithms;                 ///< 业务密钥算法 allowlist
    int max_items = 2;
    int64_t max_wrapped_key_bytes = 4096;
    int64_t request_timeout_ms = 10000;
};

class BusinessKeyProvisioningService {
public:
    BusinessKeyProvisioningService(BusinessKeyProvisioningConfig config,
                                   std::unique_ptr<BusinessKeyProvider> provider,
                                   std::shared_ptr<TrustedTimeProvider> trusted_time,
                                   std::unique_ptr<SecureMetadataLedger> ledger,
                                   BusinessKeyDeviceBindingProvider binding_provider = {});
    ~BusinessKeyProvisioningService();

    /// provider 初始化 + journal/ledger 恢复 + READY 判定。
    ErrorCode initialize();

    void beginShutdown();
    bool isShuttingDown() const noexcept { return shutting_down_.load(); }
    bool isReady() const;

    /// 查询业务密钥件内状态（US-008），slot 与 ledger 交叉校验。
    ErrorCode getStatus(const std::string& business_domain,
                        const std::vector<std::string>& purposes,
                        BusinessKeyStatusSet& out);

    /// 导入 Wrapped Key 批次（US-009/010/011/012）。非幂等：禁止调用方盲目重放。
    ErrorCode import(const std::string& request_id,
                     const std::string& business_domain,
                     const std::vector<WrappedKeyItem>& items,
                     ImportResult& out);

    /// 按 requestId 查询导入结果（US-011）。
    ErrorCode getImportResult(const std::string& request_id, ImportResult& out);

    /// SEC 依据 requestId/domain/purpose/version/device identity 构造 AAD。
    /// 调用方（云端）封装时必须绑定相同 AAD。
    static std::vector<uint8_t> buildAad(const std::string& request_id,
                                         const std::string& business_domain,
                                         const std::string& purpose,
                                         uint64_t business_key_version,
                                         const std::string& device_identity);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    std::atomic<bool> shutting_down_{false};
};

} // namespace sec
} // namespace tbox
