#pragma once

//
// V2C 业务密钥开通服务（TBOX-SEC-DSN-CR-019 §4/§5/§6/§7/§8；CR-020 §5/§8/§9/§11）。
//
// BusinessKeyProvisioningService 负责状态查询、requestId 规范化摘要与幂等事务、
// ECDH-ES v1 信封校验、HSM/eSE stage/verify/commit/rollback、掉电恢复与 UNKNOWN
// 收敛、importProof 生成与非敏感结果返回。
//
// 不负责 MQTT/Cloud Ready/VMD/KMS 调用、业务 keyId/版本选择、车辆绑定判断或
// V2C payload 加解密。明文密钥不进入调用方，也不落在普通内存/Store/日志。
//

#include "business_key_capability.h"
#include "business_key_provider.h"
#include "secure_metadata_ledger.h"
#include "trusted_time.h"
#include "tbox/sec/business_key.h"
#include "error_codes.h"

#include <atomic>
#include <cstdint>
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
    std::vector<std::string> allowed_envelope_formats;           ///< {ECDH_ES_P256_V1}
    std::vector<std::string> allowed_wrapping_suites;            ///< 版本化封装套件 allowlist
    std::vector<std::string> allowed_algorithms;                 ///< 业务密钥算法 allowlist
    int max_items = 2;
    int64_t max_wrapped_key_bytes = 4096;
    int64_t max_parameters_bytes = 2048;
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

    /// provider 初始化 + journal/ledger 恢复 + 能力合取 READY 判定。
    ErrorCode initialize();

    void beginShutdown();
    bool isShuttingDown() const noexcept { return shutting_down_.load(); }
    /// 是否接受新信封（能力合取）。状态查询不受此限制（US-022）。
    bool isReady() const;

    /// 最后一次成功探测的能力快照（US-022）。
    V2cKeyProvisioningCapability capability() const;

    /// KL1 契约快照（TBOX-SEC-DSN-CR-023 §12.11.1；只读）。
    /// 与 capability()/查询同锁读取，保证同 epoch 一致；
    /// epoch 绑定 daemon 与存储恢复世代，重启/恢复/存储更换即更换。
    KeyprovContractSnapshot contractSnapshot() const;

    /// 查询业务密钥件内状态（US-008），slot 与 ledger 交叉校验。
    ErrorCode getStatus(const std::string& business_domain,
                        const std::vector<std::string>& purposes,
                        BusinessKeyStatusSet& out);

    /// 导入 Wrapped Key 批次（US-015..US-021）。非幂等：禁止调用方盲目重放。
    ErrorCode import(const std::string& request_id,
                     const std::string& business_domain,
                     const std::vector<WrappedKeyItem>& items,
                     ImportResult& out);

    /// KL1 租约准入导入（TBOX-SEC-DSN-CR-023 §12.11.3；旧 import() 不变）。
    ///
    /// 锁内处理顺序（事实优先级）：
    ///   1. 匹配 COMMITTED → 恢复原结果/proof，旧 E 过期不否定事实；
    ///   2. STAGED/PROCESSING/UNKNOWN 或可疑残留 → 原精确状态或既有 UNKNOWN/1024，
    ///      交恢复/对账，不创建第二 operation；
    ///   3. 确属新 operation 才准入：存储/能力/可信时间不健康 → 1025；
    ///      epoch 不匹配 → 1030；epoch 匹配但 U≥E → 1029；全部门禁满足才建 journal 启动。
    ///
    /// 1029/1030 均不是强 NOT_FOUND：只能证明本次未启动新操作，
    /// 不能作为“该 rid 历史无副作用”的证据。
    ErrorCode importKl1(const std::string& request_id,
                        const std::string& business_domain,
                        const std::vector<WrappedKeyItem>& items,
                        const KeyprovImportContext& context,
                        ImportResult& out,
                        KeyprovResultAttachment& attach);

    /// 按 requestId 查询导入结果（US-021）。
    ErrorCode getImportResult(const std::string& request_id, ImportResult& out);

    /// KL1 结果查询（TBOX-SEC-DSN-CR-023 §12.11.2；只读，同 import 锁）。
    /// 附同一快照 epoch/contract 与已存在 request 身份/证据摘要；
    /// NOT_FOUND 仅在强 NF 全部条件成立（存储健康、恢复完成、无残留、非治理）时返回。
    ErrorCode getImportResultKl1(const std::string& request_id,
                                 ImportResult& out,
                                 KeyprovResultAttachment& attach);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    std::atomic<bool> shutting_down_{false};
};

} // namespace sec
} // namespace tbox
