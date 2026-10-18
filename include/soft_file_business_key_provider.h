#pragma once

//
// SoftFile V2C 业务密钥 provider（TBOX-SEC-DSN-CR-019 §4/§5/§7/§8）。
//
// 仅允许显式非生产 profile 使用：提供件内 unwrap（ECDH-ES P-256 v1 + AES-256-GCM）、
// staging/commit 双槽批次事务、掉电安全 journal、持钥证明。密钥明文在主机内存
// 中只短暂存在并立即清零；at-rest 密钥材料以 KEK 派生的 AEAD 加密后持久化。
//
// production 语义：由 HsmBusinessKeyProvider 承担，SoftFile provider 不得成为
// 量产成功路径（Service 依据 profile/provider 就绪条件 fail-closed）。
//

#include "business_key_provider.h"
#include "hsm_interface.h"

#include <array>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace hwyz {
namespace store {
class Store;
}
} // namespace hwyz

namespace tbox {
namespace sec {

struct BusinessKeyProviderConfig {
    std::string store_root;                                 ///< provider state 根目录
    std::string kek_path;                                   ///< KEK 文件路径（0600；不得与密文同文件）
    std::vector<std::string> allowed_algorithms;            ///< 业务密钥算法 allowlist
    std::vector<std::string> allowed_wrapping_suites;       ///< 封装套件 allowlist
    int64_t max_wrapped_key_bytes = 4096;
    std::string provider_version = "softfile-bk-v1";
};

class SoftFileBusinessKeyProvider : public BusinessKeyProvider {
public:
    SoftFileBusinessKeyProvider(HsmInterface* hsm,
                                BusinessKeyProviderConfig config,
                                BusinessKeyDeviceBindingProvider binding_provider);
    ~SoftFileBusinessKeyProvider() override;

    ErrorCode initialize() override;
    bool isReady() const override;
    std::string providerVersionDigest() const override;
    BusinessKeyProviderCapability capability() const override;

    ErrorCode unwrapToStaging(const std::string& domain,
                              const WrappedKeyItem& item,
                              const EcdhEsP256EnvelopeParameters& params,
                              const std::vector<uint8_t>& canonical_aad,
                              const std::vector<uint8_t>& hkdf_info,
                              const BusinessKeyDeviceBinding& binding,
                              uint64_t generation,
                              std::array<uint8_t, 3>& actual_kcv) override;

    ErrorCode verifyStaging(const std::string& domain,
                            const std::string& purpose) override;

    ErrorCode commitBatch(const std::string& domain, uint64_t generation) override;

    ErrorCode rollbackStaging(const std::string& domain, uint64_t generation) override;

    ErrorCode querySlot(const std::string& domain,
                        const std::string& purpose,
                        BusinessKeySlotInfo& out) override;

    ErrorCode generateProof(const std::string& domain,
                            const std::string& purpose,
                            uint64_t business_key_version,
                            const std::string& request_id,
                            const std::string& key_id,
                            const std::vector<uint8_t>& envelope_digest,
                            const std::vector<uint8_t>& key_check_value,
                            std::vector<uint8_t>& proof,
                            std::string& algorithm) override;

    bool loadJournal(const std::string& request_id_digest,
                     BusinessKeyJournalEntry& out) override;
    ErrorCode saveJournal(const BusinessKeyJournalEntry& entry) override;
    std::vector<BusinessKeyJournalEntry> listJournal() override;
    bool hasPendingStaging() const override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sec
} // namespace tbox
