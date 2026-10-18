#pragma once

//
// HSM/eSE V2C 业务密钥 provider（TBOX-SEC-DSN-CR-019 §4/§5；CR-020 §8/§11）。
//
// production 可信 HSM/eSE provider、设备解封装身份、secure journal 与安全元数据
// 尚未全部就绪时保持 NOT_READY，禁止软件明文降级。该适配类在真实厂商 SDK 接入前
// 将所有写/查操作 fail-closed，capability 全 false；量产启用条件满足后由设备集成
// 替换/扩展实现。
//

#include "business_key_provider.h"

#include <string>

namespace tbox {
namespace sec {

class HsmBusinessKeyProvider : public BusinessKeyProvider {
public:
    explicit HsmBusinessKeyProvider(std::string provider_version = "hsm-bk-pending")
        : provider_version_(std::move(provider_version)) {}

    ErrorCode initialize() override { return ErrorCode::SUCCESS; }
    bool isReady() const override { return false; }
    std::string providerVersionDigest() const override { return provider_version_; }
    BusinessKeyProviderCapability capability() const override {
        return BusinessKeyProviderCapability{};
    }

    ErrorCode unwrapToStaging(const std::string&, const WrappedKeyItem&,
                              const EcdhEsP256EnvelopeParameters&,
                              const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                              const BusinessKeyDeviceBinding&, uint64_t,
                              std::array<uint8_t, 3>&) override {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    ErrorCode verifyStaging(const std::string&, const std::string&) override {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    ErrorCode commitBatch(const std::string&, uint64_t) override {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    ErrorCode rollbackStaging(const std::string&, uint64_t) override {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    ErrorCode querySlot(const std::string&, const std::string&,
                        BusinessKeySlotInfo& out) override {
        out = BusinessKeySlotInfo{};
        out.state = BusinessKeyState::UNKNOWN;
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    ErrorCode generateProof(const std::string&, const std::string&, uint64_t,
                            const std::string&, const std::string&,
                            const std::vector<uint8_t>&, const std::vector<uint8_t>&,
                            std::vector<uint8_t>&, std::string&) override {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }

    bool loadJournal(const std::string&, BusinessKeyJournalEntry&) override { return false; }
    ErrorCode saveJournal(const BusinessKeyJournalEntry&) override {
        return ErrorCode::BUSINESS_KEY_NOT_READY;
    }
    std::vector<BusinessKeyJournalEntry> listJournal() override { return {}; }
    bool hasPendingStaging() const override { return false; }

private:
    std::string provider_version_;
};

} // namespace sec
} // namespace tbox
