#pragma once

#include "tbox/sec/types.h"
#include "tbox/sec/errors.h"
#include "hsm_interface.h"
#include "peer_credential.h"

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <cstdint>

namespace tbox {
namespace sec {

/// TLS profile 配置（由 sec.tls.profiles.<name> 加载）
struct TlsProfileConfig {
    std::string profile_name = "mqtt";
    std::string credential_id = "mqtt-primary";
    std::string key_usage = "clientAuth";
    std::vector<SignatureAlgorithm> allowed_signature_algorithms;
    std::string peer_service = "tbox-mqtt.service";  ///< 授权调用方 systemd unit
    bool notify_on_change = true;
    std::string root_ca_key = "root_ca";                     ///< SEC 受控存储 key：共享信任根（PEM），多处引用
    std::string client_cert_chain_key = "device_cert_chain"; ///< SEC 受控存储 key：设备客户端证书链（PEM，leaf->intermediate）
    int64_t ref_ttl_sec = 3600;          ///< private_key_ref 有效期（秒）
};

/// TLS 凭据变更通知回调（由 SecService 接线到 framework-ipc Server::push_event）
using TlsCredentialNotifyCallback =
    std::function<void(const std::string& profile, const TlsCredentialChangedEvent& event)>;

/// 设备 HSM key_id 解析器（返回 vin+"+"+ecu_uid 形式的 key_id）
using DeviceKeyIdResolver = std::function<std::string()>;

/// TLS 材料读取器：从 SEC 受控存储（framework-store）按 key 读取 PEM 文本。
/// 用于获取共享信任根（root_ca）与设备客户端证书链（device_cert_chain）。
/// 返回空字符串表示该 key 不存在或存储不可用（材料将判定为 NOT_READY）。
using TlsMaterialResolver = std::function<std::string(const std::string& key)>;

/// TlsCredentialProvider
///
/// SEC 服务端组件：统一管理 MQTT profile 的根 CA、客户端证书链与私钥能力。
/// 私钥仅以不可导出的 private_key_ref 表示，签名在 SEC/HSM 内完成。
/// private_key_ref 由进程内密钥（AES-256-GCM）保护，绑定 caller/profile/
/// credential/version/key_id/allowed_algorithms/boot_epoch/expiry；
/// SEC 重启（boot_epoch 变化）、版本变化、到期、撤销或 ACL 变化时旧引用立即失效。
class TlsCredentialProvider {
public:
    TlsCredentialProvider(HsmInterface* hsm,
                          DeviceKeyIdResolver key_id_resolver,
                          TlsMaterialResolver material_resolver,
                          TlsCredentialNotifyCallback notify = {});
    ~TlsCredentialProvider();

    TlsCredentialProvider(const TlsCredentialProvider&) = delete;
    TlsCredentialProvider& operator=(const TlsCredentialProvider&) = delete;

    /// 配置一个 profile
    void configureProfile(const TlsProfileConfig& config);

    /// 加载并校验 profile 材料 -> 设置状态 READY/NOT_READY/ERROR
    /// 校验：DER/PEM 可解析、链完整、叶子 EKU 含 clientAuth、证书有效期、
    ///       叶子公钥↔HSM 私钥匹配、根 CA 为 CA（允许 serverAuth 校验）。
    ErrorCode loadMaterials(const std::string& profile);

    /// ACL：调用方是否被授权访问该 profile
    /// fail-closed：peer 无效或 service_name 不匹配均返回 false
    bool isAuthorized(const std::string& profile, const PeerIdentity& peer) const;

    /// 获取完整凭据 bundle（含 root CA、客户端证书链、opaque private_key_ref）
    /// 仅为 READY 状态返回 bundle；private_key_ref 绑定当前调用方
    ErrorCode getTlsCredential(const std::string& profile,
                               const PeerIdentity& caller,
                               TlsCredentialBundle& bundle);

    /// 查询凭据状态摘要（不含凭据内容）
    ErrorCode getTlsCredentialState(const std::string& profile,
                                    TlsCredentialState& state) const;

    /// 远程 TLS 签名
    /// 校验调用方身份、引用完整性（解密）、版本、生命周期、算法、digest 长度、用途后
    /// 调用 HSM/SE sign_digest。禁止自动重放。
    ErrorCode signTls(const TlsSignRequest& request,
                      const PeerIdentity& caller,
                      std::vector<uint8_t>& signature);

    /// 轮换凭据：重新加载材料，version 单调递增，发布 changed 事件
    ErrorCode rotateCredential(const std::string& profile);

    /// 撤销凭据：状态置 REVOKED，version 递增，发布 changed 事件，拒绝后续签名
    ErrorCode revokeCredential(const std::string& profile);

    /// 查询 profile 当前状态
    TlsCredentialStatus getStatus(const std::string& profile) const;

    /// 当前 boot_epoch（SEC 重启后变化，使旧引用失效）
    uint64_t bootEpoch() const;

private:
    struct ProfileState {
        TlsProfileConfig config;
        TlsCredentialStatus status = TlsCredentialStatus::NOT_READY;
        uint64_t version = 0;
        int32_t reason_code = 0;
        std::vector<uint8_t> root_ca_bundle_der;     ///< 已合并为 DER bundle
        std::vector<uint8_t> client_cert_chain_der;  ///< leaf -> intermediate
        int64_t not_before = 0;
        int64_t not_after = 0;
        KeyAlgorithm key_algorithm = KeyAlgorithm::ECDSA_P256;
    };

    HsmInterface* hsm_;
    DeviceKeyIdResolver key_id_resolver_;
    TlsCredentialNotifyCallback notify_;
    TlsMaterialResolver material_resolver_;

    mutable std::mutex mutex_;
    std::map<std::string, ProfileState> profiles_;

    // 进程内密钥与 boot epoch（构造时生成，进程重启即变化）
    std::vector<uint8_t> process_key_;  // 32 bytes (AES-256)
    uint64_t boot_epoch_;

    // ---- private_key_ref 编解码 ----
    // 序列化字段 + AES-256-GCM 加密 -> OpaqueKeyRef
    struct RefPayload {
        std::string caller_service;
        std::string profile;
        std::string credential_id;
        uint64_t version = 0;
        std::string key_id;
        std::vector<SignatureAlgorithm> allowed_algorithms;
        uint64_t boot_epoch = 0;
        int64_t expiry = 0;  // unix epoch 秒
    };

    OpaqueKeyRef encodeRef(const RefPayload& payload);
    bool decodeRef(const OpaqueKeyRef& ref, RefPayload& payload);

    // ---- 内部校验 ----
    ErrorCode validateAndStoreMaterials(ProfileState& ps);
    bool algorithmAllowed(const ProfileState& ps, SignatureAlgorithm alg) const;
    void publishChanged(const std::string& profile, ProfileState& ps,
                        TlsCredentialStatus status, int32_t reason_code);
    ProfileState* findProfile(const std::string& profile);
    const ProfileState* findProfile(const std::string& profile) const;

    // 生成 32 字节随机进程密钥
    static std::vector<uint8_t> generateProcessKey();
    static uint64_t generateBootEpoch();
    // SHA-256 摘要前 8 字节十六进制（用于 credential_id_hash 日志）
    static std::string hashId(const std::string& id);
};

} // namespace sec
} // namespace tbox
