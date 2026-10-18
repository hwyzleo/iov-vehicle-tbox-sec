#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include "error_codes.h"

namespace tbox {
namespace sec {

enum class KeyStorageMode {
    HSM,        // HSM/SE 模式，私钥不出件（量产默认）
    SOFT_FILE   // 软件落盘模式，私钥加密存储到磁盘（仅测试）
};

struct KeyPair {
    std::string key_id;
    std::string algorithm;
    std::vector<uint8_t> public_key;
    bool private_key_exists;
    KeyStorageMode storage_mode = KeyStorageMode::HSM;  // 新增：存储模式
    bool exportable = false;                             // 新增：是否可导出
    std::chrono::system_clock::time_point created_at;
};

class HsmInterface {
public:
    virtual ~HsmInterface() = default;

    virtual ErrorCode initialize() = 0;

    virtual ErrorCode generate_key_pair(const std::string& key_id,
                                       const std::string& algorithm,
                                       KeyPair& key_pair) = 0;

    virtual ErrorCode sign(const std::string& key_id,
                          const std::vector<uint8_t>& data,
                          std::vector<uint8_t>& signature) = 0;

    /// 对预计算摘要直接进行 ECDSA 签名（不再二次哈希）。
    /// 用于 TLS CertificateVerify：调用方（OpenSSL adapter）已计算 transcript digest，
    /// SEC/HSM 仅对该 digest 做 ECDSA。
    /// 默认返回 NOT_IMPLEMENTED，由支持 TLS 的 HSM 实现覆写。
    virtual ErrorCode sign_digest(const std::string& key_id,
                                  const std::vector<uint8_t>& digest,
                                  std::vector<uint8_t>& signature) {
        (void)key_id;
        (void)digest;
        (void)signature;
        return ErrorCode::NOT_IMPLEMENTED;
    }

    /// ECIES / ECDH-ES + AES-256-GCM 解封装（TBOX-SEC-DSN-CR-019 §4）。
    ///
    /// @deprecated TBOX-SEC-DSN-CR-020：以 `unwrap_ecdh_es_v1` 取代（salt/info 与
    /// tag 语义更严格）。数值/接口保留以兼容旧调用点。
    ///
    /// 使用 recipient_key_id 对应的 EC 私钥与 ephemeral_public_key 执行 ECDH，
    /// 经 HKDF-SHA256（info = aad）派生 KEK，再以 AES-256-GCM 解密
    /// ciphertext_and_tag（tag 16B 追加于密文后）。明文仅短暂存在于 HSM 内部，
    /// 由调用方立即使用并清零。
    /// 默认返回 NOT_IMPLEMENTED（硬件 HSM provider 由设备集成实现）。
    virtual ErrorCode unwrap_ecdh_es(const std::string& recipient_key_id,
                                     const std::vector<uint8_t>& ephemeral_public_key,
                                     const std::vector<uint8_t>& iv,
                                     const std::vector<uint8_t>& ciphertext_and_tag,
                                     const std::vector<uint8_t>& aad,
                                     std::vector<uint8_t>& plaintext) {
        (void)recipient_key_id;
        (void)ephemeral_public_key;
        (void)iv;
        (void)ciphertext_and_tag;
        (void)aad;
        (void)plaintext;
        return ErrorCode::NOT_IMPLEMENTED;
    }

    /// ECDH-ES P-256 v1 解封原语（TBOX-SEC-DSN-CR-020 §8）。
    ///
    ///   Z     = ECDH(recipient_key_id, server_ephemeral_public_key)
    ///   KEK   = HKDF-SHA256(ikm = Z, salt = hkdf_salt, info = hkdf_info, L = 32)
    ///   plain = AES-256-GCM-Decrypt(KEK, nonce, ciphertext, authentication_tag, AAD)
    ///
    /// ciphertext 与 authentication_tag 分离；明文仅短暂存在于 HSM 内部，
    /// 由调用方立即使用并清零。默认返回 NOT_IMPLEMENTED（真实 HSM 由设备集成实现）。
    virtual ErrorCode unwrap_ecdh_es_v1(const std::string& recipient_key_id,
                                        const std::vector<uint8_t>& server_ephemeral_public_key,
                                        const std::vector<uint8_t>& hkdf_salt,
                                        const std::vector<uint8_t>& hkdf_info,
                                        const std::vector<uint8_t>& nonce,
                                        const std::vector<uint8_t>& ciphertext,
                                        const std::vector<uint8_t>& authentication_tag,
                                        const std::vector<uint8_t>& aad,
                                        std::vector<uint8_t>& plaintext) {
        (void)recipient_key_id;
        (void)server_ephemeral_public_key;
        (void)hkdf_salt;
        (void)hkdf_info;
        (void)nonce;
        (void)ciphertext;
        (void)authentication_tag;
        (void)aad;
        (void)plaintext;
        return ErrorCode::NOT_IMPLEMENTED;
    }

    /// 指定私钥是否具备 P-256 ECDH derive 能力（US-016 / readiness）。
    /// 默认 false（fail-closed）；真实 HSM 由设备集成实现。
    virtual bool supports_ecdh_derive(const std::string& key_id) {
        (void)key_id;
        return false;
    }

    virtual ErrorCode verify(const std::string& key_id,
                            const std::vector<uint8_t>& data,
                            const std::vector<uint8_t>& signature,
                            bool& valid) = 0;

    virtual ErrorCode export_public_key(const std::string& key_id,
                                       std::vector<uint8_t>& public_key) = 0;

    virtual ErrorCode export_private_key(const std::string& key_id,
                                         std::vector<uint8_t>& private_key) {
        (void)key_id;
        (void)private_key;
        return ErrorCode::NOT_IMPLEMENTED;
    }

    virtual bool key_exists(const std::string& key_id) = 0;

    virtual ErrorCode delete_key(const std::string& key_id) = 0;

    virtual std::string get_status() const = 0;
};

class HsmFactory {
public:
    enum class HsmType {
        SOFTWARE,    // 内存中的软件 HSM
        SOFT_FILE,   // 软件落盘 HSM（新增）
        PKCS11,      // PKCS#11 HSM
        TRUSTZONE    // TrustZone HSM
    };

    static std::unique_ptr<HsmInterface> create(HsmType type,
                                               const std::string& config_path = "",
                                               const std::string& store_root = "",
                                               const std::string& enc_key_path = "");
};

} // namespace sec
} // namespace tbox
