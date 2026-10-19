#include "soft_file_hsm.h"
#include "constants.h"
#include "sec_log_adapter.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <chrono>
#include <cstring>
#include <iostream>

namespace tbox {
namespace sec {

namespace fs = std::filesystem;

static constexpr int AES_GCM_IV_SIZE = 12;
static constexpr int AES_GCM_TAG_SIZE = 16;
static constexpr int ENCRYPTION_KEY_SIZE = 32;

// HKDF-SHA256（Extract + Expand），避免依赖 OpenSSL 版本化的 HKDF API。
static void hkdf_sha256(const std::vector<uint8_t>& ikm,
                        const std::vector<uint8_t>& salt,
                        const std::vector<uint8_t>& info,
                        uint8_t* out, size_t out_len) {
    uint8_t prk[SHA256_DIGEST_LENGTH];
    {
        unsigned int prk_len = 0;
        const uint8_t zeros[SHA256_DIGEST_LENGTH] = {0};
        const uint8_t* salt_ptr = salt.empty() ? zeros : salt.data();
        size_t salt_len = salt.empty() ? SHA256_DIGEST_LENGTH : salt.size();
        HMAC(EVP_sha256(), salt_ptr, static_cast<int>(salt_len),
             ikm.data(), ikm.size(), prk, &prk_len);
    }

    std::vector<uint8_t> t;
    size_t pos = 0;
    uint8_t counter = 1;
    while (pos < out_len) {
        std::vector<uint8_t> data;
        data.reserve(t.size() + info.size() + 1);
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(counter);
        unsigned int n = 0;
        uint8_t block[SHA256_DIGEST_LENGTH];
        HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH,
             data.data(), data.size(), block, &n);
        size_t take = std::min<size_t>(n, out_len - pos);
        std::memcpy(out + pos, block, take);
        pos += take;
        t.assign(block, block + n);
        ++counter;
    }
    OPENSSL_cleanse(prk, sizeof(prk));
}

SoftFileHsm::SoftFileHsm(hwyz::store::Store store,
                         const std::string& encryption_algo,
                         const std::string& encryption_key_path)
    : store_(std::move(store)),
      encryption_algo_(encryption_algo),
      encryption_key_path_(encryption_key_path) {}

SoftFileHsm::~SoftFileHsm() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, kd] : keys_) {
        secure_zero(kd.priv);
    }
    secure_zero(encryption_key_);
}

ErrorCode SoftFileHsm::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (fs::exists(encryption_key_path_)) {
        auto rc = load_encryption_key();
        if (rc != ErrorCode::SUCCESS) return rc;
    } else {
        auto rc = generate_encryption_key();
        if (rc != ErrorCode::SUCCESS) return rc;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::generate_key_pair(const std::string& key_id,
                                         const std::string& algorithm,
                                         KeyPair& key_pair) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    if (keys_.find(key_id) != keys_.end()) {
        return ErrorCode::KEY_ALREADY_EXISTS;
    }

    KeyData kd;
    kd.algorithm = algorithm;
    kd.created_at = std::chrono::system_clock::now();

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::KEY_GENERATION_FAILED;

    if (!EC_KEY_generate_key(ec)) {
        EC_KEY_free(ec);
        return ErrorCode::KEY_GENERATION_FAILED;
    }

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const EC_POINT* pub = EC_KEY_get0_public_key(ec);
    size_t len = EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
    kd.pub.resize(len);
    EC_POINT_point2oct(group, pub, POINT_CONVERSION_UNCOMPRESSED, kd.pub.data(), len, nullptr);

    const BIGNUM* priv = EC_KEY_get0_private_key(ec);
    int priv_len = BN_num_bytes(priv);
    kd.priv.resize(priv_len);
    BN_bn2bin(priv, kd.priv.data());

    EC_KEY_free(ec);

    auto rc = save_key_to_store(key_id, kd);
    if (rc != ErrorCode::SUCCESS) {
        secure_zero(kd.priv);
        return rc;
    }

    key_pair.key_id = key_id;
    key_pair.algorithm = algorithm;
    key_pair.public_key = kd.pub;
    key_pair.private_key_exists = true;
    key_pair.storage_mode = KeyStorageMode::SOFT_FILE;
    // TBOX-SEC-DSN-CR-015 §8：软 HSM 密钥私钥不可导出（即使测试/开发模式）
    key_pair.exportable = false;
    key_pair.created_at = kd.created_at;

    keys_[key_id] = std::move(kd);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::sign(const std::string& key_id,
                            const std::vector<uint8_t>& data,
                            std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::HSM_SIGN_FAILED;

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
    if (EC_POINT_oct2point(group, pt, it->second.pub.data(), it->second.pub.size(), nullptr) != 1) {
        EC_POINT_free(pt);
        EC_KEY_free(ec);
        return ErrorCode::HSM_KEY_GENERATION_FAILED;
    }
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);

    BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                 static_cast<int>(it->second.priv.size()), nullptr);
    if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
    EC_KEY_set_private_key(ec, priv_bn);
    BN_free(priv_bn);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    unsigned int sig_len = ECDSA_size(ec);
    signature.resize(sig_len);
    if (ECDSA_sign(0, digest, SHA256_DIGEST_LENGTH, signature.data(), &sig_len, ec) != 1) {
        EC_KEY_free(ec);
        return ErrorCode::HSM_SIGN_FAILED;
    }
    signature.resize(sig_len);
    EC_KEY_free(ec);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::sign_digest(const std::string& key_id,
                                   const std::vector<uint8_t>& digest,
                                   std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }
    // TLS ecdsa_secp256r1_sha256 期望 32 字节 SHA-256 摘要
    if (digest.size() != SHA256_DIGEST_LENGTH) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::HSM_SIGN_FAILED;

    BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                 static_cast<int>(it->second.priv.size()), nullptr);
    if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
    EC_KEY_set_private_key(ec, priv_bn);
    BN_free(priv_bn);

    // 直接对传入 digest 做 ECDSA，不再二次哈希
    unsigned int sig_len = ECDSA_size(ec);
    signature.resize(sig_len);
    if (ECDSA_sign(0, digest.data(), static_cast<int>(digest.size()),
                   signature.data(), &sig_len, ec) != 1) {
        EC_KEY_free(ec);
        return ErrorCode::HSM_SIGN_FAILED;
    }
    signature.resize(sig_len);
    EC_KEY_free(ec);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::sign_digest_p1363(const std::string& key_id,
                                         const std::vector<uint8_t>& digest,
                                         std::vector<uint8_t>& signature) {
    std::lock_guard<std::mutex> lock(mutex_);
    signature.clear();

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }
    // Import Attestation 固定 SHA-256 摘要（32 字节），不参与算法协商。
    if (digest.size() != SHA256_DIGEST_LENGTH) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::HSM_SIGN_FAILED;

    BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                 static_cast<int>(it->second.priv.size()), nullptr);
    if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }
    EC_KEY_set_private_key(ec, priv_bn);
    BN_free(priv_bn);

    // 原生 raw r/s（芯片只返回 DER 时由各自 Provider Adapter 内部转换）。
    ECDSA_SIG* sig = ECDSA_do_sign(digest.data(), static_cast<int>(digest.size()), ec);
    if (!sig) { EC_KEY_free(ec); return ErrorCode::HSM_SIGN_FAILED; }

    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const BIGNUM* order = group ? EC_GROUP_get0_order(group) : nullptr;
    if (r == nullptr || s == nullptr || order == nullptr || BN_is_negative(r) ||
        BN_is_negative(s) || BN_is_zero(r) || BN_is_zero(s) || BN_cmp(r, order) >= 0 ||
        BN_cmp(s, order) >= 0) {
        ECDSA_SIG_free(sig);
        EC_KEY_free(ec);
        return ErrorCode::HSM_SIGN_FAILED;
    }

    // low-S 归一化：s' = min(s, n - s)。
    BIGNUM* s_norm = BN_dup(s);
    BIGNUM* half = BN_new();
    if (!s_norm || !half) {
        BN_free(s_norm);
        BN_free(half);
        ECDSA_SIG_free(sig);
        EC_KEY_free(ec);
        return ErrorCode::HSM_SIGN_FAILED;
    }
    BN_rshift1(half, order);  // floor(n/2)
    if (BN_cmp(s_norm, half) > 0) {
        BIGNUM* s_alt = BN_new();
        BN_sub(s_alt, order, s_norm);
        BN_free(s_norm);
        s_norm = s_alt;
    }

    signature.assign(2 * 32, 0);
    if (BN_bn2binpad(r, signature.data(), 32) != 32 ||
        BN_bn2binpad(s_norm, signature.data() + 32, 32) != 32) {
        BN_free(s_norm);
        BN_free(half);
        ECDSA_SIG_free(sig);
        EC_KEY_free(ec);
        signature.clear();
        return ErrorCode::HSM_SIGN_FAILED;
    }
    BN_free(s_norm);
    BN_free(half);
    ECDSA_SIG_free(sig);
    EC_KEY_free(ec);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::unwrap_ecdh_es(const std::string& recipient_key_id,
                                       const std::vector<uint8_t>& ephemeral_public_key,
                                       const std::vector<uint8_t>& iv,
                                       const std::vector<uint8_t>& ciphertext_and_tag,
                                       const std::vector<uint8_t>& aad,
                                       std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(recipient_key_id)) return ErrorCode::INVALID_PARAMETER;
    if (ephemeral_public_key.empty() || iv.size() != AES_GCM_IV_SIZE ||
        ciphertext_and_tag.size() < AES_GCM_TAG_SIZE) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(recipient_key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(recipient_key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[recipient_key_id] = std::move(kd);
        it = keys_.find(recipient_key_id);
    }

    const EC_GROUP* group = nullptr;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::WRAPPED_KEY_INVALID;
    group = EC_KEY_get0_group(ec);

    EC_POINT* pub_pt = EC_POINT_new(group);
    if (!pub_pt || EC_POINT_oct2point(group, pub_pt, it->second.pub.data(),
                                      it->second.pub.size(), nullptr) != 1) {
        if (pub_pt) EC_POINT_free(pub_pt);
        EC_KEY_free(ec);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }
    EC_KEY_set_public_key(ec, pub_pt);
    EC_POINT_free(pub_pt);

    BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                static_cast<int>(it->second.priv.size()), nullptr);
    if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::WRAPPED_KEY_INVALID; }
    EC_KEY_set_private_key(ec, priv_bn);
    BN_free(priv_bn);

    EC_POINT* eph_pt = EC_POINT_new(group);
    if (!eph_pt || EC_POINT_oct2point(group, eph_pt, ephemeral_public_key.data(),
                                      ephemeral_public_key.size(), nullptr) != 1) {
        if (eph_pt) EC_POINT_free(eph_pt);
        EC_KEY_free(ec);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }

    std::vector<uint8_t> shared(ENCRYPTION_KEY_SIZE);
    int shared_len = ECDH_compute_key(shared.data(), shared.size(), eph_pt, ec, nullptr);
    EC_POINT_free(eph_pt);
    EC_KEY_free(ec);
    if (shared_len <= 0) {
        secure_zero(shared);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }
    shared.resize(static_cast<size_t>(shared_len));

    // KEK = HKDF-SHA256(ikm=shared, salt="", info=aad, L=32)
    uint8_t kek[ENCRYPTION_KEY_SIZE];
    std::vector<uint8_t> info = aad;
    hkdf_sha256(shared, {}, info, kek, sizeof(kek));
    secure_zero(shared);
    OPENSSL_cleanse(info.data(), info.size());

    const uint8_t* tag = ciphertext_and_tag.data() + ciphertext_and_tag.size() - AES_GCM_TAG_SIZE;
    const uint8_t* ct = ciphertext_and_tag.data();
    int ct_len = static_cast<int>(ciphertext_and_tag.size() - AES_GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { OPENSSL_cleanse(kek, sizeof(kek)); return ErrorCode::INTERNAL_ERROR; }

    bool ok = true;
    int out_len = 0;
    int total = 0;
    plaintext.assign(static_cast<size_t>(ct_len), 0);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, kek, iv.data()) != 1) ok = false;
    if (ok && !aad.empty() &&
        EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) ok = false;
    if (ok && ct_len > 0 &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ct, ct_len) != 1) ok = false;
    total = out_len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                                  const_cast<uint8_t*>(tag)) != 1) ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &out_len) != 1) ok = false;
    total += out_len;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(kek, sizeof(kek));

    if (!ok) {
        secure_zero(plaintext);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }
    plaintext.resize(static_cast<size_t>(total));
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::unwrap_ecdh_es_v1(
    const std::string& recipient_key_id,
    const std::vector<uint8_t>& server_ephemeral_public_key,
    const std::vector<uint8_t>& hkdf_salt,
    const std::vector<uint8_t>& hkdf_info,
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& authentication_tag,
    const std::vector<uint8_t>& aad,
    std::vector<uint8_t>& plaintext) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(recipient_key_id)) return ErrorCode::INVALID_PARAMETER;
    if (server_ephemeral_public_key.size() != 65 ||
        nonce.size() != AES_GCM_IV_SIZE ||
        authentication_tag.size() != AES_GCM_TAG_SIZE ||
        hkdf_salt.size() != 32) {
        return ErrorCode::WRAPPED_KEY_INVALID;
    }

    auto it = keys_.find(recipient_key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(recipient_key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[recipient_key_id] = std::move(kd);
        it = keys_.find(recipient_key_id);
    }

    const EC_GROUP* group = nullptr;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::WRAPPED_KEY_INVALID;
    group = EC_KEY_get0_group(ec);

    EC_POINT* pub_pt = EC_POINT_new(group);
    if (!pub_pt || EC_POINT_oct2point(group, pub_pt, it->second.pub.data(),
                                      it->second.pub.size(), nullptr) != 1) {
        if (pub_pt) EC_POINT_free(pub_pt);
        EC_KEY_free(ec);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }
    EC_KEY_set_public_key(ec, pub_pt);
    EC_POINT_free(pub_pt);

    BIGNUM* priv_bn = BN_bin2bn(it->second.priv.data(),
                                static_cast<int>(it->second.priv.size()), nullptr);
    if (!priv_bn) { EC_KEY_free(ec); return ErrorCode::WRAPPED_KEY_INVALID; }
    EC_KEY_set_private_key(ec, priv_bn);
    BN_free(priv_bn);

    EC_POINT* eph_pt = EC_POINT_new(group);
    if (!eph_pt || EC_POINT_oct2point(group, eph_pt, server_ephemeral_public_key.data(),
                                      server_ephemeral_public_key.size(), nullptr) != 1 ||
        EC_POINT_is_at_infinity(group, eph_pt) ||
        EC_POINT_is_on_curve(group, eph_pt, nullptr) != 1) {
        if (eph_pt) EC_POINT_free(eph_pt);
        EC_KEY_free(ec);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }

    std::vector<uint8_t> shared(ENCRYPTION_KEY_SIZE);
    int shared_len = ECDH_compute_key(shared.data(), shared.size(), eph_pt, ec, nullptr);
    EC_POINT_free(eph_pt);
    EC_KEY_free(ec);
    if (shared_len <= 0) {
        secure_zero(shared);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }
    shared.resize(static_cast<size_t>(shared_len));

    // KEK = HKDF-SHA256(ikm = Z, salt = hkdf_salt, info = hkdf_info, L = 32)
    uint8_t kek[ENCRYPTION_KEY_SIZE];
    hkdf_sha256(shared, hkdf_salt, hkdf_info, kek, sizeof(kek));
    secure_zero(shared);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { OPENSSL_cleanse(kek, sizeof(kek)); return ErrorCode::INTERNAL_ERROR; }

    bool ok = true;
    int out_len = 0, total = 0;
    plaintext.assign(ciphertext.size(), 0);
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, kek, nonce.data()) != 1) ok = false;
    if (ok && !aad.empty() &&
        EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1)
        ok = false;
    if (ok && !ciphertext.empty() &&
        EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1)
        ok = false;
    total = out_len;
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                                  const_cast<uint8_t*>(authentication_tag.data())) != 1)
        ok = false;
    if (ok && EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &out_len) != 1) ok = false;
    total += out_len;
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(kek, sizeof(kek));

    if (!ok) {
        secure_zero(plaintext);
        return ErrorCode::WRAPPED_KEY_INVALID;
    }
    plaintext.resize(static_cast<size_t>(total));
    return ErrorCode::SUCCESS;
}

bool SoftFileHsm::supports_ecdh_derive(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_valid_key_id(key_id)) return false;
    if (keys_.find(key_id) != keys_.end()) return true;
    KeyData kd;
    return load_key_from_store(key_id, kd) == ErrorCode::SUCCESS;
}

bool SoftFileHsm::supports_ecdsa_sign(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_valid_key_id(key_id)) return false;
    if (keys_.find(key_id) != keys_.end()) return true;
    KeyData kd;
    return load_key_from_store(key_id, kd) == ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::verify(const std::string& key_id,
                              const std::vector<uint8_t>& data,
                              const std::vector<uint8_t>& signature,
                              bool& valid) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return ErrorCode::HSM_VERIFICATION_FAILED;

    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) { EC_KEY_free(ec); return ErrorCode::HSM_VERIFICATION_FAILED; }
    if (EC_POINT_oct2point(group, pt, it->second.pub.data(), it->second.pub.size(), nullptr) != 1) {
        EC_POINT_free(pt);
        EC_KEY_free(ec);
        return ErrorCode::HSM_KEY_GENERATION_FAILED;
    }
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);

    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), digest);

    int result = ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH,
                              signature.data(), static_cast<int>(signature.size()), ec);
    EC_KEY_free(ec);

    valid = (result == 1);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::export_public_key(const std::string& key_id,
                                         std::vector<uint8_t>& public_key) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it == keys_.end()) {
        KeyData kd;
        auto rc = load_key_from_store(key_id, kd);
        if (rc != ErrorCode::SUCCESS) return rc;
        keys_[key_id] = std::move(kd);
        it = keys_.find(key_id);
    }

    public_key = it->second.pub;
    return ErrorCode::SUCCESS;
}

bool SoftFileHsm::key_exists(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!is_valid_key_id(key_id)) return false;
    if (keys_.find(key_id) != keys_.end()) return true;

    try {
        return store_.has("key_metadata_" + key_id);
    } catch (const hwyz::store::StoreException& e) {
        return false;
    }
}

ErrorCode SoftFileHsm::delete_key(const std::string& key_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!is_valid_key_id(key_id)) {
        return ErrorCode::INVALID_PARAMETER;
    }

    auto it = keys_.find(key_id);
    if (it != keys_.end()) {
        secure_zero(it->second.priv);
        keys_.erase(it);
    }

    try {
        store_.remove("encrypted_private_key_" + key_id);
        store_.remove("key_metadata_" + key_id);
    } catch (const hwyz::store::StoreException& e) {
        SecLogAdapter::service().error(
            "sec.hsm.soft_key_delete_failed", "从 store 删除密钥失败",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_id)},
             {"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        return ErrorCode::STORAGE_WRITE_FAILED;
    }

    return ErrorCode::SUCCESS;
}

std::string SoftFileHsm::get_status() const {
    return "SoftFile HSM (store, algo=" + encryption_algo_ + ")";
}

ErrorCode SoftFileHsm::export_private_key(const std::string& key_id,
                                          std::vector<uint8_t>& private_key) {
    // TBOX-SEC-DSN-CR-015 §8：API 不提供导出私钥明文能力（软 HSM 亦不例外）。
    // 私钥只存在于加密 at-rest 存储中，仅 HSM 内部可用于签名。
    (void)key_id;
    (void)private_key;
    SecLogAdapter::service().warn(
        "sec.hsm.soft_export_denied", "软件 HSM 不允许导出私钥明文（fail-closed）");
    return ErrorCode::NOT_IMPLEMENTED;
}

ErrorCode SoftFileHsm::save_key_to_store(const std::string& key_id, const KeyData& key_data) {
    try {
        // 1. Encrypt private key first
        std::vector<uint8_t> encrypted_key;
        auto rc = encrypt_private_key(key_data.priv, encrypted_key);
        if (rc != ErrorCode::SUCCESS) {
            return rc;
        }

        // 2. Save encrypted key first (leaf data)
        store_.save("encrypted_private_key_" + key_id, bytes_to_hex(encrypted_key));

        // 3. Save metadata last (commit marker)
        nlohmann::json metadata;
        metadata["key_id"] = key_id;
        metadata["algorithm"] = key_data.algorithm;
        metadata["created_at"] = std::chrono::duration_cast<std::chrono::seconds>(
            key_data.created_at.time_since_epoch()).count();
        metadata["public_key"] = bytes_to_hex(key_data.pub);
        store_.save("key_metadata_" + key_id, metadata.dump());

        return ErrorCode::SUCCESS;
    } catch (const hwyz::store::StoreException& e) {
        SecLogAdapter::service().error(
            "sec.hsm.soft_key_save_failed", "保存密钥到 store 失败",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_id)},
             {"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        return ErrorCode::STORAGE_WRITE_FAILED;
    }
}

ErrorCode SoftFileHsm::load_key_from_store(const std::string& key_id, KeyData& key_data) {
    try {
        if (!store_.has("key_metadata_" + key_id)) {
            return ErrorCode::KEY_NOT_FOUND;
        }

        std::string json_str = store_.load<std::string>("key_metadata_" + key_id);
        auto metadata = nlohmann::json::parse(json_str);

        key_data.algorithm = metadata.at("algorithm").get<std::string>();

        auto pub_hex = metadata.at("public_key").get<std::string>();
        key_data.pub = hex_to_bytes(pub_hex);

        auto enc_hex = store_.load<std::string>("encrypted_private_key_" + key_id);
        std::vector<uint8_t> encrypted_key = hex_to_bytes(enc_hex);

        auto rc = decrypt_private_key(encrypted_key, key_data.priv);
        if (rc != ErrorCode::SUCCESS) return rc;

        auto ts = metadata.at("created_at").get<int64_t>();
        key_data.created_at = std::chrono::system_clock::time_point(std::chrono::seconds(ts));

        return ErrorCode::SUCCESS;
    } catch (const hwyz::store::StoreException& e) {
        if (e.getError().code == hwyz::store::StoreError::kKeyNotFound) {
            return ErrorCode::KEY_NOT_FOUND;
        }
        SecLogAdapter::service().error(
            "sec.hsm.soft_key_load_failed", "从 store 加载密钥失败",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_id)},
             {"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        return ErrorCode::STORAGE_READ_FAILED;
    } catch (const std::exception& e) {
        SecLogAdapter::service().error(
            "sec.hsm.soft_key_parse_failed", "解析 store 中密钥失败",
            {{"key_id", tbox::fw::log::FieldValue::makeString(key_id)},
             {"reason", tbox::fw::log::FieldValue::makeString(e.what())}});
        return ErrorCode::STORAGE_CORRUPTION;
    }
}

ErrorCode SoftFileHsm::encrypt_private_key(const std::vector<uint8_t>& plain_key,
                                           std::vector<uint8_t>& encrypted_key) {
    if (encryption_key_.size() != ENCRYPTION_KEY_SIZE) return ErrorCode::INTERNAL_ERROR;

    std::vector<uint8_t> iv(AES_GCM_IV_SIZE);
    if (RAND_bytes(iv.data(), AES_GCM_IV_SIZE) != 1) return ErrorCode::INTERNAL_ERROR;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::INTERNAL_ERROR;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }

    std::vector<uint8_t> ciphertext(plain_key.size() + AES_GCM_TAG_SIZE);
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                          plain_key.data(), static_cast<int>(plain_key.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    int total = out_len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    total += out_len;

    std::vector<uint8_t> tag(AES_GCM_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    EVP_CIPHER_CTX_free(ctx);

    encrypted_key.clear();
    encrypted_key.insert(encrypted_key.end(), iv.begin(), iv.end());
    encrypted_key.insert(encrypted_key.end(), ciphertext.begin(), ciphertext.begin() + total);
    encrypted_key.insert(encrypted_key.end(), tag.begin(), tag.end());

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::decrypt_private_key(const std::vector<uint8_t>& encrypted_key,
                                           std::vector<uint8_t>& plain_key) {
    if (encryption_key_.size() != ENCRYPTION_KEY_SIZE) return ErrorCode::INTERNAL_ERROR;

    if (encrypted_key.size() < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        return ErrorCode::STORAGE_CORRUPTION;
    }

    const uint8_t* iv = encrypted_key.data();
    const uint8_t* tag = encrypted_key.data() + encrypted_key.size() - AES_GCM_TAG_SIZE;
    const uint8_t* ciphertext = encrypted_key.data() + AES_GCM_IV_SIZE;
    int ciphertext_len = static_cast<int>(encrypted_key.size() - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::INTERNAL_ERROR;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }

    plain_key.resize(ciphertext_len + AES_GCM_TAG_SIZE);
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, plain_key.data(), &out_len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }
    int total = out_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
                            const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::INTERNAL_ERROR;
    }

    if (EVP_DecryptFinal_ex(ctx, plain_key.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::STORAGE_CORRUPTION;
    }
    total += out_len;
    plain_key.resize(total);

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::generate_encryption_key() {
    encryption_key_.resize(ENCRYPTION_KEY_SIZE);
    if (RAND_bytes(encryption_key_.data(), ENCRYPTION_KEY_SIZE) != 1) {
        return ErrorCode::INTERNAL_ERROR;
    }

    fs::path p(encryption_key_path_);
    if (p.has_parent_path()) {
        std::error_code ec;
        fs::create_directories(p.parent_path(), ec);
    }

    std::ofstream ofs(encryption_key_path_, std::ios::binary);
    if (!ofs.is_open()) return ErrorCode::STORAGE_WRITE_FAILED;
    ofs.write(reinterpret_cast<const char*>(encryption_key_.data()), ENCRYPTION_KEY_SIZE);
    ofs.close();

    fs::permissions(encryption_key_path_,
                    fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace);

    return ErrorCode::SUCCESS;
}

ErrorCode SoftFileHsm::load_encryption_key() {
    std::ifstream ifs(encryption_key_path_, std::ios::binary);
    if (!ifs.is_open()) return ErrorCode::STORAGE_READ_FAILED;

    encryption_key_.resize(ENCRYPTION_KEY_SIZE);
    ifs.read(reinterpret_cast<char*>(encryption_key_.data()), ENCRYPTION_KEY_SIZE);
    if (ifs.gcount() != ENCRYPTION_KEY_SIZE) {
        encryption_key_.clear();
        return ErrorCode::STORAGE_CORRUPTION;
    }

    return ErrorCode::SUCCESS;
}

void SoftFileHsm::secure_zero(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

bool SoftFileHsm::is_valid_key_id(const std::string& key_id) const {
    return key_id.find("..") == std::string::npos &&
           key_id.find('/') == std::string::npos &&
           key_id.find('\\') == std::string::npos;
}

std::string SoftFileHsm::bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    hex.reserve(bytes.size() * 2);
    char buf[3];
    for (auto b : bytes) {
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

std::vector<uint8_t> SoftFileHsm::hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

} // namespace sec
} // namespace tbox
