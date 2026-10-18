//
// 非生产参考实现：ECDH-ES P-256 v1 信封封装（TBOX-SEC-DSN-CR-020 §7/§8）。
//
#include "keyprov_envelope_builder.h"

#include "business_key_envelope.h"
#include "proto/security/keyprov/v1/key_provisioning.pb.h"

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>

namespace tbox {
namespace sec {

namespace {

namespace kp = ::security::keyprov::v1;

constexpr int kNonceSize = 12;
constexpr int kTagSize = 16;
constexpr int kKekSize = 32;

void hkdf_sha256(const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& salt,
                 const std::vector<uint8_t>& info, uint8_t* out, size_t out_len) {
    uint8_t prk[SHA256_DIGEST_LENGTH];
    unsigned int prk_len = 0;
    const uint8_t zeros[SHA256_DIGEST_LENGTH] = {0};
    const uint8_t* salt_ptr = salt.empty() ? zeros : salt.data();
    size_t salt_len = salt.empty() ? SHA256_DIGEST_LENGTH : salt.size();
    HMAC(EVP_sha256(), salt_ptr, static_cast<int>(salt_len), ikm.data(), ikm.size(), prk,
         &prk_len);

    std::vector<uint8_t> t;
    size_t pos = 0;
    uint8_t counter = 1;
    while (pos < out_len) {
        std::vector<uint8_t> data;
        data.insert(data.end(), t.begin(), t.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(counter);
        uint8_t block[SHA256_DIGEST_LENGTH];
        unsigned int n = 0;
        HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH, data.data(), data.size(), block, &n);
        size_t take = std::min<size_t>(n, out_len - pos);
        std::memcpy(out + pos, block, take);
        pos += take;
        t.assign(block, block + n);
        ++counter;
    }
    OPENSSL_cleanse(prk, sizeof(prk));
}

bool aes_gcm_encrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce,
                     const std::vector<uint8_t>& aad, const std::vector<uint8_t>& plain,
                     std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& tag) {
    if (key.size() != kKekSize || nonce.size() != kNonceSize) return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = true;
    int out_len = 0, total = 0;
    ciphertext.assign(plain.size(), 0);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) ok = false;
    if (ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) ok = false;
    if (ok && !aad.empty() &&
        EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1)
        ok = false;
    if (ok && !plain.empty() &&
        EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len, plain.data(),
                          static_cast<int>(plain.size())) != 1)
        ok = false;
    total = out_len;
    if (ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &out_len) != 1) ok = false;
    total += out_len;
    tag.assign(kTagSize, 0);
    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag.data()) != 1) ok = false;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    ciphertext.resize(static_cast<size_t>(total));
    return true;
}

bool derive_public_key(const std::vector<uint8_t>& priv, std::vector<uint8_t>& pub) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return false;
    BIGNUM* bn = BN_bin2bn(priv.data(), static_cast<int>(priv.size()), nullptr);
    if (!bn) { EC_GROUP_free(group); return false; }
    bool ok = false;
    EC_POINT* pt = EC_POINT_new(group);
    if (pt && EC_POINT_mul(group, pt, bn, nullptr, nullptr, nullptr) == 1) {
        pub.assign(65, 0);
        size_t n = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED, pub.data(),
                                      pub.size(), nullptr);
        if (n == 65) { pub.resize(n); ok = true; } else { pub.clear(); }
    }
    if (pt) EC_POINT_free(pt);
    BN_clear_free(bn);
    EC_GROUP_free(group);
    return ok;
}

bool ecdh_shared(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& peer_pub,
                 std::vector<uint8_t>& shared) {
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return false;
    EC_KEY* ec = EC_KEY_new();
    if (!ec) { EC_GROUP_free(group); return false; }
    bool ok = false;
    do {
        if (EC_KEY_set_group(ec, group) != 1) break;
        BIGNUM* bn = BN_bin2bn(priv.data(), static_cast<int>(priv.size()), nullptr);
        if (!bn) break;
        int r = EC_KEY_set_private_key(ec, bn);
        BN_clear_free(bn);
        if (r != 1) break;
        EC_POINT* peer = EC_POINT_new(group);
        if (!peer) break;
        int p = EC_POINT_oct2point(group, peer, peer_pub.data(), peer_pub.size(), nullptr);
        if (p != 1) { EC_POINT_free(peer); break; }
        shared.assign(32, 0);
        int len = ECDH_compute_key(shared.data(), shared.size(), peer, ec, nullptr);
        EC_POINT_free(peer);
        if (len <= 0) { shared.clear(); break; }
        shared.resize(static_cast<size_t>(len));
        ok = true;
    } while (false);
    EC_KEY_free(ec);
    EC_GROUP_free(group);
    return ok;
}

bool random_bytes(std::vector<uint8_t>& out, size_t n) {
    out.assign(n, 0);
    return RAND_bytes(out.data(), static_cast<int>(n)) == 1;
}

} // namespace

ErrorCode buildEcdhEsP256EnvelopeV1(const KeyprovEnvelopeInput& in, KeyprovEnvelopeOutput& out) {
    out = KeyprovEnvelopeOutput{};

    if (!isValidP256UncompressedPoint(in.device_public_key))
        return ErrorCode::INVALID_PARAMETER;
    if (in.request_id.empty() || in.key_id.empty() || in.business_domain.empty() ||
        in.purpose.empty())
        return ErrorCode::INVALID_PARAMETER;
    if (in.business_key.size() != 32) return ErrorCode::INVALID_PARAMETER;
    if (in.recipient_certificate_digest.size() != 32) return ErrorCode::INVALID_PARAMETER;
    if (in.business_key_version == 0) return ErrorCode::INVALID_PARAMETER;
    if (in.wrapping_suite != kWrappingSuiteEcdhEsP256) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    if (in.key_algorithm != kDefaultKeyAlgorithm) return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

    uint64_t suite_val = 0;
    if (!wrappingSuiteEnumValue(in.wrapping_suite, suite_val))
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;
    uint64_t purpose_val = 0;
    if (!purposeEnumValue(in.purpose, purpose_val))
        return ErrorCode::BUSINESS_KEY_UNSUPPORTED;

    // 临时密钥（测试可固定，保证 golden vector 字节级确定）。
    std::vector<uint8_t> eph_priv = in.server_ephemeral_private_key;
    if (eph_priv.empty()) {
        if (!random_bytes(eph_priv, 32)) return ErrorCode::INTERNAL_ERROR;
    } else if (eph_priv.size() != 32) {
        return ErrorCode::INVALID_PARAMETER;
    }
    std::vector<uint8_t> eph_pub;
    if (!derive_public_key(eph_priv, eph_pub)) return ErrorCode::INTERNAL_ERROR;
    out.server_ephemeral_public_key = eph_pub;

    std::vector<uint8_t> salt = in.hkdf_salt;
    if (salt.empty()) {
        if (!random_bytes(salt, 32)) return ErrorCode::INTERNAL_ERROR;
    } else if (salt.size() != 32) {
        return ErrorCode::INVALID_PARAMETER;
    }
    std::vector<uint8_t> nonce = in.nonce;
    if (nonce.empty()) {
        if (!random_bytes(nonce, kNonceSize)) return ErrorCode::INTERNAL_ERROR;
    } else if (nonce.size() != kNonceSize) {
        return ErrorCode::INVALID_PARAMETER;
    }

    // canonical AAD（FW-SEC EnvelopeAadV1 的 TBOX-SEC 解释）
    canonical::EnvelopeAadInput aad_in;
    aad_in.envelope_version = "v1";
    aad_in.wrapping_suite = suite_val;
    aad_in.request_id = in.request_id;
    aad_in.business_domain = in.business_domain;
    aad_in.purpose = purpose_val;
    aad_in.key_id = in.key_id;
    aad_in.business_key_version = in.business_key_version;
    aad_in.root_key_version = in.root_key_version;
    aad_in.derivation_version = in.derivation_version;
    aad_in.recipient_certificate_fingerprint = in.recipient_certificate_digest;
    std::vector<uint8_t> canonical_aad = canonical::buildEnvelopeAadV1(aad_in);
    out.canonical_aad = canonical_aad;
    out.aad_digest = canonical::computeAadDigest(canonical_aad);

    // HKDF info（FW-SEC §3.2 canonical info）
    std::string recipient_fp_hex = canonical::toHex(in.recipient_certificate_digest);
    std::string info = canonical::buildHkdfInfoV1(in.request_id, in.business_domain, in.purpose,
                                                  in.key_id, in.business_key_version,
                                                  recipient_fp_hex);
    out.hkdf_info.assign(info.begin(), info.end());

    // ECDH → HKDF → AES-256-GCM
    std::vector<uint8_t> shared;
    if (!ecdh_shared(eph_priv, in.device_public_key, shared)) {
        OPENSSL_cleanse(eph_priv.data(), eph_priv.size());
        return ErrorCode::INTERNAL_ERROR;
    }
    out.ecdh_shared_secret = shared;
    std::vector<uint8_t> kek(kKekSize, 0);
    hkdf_sha256(shared, salt, out.hkdf_info, kek.data(), kek.size());
    out.kek = kek;

    std::vector<uint8_t> ciphertext, tag;
    bool enc_ok = aes_gcm_encrypt(kek, nonce, canonical_aad, in.business_key, ciphertext, tag);
    OPENSSL_cleanse(eph_priv.data(), eph_priv.size());
    OPENSSL_cleanse(shared.data(), shared.size());
    OPENSSL_cleanse(kek.data(), kek.size());
    if (!enc_ok) return ErrorCode::INTERNAL_ERROR;
    out.wrapped_key = ciphertext;
    out.authentication_tag = tag;
    out.key_check_value = canonical::computeKcv(in.business_key);

    // deterministic protobuf parameters
    kp::EcdhEsP256EnvelopeParametersV1 msg;
    msg.set_format_version(1);
    msg.set_server_ephemeral_public_key(eph_pub.data(), eph_pub.size());
    msg.set_hkdf_salt(salt.data(), salt.size());
    msg.set_hkdf_context_version(in.hkdf_context_version);
    msg.set_nonce(nonce.data(), nonce.size());
    msg.set_authentication_tag(tag.data(), tag.size());
    msg.set_canonical_aad(canonical_aad.data(), canonical_aad.size());
    msg.set_aad_digest(out.aad_digest.data(), out.aad_digest.size());
    msg.set_root_key_version(in.root_key_version);
    msg.set_derivation_version(in.derivation_version);
    msg.set_recipient_certificate_digest(in.recipient_certificate_digest.data(),
                                         in.recipient_certificate_digest.size());
    msg.set_operation_id(in.operation_id);
    std::string params_bytes;
    if (!msg.SerializeToString(&params_bytes)) return ErrorCode::INTERNAL_ERROR;
    out.parameters.assign(params_bytes.begin(), params_bytes.end());

    // envelopeDigest（以原始 wrappedKey + parameters）
    canonical::EnvelopeDigestInput di;
    di.envelope_format = static_cast<uint64_t>(KeyEnvelopeFormat::ECDH_ES_P256_V1);
    di.request_id = in.request_id;
    di.business_domain = in.business_domain;
    di.purpose = purpose_val;
    di.key_id = in.key_id;
    di.business_key_version = in.business_key_version;
    di.wrapping_suite = suite_val;
    di.wrapped_key = out.wrapped_key;
    di.parameters = out.parameters;
    out.envelope_digest = canonical::computeEnvelopeDigest(di);

    // proofInput
    canonical::ProofInput pi;
    pi.request_id = in.request_id;
    pi.business_domain = in.business_domain;
    pi.purpose = purpose_val;
    pi.key_id = in.key_id;
    pi.business_key_version = in.business_key_version;
    pi.envelope_digest = out.envelope_digest;
    pi.key_check_value.assign(out.key_check_value.begin(), out.key_check_value.end());
    out.proof_input = canonical::buildProofInput(pi);

    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox
