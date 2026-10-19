//
// CanonicalEncodingV1 单元测试（TBOX-SEC-DSN-CR-020 §6/§7 / US-018/020）。
//
// 含 golden vector 交叉校验：期望值由独立 Python 参考实现
// （tests/fixtures/gen_keyprov_ecdh_es_v1_vector.py）生成，C++ 侧不得自证。
//
#include <gtest/gtest.h>

#include "canonical_encoding.h"
#include "business_key_envelope.h"
#include "tbox/sec/business_key.h"

#include <nlohmann/json.hpp>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <fstream>
#include <string>
#include <vector>

using namespace tbox::sec;

namespace {

nlohmann::json load_fixture() {
    std::ifstream ifs(std::string(SEC_TEST_FIXTURE_DIR) + "/keyprov_ecdh_es_v1_vector.json");
    EXPECT_TRUE(ifs.is_open());
    nlohmann::json j;
    ifs >> j;
    return j;
}

std::vector<uint8_t> hx(const std::string& s) {
    std::vector<uint8_t> out;
    EXPECT_TRUE(canonical::hexToBytes(s, out));
    return out;
}

/// 用设备公钥验证 P1363 proof（恒 64B、low-S）对给定 proofInput 的签名。
bool verify_p1363_proof(const std::vector<uint8_t>& device_pub,
                        const std::vector<uint8_t>& proof_input,
                        const std::vector<uint8_t>& proof) {
    if (proof.size() != 64) return false;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) return false;
    bool ok = false;
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (pt && EC_POINT_oct2point(group, pt, device_pub.data(), device_pub.size(),
                                 nullptr) == 1) {
        EC_KEY_set_public_key(ec, pt);
        BIGNUM* s_bn = BN_bin2bn(proof.data() + 32, 32, nullptr);
        BIGNUM* half = BN_new();
        BN_rshift1(half, EC_GROUP_get0_order(group));
        const bool low_s = BN_cmp(s_bn, half) <= 0;
        ECDSA_SIG* sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(sig, BN_bin2bn(proof.data(), 32, nullptr),
                       BN_bin2bn(proof.data() + 32, 32, nullptr));
        unsigned char* der = nullptr;
        int der_len = i2d_ECDSA_SIG(sig, &der);
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256(proof_input.data(), proof_input.size(), digest);
        ok = low_s && der_len > 0 &&
             ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, der, der_len, ec) == 1;
        OPENSSL_free(der);
        ECDSA_SIG_free(sig);
        BN_free(s_bn);
        BN_free(half);
    }
    if (pt) EC_POINT_free(pt);
    EC_KEY_free(ec);
    return ok;
}

} // namespace

TEST(CanonicalEncoding, Uint64BeAlwaysEightBytes) {
    const uint64_t values[] = {1ULL, 127ULL, 128ULL, 255ULL, 256ULL, (1ULL << 32),
                               (1ULL << 63) - 1};
    for (uint64_t v : values) {
        std::vector<uint8_t> b = canonical::uint64beBytes(v);
        EXPECT_EQ(b.size(), 8u);
        // 大端序
        uint64_t back = 0;
        for (uint8_t x : b) back = (back << 8) | x;
        EXPECT_EQ(back, v);
    }
    EXPECT_EQ(canonical::uint64beBytes(128)[7], 128u);
    EXPECT_EQ(canonical::uint64beBytes(128).size(), 8u);
}

TEST(CanonicalEncoding, EnumVarintCanonicalForm) {
    std::vector<uint8_t> b;
    canonical::appendEnumVarint(b, 1);
    ASSERT_EQ(b.size(), 1u);
    EXPECT_EQ(b[0], 1u);
    b.clear();
    canonical::appendEnumVarint(b, 128);
    ASSERT_EQ(b.size(), 2u);
    EXPECT_EQ(b[0], 0x80u);
    EXPECT_EQ(b[1], 0x01u);
}

TEST(CanonicalEncoding, LengthPrefixedUint32Be) {
    std::vector<uint8_t> b;
    canonical::appendString(b, "v1");
    ASSERT_EQ(b.size(), 6u);
    EXPECT_EQ(b[3], 2u);  // 长度前缀 = 2
    EXPECT_EQ(b[4], 'v');
    EXPECT_EQ(b[5], '1');
}

TEST(CanonicalEncoding, GoldenAadAndDigestsMatchPythonReference) {
    auto fx = load_fixture();
    auto in = fx["inputs"];
    auto ex = fx["expected"];

    canonical::EnvelopeAadInput aad;
    aad.envelope_version = "v1";
    uint64_t suite_val = 0;
    ASSERT_TRUE(wrappingSuiteEnumValue(in["wrapping_suite"].get<std::string>(), suite_val));
    aad.wrapping_suite = suite_val;
    aad.request_id = in["request_id"].get<std::string>();
    aad.business_domain = in["business_domain"].get<std::string>();
    uint64_t purpose_val = 0;
    ASSERT_TRUE(purposeEnumValue(in["purpose"].get<std::string>(), purpose_val));
    aad.purpose = purpose_val;
    aad.key_id = in["key_id"].get<std::string>();
    aad.business_key_version = in["business_key_version"].get<uint64_t>();
    aad.root_key_version = in["root_key_version"].get<uint64_t>();
    aad.derivation_version = in["derivation_version"].get<std::string>();
    aad.recipient_certificate_fingerprint = hx(in["recipient_certificate_digest"]);

    std::vector<uint8_t> aad_bytes = canonical::buildEnvelopeAadV1(aad);
    EXPECT_EQ(canonical::toHex(aad_bytes), ex["canonical_aad"].get<std::string>());
    EXPECT_EQ(canonical::toHex(canonical::computeAadDigest(aad_bytes)),
              ex["aad_digest"].get<std::string>());

    canonical::EnvelopeDigestInput di;
    di.envelope_format = static_cast<uint64_t>(KeyEnvelopeFormat::ECDH_ES_P256_V1);
    di.request_id = aad.request_id;
    di.business_domain = aad.business_domain;
    di.purpose = purpose_val;
    di.key_id = aad.key_id;
    di.business_key_version = aad.business_key_version;
    di.wrapping_suite = suite_val;
    di.wrapped_key = hx(ex["wrapped_key"]);
    di.parameters = hx(ex["parameters"]);
    EXPECT_EQ(canonical::toHex(canonical::computeEnvelopeDigest(di)),
              ex["envelope_digest"].get<std::string>());

    std::array<uint8_t, 3> kcv = canonical::computeKcv(hx(in["business_key"]));
    EXPECT_EQ(canonical::toHex(std::vector<uint8_t>(kcv.begin(), kcv.end())),
              ex["key_check_value"].get<std::string>());

    canonical::ProofInput pi;
    pi.request_id = aad.request_id;
    pi.business_domain = aad.business_domain;
    pi.purpose = purpose_val;
    pi.key_id = aad.key_id;
    pi.business_key_version = aad.business_key_version;
    pi.envelope_digest = hx(ex["envelope_digest"]);
    pi.key_check_value = hx(ex["key_check_value"]);
    EXPECT_EQ(canonical::toHex(canonical::buildProofInput(pi)),
              ex["proof_input"].get<std::string>());

    EXPECT_EQ(canonical::buildHkdfInfoV1(aad.request_id, aad.business_domain,
                                         in["purpose"].get<std::string>(), aad.key_id,
                                         aad.business_key_version,
                                         canonical::toHex(aad.recipient_certificate_fingerprint)),
              ex["hkdf_info"].get<std::string>());
}

// 设备私钥导入证明（DSN-CR-020 §5/§7.3）golden vector：Python/RFC 6979 参考实现
// 签名，C++ 侧仅以设备公钥独立验签，不得自证。
TEST(CanonicalEncoding, GoldenImportProofP1363Verifies) {
    auto fx = load_fixture();
    auto in = fx["inputs"];
    auto ex = fx["expected"];

    EXPECT_EQ(ex["proof_algorithm"].get<std::string>(),
              std::string(kImportProofAlgorithmP1363));

    std::vector<uint8_t> device_pub = hx(in["device_public_key"]);
    std::vector<uint8_t> pinput = hx(ex["proof_input"]);
    std::vector<uint8_t> proof = hx(ex["import_proof"]);

    ASSERT_EQ(proof.size(), kImportProofSizeP1363);
    EXPECT_TRUE(verify_p1363_proof(device_pub, pinput, proof));

    // 篡改 proofInput → 验签失败。
    std::vector<uint8_t> tampered_input = pinput;
    tampered_input[0] ^= 0xff;
    EXPECT_FALSE(verify_p1363_proof(device_pub, tampered_input, proof));

    // 篡改签名 → 验签失败。
    std::vector<uint8_t> tampered = proof;
    tampered[0] ^= 0xff;
    EXPECT_FALSE(verify_p1363_proof(device_pub, pinput, tampered));

    // 非 low-S（s' = n - s）→ 拒绝。
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    ASSERT_NE(group, nullptr);
    const BIGNUM* order = EC_GROUP_get0_order(group);
    BIGNUM* s = BN_bin2bn(proof.data() + 32, 32, nullptr);
    BIGNUM* s_high = BN_new();
    BN_sub(s_high, order, s);
    std::vector<uint8_t> high_s = proof;
    BN_bn2binpad(s_high, high_s.data() + 32, 32);
    EXPECT_FALSE(verify_p1363_proof(device_pub, pinput, high_s));
    BN_free(s);
    BN_free(s_high);
    EC_GROUP_free(group);

    // DER 编码（非定长 64B P1363）→ 拒绝。
    ECDSA_SIG* sig = ECDSA_SIG_new();
    ECDSA_SIG_set0(sig, BN_bin2bn(proof.data(), 32, nullptr),
                   BN_bin2bn(proof.data() + 32, 32, nullptr));
    unsigned char* der = nullptr;
    int der_len = i2d_ECDSA_SIG(sig, &der);
    ASSERT_GT(der_len, 0);
    std::vector<uint8_t> der_proof(der, der + der_len);
    EXPECT_FALSE(verify_p1363_proof(device_pub, pinput, der_proof));
    OPENSSL_free(der);
    ECDSA_SIG_free(sig);
}
