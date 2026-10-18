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
