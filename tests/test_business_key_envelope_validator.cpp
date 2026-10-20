//
// EnvelopeValidator + ECDH-ES P-256 v1 参数解析测试（TBOX-SEC-DSN-CR-020 §5/§6）。
//
// 同时以 golden vector 校验非生产封装参考实现 buildEcdhEsP256EnvelopeV1。
//
#include <gtest/gtest.h>

#include "business_key_envelope.h"
#include "canonical_encoding.h"
#include "keyprov_envelope_builder.h"
#include "tbox/sec/business_key.h"

#include "proto/security/keyprov/v1/key_provisioning.pb.h"

#include <nlohmann/json.hpp>

#include <fstream>
#include <string>
#include <vector>

using namespace tbox::sec;

namespace {

namespace kp = security::keyprov::v1;

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

KeyprovEnvelopeInput fixture_input(const nlohmann::json& in) {
    KeyprovEnvelopeInput i;
    i.device_public_key = hx(in["device_public_key"]);
    i.server_ephemeral_private_key = hx(in["server_ephemeral_private_key"]);
    i.hkdf_salt = hx(in["hkdf_salt"]);
    i.nonce = hx(in["nonce"]);
    i.business_key = hx(in["business_key"]);
    i.recipient_certificate_digest = hx(in["recipient_certificate_digest"]);
    i.request_id = in["request_id"];
    i.business_domain = in["business_domain"];
    i.purpose = in["purpose"];
    i.key_id = in["key_id"];
    i.business_key_version = in["business_key_version"];
    i.root_key_version = in["root_key_version"];
    i.derivation_version = in["derivation_version"];
    i.operation_id = in["operation_id"];
    i.hkdf_context_version = in["hkdf_context_version"];
    i.wrapping_suite = in["wrapping_suite"];
    i.key_algorithm = in["key_algorithm"];
    return i;
}

WrappedKeyItem item_from_output(const KeyprovEnvelopeInput& in, const KeyprovEnvelopeOutput& out) {
    WrappedKeyItem item;
    item.purpose = in.purpose;
    item.key_id = in.key_id;
    item.business_key_version = in.business_key_version;
    item.algorithm = in.key_algorithm;
    item.wrapping_suite = in.wrapping_suite;
    item.envelope_format = KeyEnvelopeFormat::ECDH_ES_P256_V1;
    item.wrapped_key.assign(out.wrapped_key);
    item.parameters.assign(out.parameters);
    item.envelope_digest = out.envelope_digest;
    item.key_check_value = out.key_check_value;
    item.key_check_value_present = true;
    item.valid_from_ms = 1;
    item.valid_to_ms = ((1LL << 62));
    return item;
}

EnvelopeContext context_for(const KeyprovEnvelopeInput& in) {
    EnvelopeContext ctx;
    ctx.request_id = in.request_id;
    ctx.business_domain = in.business_domain;
    ctx.purpose = in.purpose;
    ctx.active_cert_digest = in.recipient_certificate_digest;
    ctx.active_cert_p256 = true;
    ctx.active_cert_key_agreement = true;
    ctx.active_cert_digital_signature = true;
    ctx.private_key_can_derive = true;
    ctx.private_key_can_sign = true;
    ctx.active_cert_ca_false = true;
    ctx.active_cert_eku_client_auth_only = true;
    ctx.active_cert_critical_extensions_allowed = true;
    ctx.active_cert_leaf_digest_bound = true;
    ctx.active_cert_chain_key_match = true;
    ctx.identity_template_sign_derive = true;
    return ctx;
}

/// 解析、修改、重序列化 parameters（保持 deterministic 形式）。
template <typename Fn>
void mutate_params(WrappedKeyItem& item, Fn fn) {
    kp::EcdhEsP256EnvelopeParametersV1 msg;
    ASSERT_TRUE(msg.ParseFromArray(item.parameters.data(), (int)item.parameters.size()));
    fn(msg);
    std::string s;
    ASSERT_TRUE(msg.SerializeToString(&s));
    item.parameters.assign(std::vector<uint8_t>(s.begin(), s.end()));
}

} // namespace

TEST(EnvelopeValidator, GoldenBuilderMatchesPythonReference) {
    auto fx = load_fixture();
    auto in = fixture_input(fx["inputs"]);
    auto ex = fx["expected"];

    KeyprovEnvelopeOutput out;
    ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);

    EXPECT_EQ(canonical::toHex(out.server_ephemeral_public_key),
              ex["server_ephemeral_public_key"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.canonical_aad), ex["canonical_aad"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.aad_digest), ex["aad_digest"].get<std::string>());
    EXPECT_EQ(std::string(out.hkdf_info.begin(), out.hkdf_info.end()),
              ex["hkdf_info"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.ecdh_shared_secret),
              ex["ecdh_shared_secret"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.kek), ex["kek"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.wrapped_key), ex["wrapped_key"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.authentication_tag),
              ex["authentication_tag"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.parameters), ex["parameters"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.envelope_digest), ex["envelope_digest"].get<std::string>());
    EXPECT_EQ(canonical::toHex(std::vector<uint8_t>(out.key_check_value.begin(),
                                                    out.key_check_value.end())),
              ex["key_check_value"].get<std::string>());
    EXPECT_EQ(canonical::toHex(out.proof_input), ex["proof_input"].get<std::string>());
}

TEST(EnvelopeValidator, GoldenItemValidates) {
    auto fx = load_fixture();
    auto in = fixture_input(fx["inputs"]);
    KeyprovEnvelopeOutput out;
    ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);

    ValidatedEnvelope v;
    ASSERT_EQ(validateEnvelope(item_from_output(in, out), context_for(in), EnvelopeLimits{}, v),
              ErrorCode::SUCCESS);
    EXPECT_EQ(canonical::toHex(v.envelope_digest), canonical::toHex(out.envelope_digest));
    EXPECT_EQ(canonical::toHex(v.canonical_aad), canonical::toHex(out.canonical_aad));
}

TEST(EnvelopeValidator, P256PointValidation) {
    std::vector<uint8_t> good = hx(load_fixture()["inputs"]["device_public_key"].get<std::string>());
    EXPECT_TRUE(isValidP256UncompressedPoint(good));

    std::vector<uint8_t> short_pt(good.begin(), good.begin() + 64);
    EXPECT_FALSE(isValidP256UncompressedPoint(short_pt));
    std::vector<uint8_t> compressed = good;
    compressed[0] = 0x02;
    EXPECT_FALSE(isValidP256UncompressedPoint(compressed));
    std::vector<uint8_t> off_curve = good;
    for (size_t i = 1; i < off_curve.size(); ++i) off_curve[i] = 0xff;
    EXPECT_FALSE(isValidP256UncompressedPoint(off_curve));
}

TEST(EnvelopeValidator, RejectsUnsupportedFormatSuiteAlgorithm) {
    auto fx = load_fixture();
    auto in = fixture_input(fx["inputs"]);
    KeyprovEnvelopeOutput out;
    ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
    ValidatedEnvelope v;

    WrappedKeyItem item = item_from_output(in, out);
    item.envelope_format = KeyEnvelopeFormat::UNSPECIFIED;
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);

    item = item_from_output(in, out);
    item.wrapping_suite = "ECIES-ECDH-ES-A256GCM-v1";
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);

    item = item_from_output(in, out);
    item.algorithm = "AES-128";
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);
}

TEST(EnvelopeValidator, RejectsMalformedParameters) {
    auto fx = load_fixture();
    auto in = fixture_input(fx["inputs"]);
    KeyprovEnvelopeOutput out;
    ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
    ValidatedEnvelope v;

    WrappedKeyItem item = item_from_output(in, out);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) { m.set_format_version(2); });
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    item = item_from_output(in, out);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) {
        m.set_hkdf_salt(std::string(31, 'x'));
    });
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    item = item_from_output(in, out);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) {
        m.set_nonce(std::string(11, 'n'));
    });
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    item = item_from_output(in, out);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) {
        m.set_authentication_tag(std::string(8, 't'));
    });
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    item = item_from_output(in, out);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) {
        std::string pt(65, '\0');
        pt[0] = 0x04;
        m.set_server_ephemeral_public_key(pt);
    });
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST(EnvelopeValidator, RejectsAadDigestCertAndDigestMismatch) {
    auto fx = load_fixture();
    auto in = fixture_input(fx["inputs"]);
    KeyprovEnvelopeOutput out;
    ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
    ValidatedEnvelope v;

    // AAD 篡改（canonical_aad 改变但未重算 aad_digest）
    WrappedKeyItem item = item_from_output(in, out);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) {
        std::string a = m.canonical_aad();
        a[0] ^= 0xff;
        m.set_canonical_aad(a);
    });
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    // envelopeDigest 篡改
    item = item_from_output(in, out);
    item.envelope_digest[0] ^= 0xff;
    EXPECT_EQ(validateEnvelope(item, context_for(in), EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    // ACTIVE 证书摘要与信封绑定不一致
    item = item_from_output(in, out);
    EnvelopeContext ctx = context_for(in);
    ctx.active_cert_digest[0] ^= 0xff;
    EXPECT_EQ(validateEnvelope(item, ctx, EnvelopeLimits{}, v),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST(EnvelopeValidator, RejectsWhenCertificateCannotDerive) {
    auto fx = load_fixture();
    auto in = fixture_input(fx["inputs"]);
    KeyprovEnvelopeOutput out;
    ASSERT_EQ(buildEcdhEsP256EnvelopeV1(in, out), ErrorCode::SUCCESS);
    ValidatedEnvelope v;

    EnvelopeContext ctx = context_for(in);
    ctx.private_key_can_derive = false;
    EXPECT_EQ(validateEnvelope(item_from_output(in, out), ctx, EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);

    ctx = context_for(in);
    ctx.active_cert_key_agreement = false;
    EXPECT_EQ(validateEnvelope(item_from_output(in, out), ctx, EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);

    ctx = context_for(in);
    ctx.active_cert_digital_signature = false;
    EXPECT_EQ(validateEnvelope(item_from_output(in, out), ctx, EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);

    ctx = context_for(in);
    ctx.private_key_can_sign = false;
    EXPECT_EQ(validateEnvelope(item_from_output(in, out), ctx, EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);
}
