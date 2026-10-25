//
// EnvelopeValidator + ECDH-ES P-256 v1 参数解析测试（TBOX-SEC-DSN-CR-022 §2/§3/§5；
// VEH-PROTO §7.2.2）。
//
// golden 交叉校验：期望值由本地 Python 再生工具生成（跨端与 VMD/Java 一致）；
// 非生产封装参考实现 buildEcdhEsP256EnvelopeV1 的字节级 cross-check 使用
// fixture 的 builder 段（真实 ECDH/HKDF/AES-GCM）。
//
#include <gtest/gtest.h>

#include "business_key_envelope.h"
#include "canonical_encoding.h"
#include "keyprov_envelope_builder.h"
#include "tbox/sec/business_key.h"

#include "proto/security/keyprov/v1/key_provisioning.pb.h"

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

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

/// 显式 deterministic protobuf serialization（与 parseEcdhEsP256Parameters 同路径）。
std::vector<uint8_t> deterministic_serialize(const kp::EcdhEsP256EnvelopeParametersV1& msg) {
    std::string out;
    google::protobuf::io::StringOutputStream sos(&out);
    google::protobuf::io::CodedOutputStream cos(&sos);
    cos.SetSerializationDeterministic(true);
    EXPECT_TRUE(msg.SerializeToCodedStream(&cos));
    cos.Trim();  // 收敛 StringOutputStream 尾部未写入字节
    return std::vector<uint8_t>(out.begin(), out.end());
}

/// 从 fixture primary 段构造一条合法 WrappedKeyItem。
WrappedKeyItem primary_item(const nlohmann::json& fx) {
    auto p = fx["primary"];
    auto ex = p["expected"];
    WrappedKeyItem item;
    item.purpose = "UPLINK_AEAD";
    item.key_id = p["key_id"].get<std::string>();
    item.business_key_version = p["business_key_version"].get<uint64_t>();
    item.algorithm = p["crypto"]["key_algorithm"].get<std::string>();
    item.wrapping_suite = "ECDH_ES_P256_HKDF_SHA256_AES256GCM";
    item.envelope_format = KeyEnvelopeFormat::ECDH_ES_P256_V1;
    item.wrapped_key.assign(hx(p["crypto"]["wrapped_key_hex"]));
    item.parameters.assign(hx(ex["parameters"]));
    item.envelope_digest = hx(ex["wire_envelope_digest"]);
    item.key_check_value = {hx(ex["key_check_value"])[0], hx(ex["key_check_value"])[1],
                            hx(ex["key_check_value"])[2]};
    item.key_check_value_present = true;
    item.valid_from_ms = 1;
    item.valid_to_ms = ((1LL << 62));
    return item;
}

/// 与 primary item 匹配的 outer context（ACTIVE 证书摘要 = 0x61*32）。
EnvelopeContext primary_context(const nlohmann::json& fx) {
    auto p = fx["primary"];
    EnvelopeContext ctx;
    ctx.request_id = p["request_id"].get<std::string>();
    ctx.business_domain = p["business_domain"].get<std::string>();
    ctx.purpose = "UPLINK_AEAD";
    ctx.active_cert_digest = hx(p["recipient_certificate_digest_hex"]);
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

/// 解析、修改、deterministic 重序列化 parameters。
template <typename Fn>
void mutate_params(WrappedKeyItem& item, Fn fn) {
    kp::EcdhEsP256EnvelopeParametersV1 msg;
    ASSERT_TRUE(msg.ParseFromArray(item.parameters.data(), (int)item.parameters.size()));
    fn(msg);
    item.parameters.assign(deterministic_serialize(msg));
}

KeyprovEnvelopeInput builder_input(const nlohmann::json& in) {
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

} // namespace

TEST(EnvelopeValidator, GoldenBuilderMatchesPythonReference) {
    auto fx = load_fixture();
    auto in = builder_input(fx["builder"]["inputs"]);
    auto ex = fx["builder"]["expected"];

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

TEST(EnvelopeValidator, GoldenPrimaryItemValidates) {
    auto fx = load_fixture();
    ValidatedEnvelope v;
    ASSERT_EQ(validateEnvelope(primary_item(fx), primary_context(fx), EnvelopeLimits{}, v),
              ErrorCode::SUCCESS);
    EXPECT_EQ(canonical::toHex(v.envelope_digest),
              fx["primary"]["expected"]["wire_envelope_digest"].get<std::string>());
    EXPECT_EQ(canonical::toHex(v.canonical_aad),
              fx["primary"]["expected"]["canonical_aad"].get<std::string>());
}

TEST(EnvelopeValidator, P256PointValidation) {
    std::vector<uint8_t> good = hx(
        load_fixture()["primary"]["crypto"]["server_ephemeral_public_key_hex"].get<std::string>());
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
    ValidatedEnvelope v;

    WrappedKeyItem item = primary_item(fx);
    item.envelope_format = KeyEnvelopeFormat::UNSPECIFIED;
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);

    item = primary_item(fx);
    item.wrapping_suite = "ECIES-ECDH-ES-A256GCM-v1";
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);

    item = primary_item(fx);
    item.algorithm = "AES-128";
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), EnvelopeLimits{}, v),
              ErrorCode::BUSINESS_KEY_UNSUPPORTED);
}

TEST(EnvelopeValidator, RejectsMalformedParameters) {
    auto fx = load_fixture();
    ValidatedEnvelope v;
    EnvelopeLimits limits;

    // fixture negative：非法长度（每个 parameters 子字段）
    for (const auto& c : fx["negative"]["parameters_illegal_lengths"]) {
        WrappedKeyItem item = primary_item(fx);
        item.parameters.assign(hx(c["parameters_hex"]));
        EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
                  ErrorCode::WRAPPED_KEY_INVALID)
            << "illegal length case " << c["name"].get<std::string>();
    }

    WrappedKeyItem item = primary_item(fx);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) { m.set_format_version(2); });
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST(EnvelopeValidator, RejectsUnknownFieldAndUnknownFormatVersion) {
    auto fx = load_fixture();
    EnvelopeLimits limits;
    ValidatedEnvelope v;

    // VEH-PROTO §7.2.2（3）：unknown fields 必须拒绝。
    WrappedKeyItem item = primary_item(fx);
    item.parameters.assign(
        hx(fx["negative"]["parameters_unknown_field"]["parameters_hex"]));
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    // 未知 format_version
    item = primary_item(fx);
    item.parameters.assign(
        hx(fx["negative"]["parameters_unknown_format_version"]["parameters_hex"]));
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST(EnvelopeValidator, RejectsReencodedParameters) {
    // VEH-PROTO §7.2.2（4）：语义相同但字段乱序的重编码（非 canonical）→ 拒绝，
    // 且 digest 不同。
    auto fx = load_fixture();
    auto neg = fx["negative"]["parameters_reencoded"];
    EXPECT_NE(neg["reencoded_parameters_hex"].get<std::string>(),
              neg["original_parameters_hex"].get<std::string>());
    EXPECT_NE(neg["digest_over_reencoded_hex"].get<std::string>(),
              neg["authoritative_wire_envelope_digest_hex"].get<std::string>());

    EnvelopeLimits limits;
    ValidatedEnvelope v;
    WrappedKeyItem item = primary_item(fx);
    item.parameters.assign(hx(neg["reencoded_parameters_hex"]));
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);
}

TEST(EnvelopeValidator, RejectsAadDigestCertAndDigestMismatch) {
    auto fx = load_fixture();
    EnvelopeLimits limits;
    ValidatedEnvelope v;

    // AAD 篡改（canonical_aad 改变但未重算 aad_digest）
    WrappedKeyItem item = primary_item(fx);
    mutate_params(item, [](kp::EcdhEsP256EnvelopeParametersV1& m) {
        std::string a = m.canonical_aad();
        a[0] ^= 0xff;
        m.set_canonical_aad(a);
    });
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    // envelopeDigest 篡改
    item = primary_item(fx);
    item.envelope_digest[0] ^= 0xff;
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    // ACTIVE 证书摘要与信封绑定不一致
    item = primary_item(fx);
    EnvelopeContext ctx = primary_context(fx);
    ctx.active_cert_digest[0] ^= 0xff;
    EXPECT_EQ(validateEnvelope(item, ctx, limits, v), ErrorCode::WRAPPED_KEY_INVALID);
}

// CR-022 §5：负向逐字节篡改每个顶层 segment（AAD 10 段）→ 整批拒绝。
TEST(EnvelopeValidator, RejectsPerSegmentCanonicalAadTamper) {
    auto fx = load_fixture();
    EnvelopeLimits limits;
    auto neg = fx["negative"]["tamper_canonical_aad"];

    for (const auto& c : neg["cases"]) {
        // 把 mutated canonical_aad 写入 parameters，其余 outer 字段保持权威
        // （validateEnvelope 重建出权威 AAD → 与承载值不一致 → AAD 步拒绝）。
        const std::vector<uint8_t> mutated_aad = hx(c["mutated_canonical_aad_hex"]);
        WrappedKeyItem item = primary_item(fx);
        mutate_params(item, [&](kp::EcdhEsP256EnvelopeParametersV1& m) {
            m.set_canonical_aad(
                std::string(mutated_aad.begin(), mutated_aad.end()));
        });
        ValidatedEnvelope v;
        EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
                  ErrorCode::WRAPPED_KEY_INVALID)
            << "AAD segment " << c["segment_index"].get<int>() << " ("
            << c["segment"].get<std::string>() << ")";
    }
}

// CR-022 §5：负向逐字节篡改每个顶层 segment（wire digest 9 段）→ 整批拒绝。
TEST(EnvelopeValidator, RejectsPerSegmentWireDigestTamper) {
    auto fx = load_fixture();
    EnvelopeLimits limits;
    auto neg = fx["negative"]["tamper_wire_digest_input"];

    // 每段对应一个可篡改字段；envelope_digest 保持权威值 → 重算不同 → 拒绝。
    for (const auto& c : neg["cases"]) {
        WrappedKeyItem item = primary_item(fx);
        EnvelopeContext ctx = primary_context(fx);
        switch (c["segment_index"].get<int>()) {
            case 0:  // envelopeFormat
                item.envelope_format = KeyEnvelopeFormat::UNSPECIFIED;
                break;
            case 1:  // requestId（case: 'r'->'s'）
                ctx.request_id = "seq-kp-0009";
                break;
            case 2:  // businessDomain（case: 'V'->'W'）
                ctx.business_domain = "W2C_COMM";
                break;
            case 3:  // purpose（case: 1->0）
                item.purpose = "UNSPECIFIED";
                break;
            case 4:  // keyId（case: 'b'->'c'）
                item.key_id = "ciz-key-up-0009";
                break;
            case 5:  // businessKeyVersion（case: 3 -> 高位翻转）
                item.business_key_version = 4;
                break;
            case 6:  // wrappingSuite（case: 2->3）
                item.wrapping_suite = "BOGUS-SUITE";
                break;
            case 7:  // wrappedKey（case: 0x71->0x70）
                item.wrapped_key.data()[0] ^= 0x01;
                break;
            case 8:  // parameters（case: 0x08->0x09）
                item.parameters.data()[0] ^= 0x01;
                break;
            default:
                FAIL() << "unexpected segment index";
        }
        ValidatedEnvelope v;
        EXPECT_NE(validateEnvelope(item, ctx, limits, v), ErrorCode::SUCCESS)
            << "wire segment " << c["segment_index"].get<int>() << " ("
            << c["segment"].get<std::string>() << ")";
    }
}

TEST(EnvelopeValidator, RejectsWhenCertificateCannotDerive) {
    auto fx = load_fixture();
    EnvelopeLimits limits;
    ValidatedEnvelope v;

    EnvelopeContext ctx = primary_context(fx);
    ctx.private_key_can_derive = false;
    EXPECT_EQ(validateEnvelope(primary_item(fx), ctx, limits, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);

    ctx = primary_context(fx);
    ctx.active_cert_key_agreement = false;
    EXPECT_EQ(validateEnvelope(primary_item(fx), ctx, limits, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);

    ctx = primary_context(fx);
    ctx.active_cert_digital_signature = false;
    EXPECT_EQ(validateEnvelope(primary_item(fx), ctx, limits, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);

    ctx = primary_context(fx);
    ctx.private_key_can_sign = false;
    EXPECT_EQ(validateEnvelope(primary_item(fx), ctx, limits, v),
              ErrorCode::BUSINESS_KEY_NOT_READY);
}

// CR-022 §5：证明 SEC 只按 wire 规则工作——携带一个与 wire 摘要不同的
// "FW core" 式摘要字段不会影响校验（SEC 校验从不依赖 FW 私有 canonical）。
TEST(EnvelopeValidator, FwCoreEnvelopeDigestIndependence) {
    auto fx = load_fixture();
    EnvelopeLimits limits;
    ValidatedEnvelope v;

    // 构造一个"假 FW core 摘要"（对与 wire 无关的输入做摘要），并塞进
    // envelope_digest；SEC 会重算 wire digest 并与该值比较 → 拒绝。
    WrappedKeyItem item = primary_item(fx);
    std::vector<uint8_t> fw_core_input;
    canonical::appendString(fw_core_input, item.key_id);
    canonical::appendEnumVarint(fw_core_input, item.business_key_version);
    item.envelope_digest = canonical::sha256(fw_core_input);
    EXPECT_NE(canonical::toHex(item.envelope_digest),
              fx["primary"]["expected"]["wire_envelope_digest"].get<std::string>());
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v),
              ErrorCode::WRAPPED_KEY_INVALID);

    // 反向证明：envelope_digest 恰好等于 wire 摘要时（无 FW 摘要参与）校验通过。
    item = primary_item(fx);
    EXPECT_EQ(validateEnvelope(item, primary_context(fx), limits, v), ErrorCode::SUCCESS);
}
