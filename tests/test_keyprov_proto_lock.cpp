//
// PAR-PROTO/VEH-PROTO 本地锁版校验（TBOX-SEC-DSN-CR-022 §5/§6）。
//
// 从受控 proto 生成的 DescriptorSet 计算 SHA-256 并与固定值比较；冻结枚举
// 登记数值与关键字段号；校验本地 fixture manifest 的 VEH-PROTO 修订、本地
// proto source hash、生成工具 hash、逐文件 hash 与 manifest 内容 hash。
// 任何 proto 同步/重编号/生成器变更或 fixtures 手工修改都会使本测试失败，
// 必须显式更新锁定常量并复核 VEH-PROTO 文档。
//
#include <gtest/gtest.h>

#include "proto/security/keyprov/v1/key_provisioning.pb.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>

#include <nlohmann/json.hpp>

#include <openssl/sha.h>

#include <fstream>
#include <filesystem>
#include <string>

namespace {

namespace kp = security::keyprov::v1;

std::string hex(const unsigned char* p, size_t n) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(digits[p[i] >> 4]);
        out.push_back(digits[p[i] & 0x0f]);
    }
    return out;
}

std::string sha256_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    EXPECT_TRUE(ifs.is_open()) << "cannot open " << path;
    std::string data((std::istreambuf_iterator<char>(ifs)),
                     std::istreambuf_iterator<char>());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return hex(digest, sizeof(digest));
}

// ---- 生成器/运行时：protoc (libprotoc) 35.1（VEH-PROTO 2026-10-25 修订）----
// 更新除 generator 变更外的 proto 定义时必须同步刷新该常量并复核 manifest。
constexpr const char* kPinnedDescriptorSetSha256 =
    "0555b2d8e0f156b59d145dd19a4c2162e63dad5cecb08d370d122ca7bff7c1da";

// ---- VEH-PROTO 文档修订与 fixture manifest 锁定 ----
constexpr const char* kPinnedVehProtoRevision =
    "VEH-PROTO 2026-10-25（PAR-PROTO-DSN-CR-009 同步）";
constexpr const char* kPinnedParProtoRelease = "PAR-PROTO-DSN-CR-009";
// tests/fixtures/keyprov_fixture_manifest.json 内容 hash（任一项变化须显式评审后更新）
constexpr const char* kPinnedManifestContentSha256 =
    "6c046e4e95e4af5ba6ee4f7118254bafed347b8f23729a16865d929b10f801be";

// 编译期枚举登记值断言（VEH-PROTO §7.2.2：wrappingSuite 登记值 = 2）。
static_assert(static_cast<int>(kp::WRAPPING_SUITE_UNSPECIFIED) == 0, "suite 0 reserved");
static_assert(static_cast<int>(kp::WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM) == 2,
              "wrapping suite registered value MUST be 2");
static_assert(static_cast<int>(kp::KEY_PURPOSE_UNSPECIFIED) == 0, "purpose 0 reserved");
static_assert(static_cast<int>(kp::KEY_PURPOSE_UPLINK_AEAD) == 1, "purpose 1");
static_assert(static_cast<int>(kp::KEY_PURPOSE_DOWNLINK_AEAD) == 2, "purpose 2");
static_assert(static_cast<int>(kp::KEY_ENVELOPE_FORMAT_UNSPECIFIED) == 0, "format 0 reserved");
static_assert(static_cast<int>(kp::KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1) == 1, "format 1");

} // namespace

TEST(KeyprovProtoLock, DescriptorSetSha256) {
    const google::protobuf::FileDescriptor* fd =
        kp::EcdhEsP256EnvelopeParametersV1::descriptor()->file();
    ASSERT_NE(fd, nullptr);

    google::protobuf::FileDescriptorSet fds;
    fd->CopyTo(fds.add_file());
    std::string serialized;
    ASSERT_TRUE(fds.SerializeToString(&serialized));

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(serialized.data()), serialized.size(),
           digest);
    std::string actual = hex(digest, sizeof(digest));

    GTEST_LOG_(INFO) << "descriptor_set_sha256=" << actual;
    EXPECT_EQ(actual, std::string(kPinnedDescriptorSetSha256));
}

TEST(KeyprovProtoLock, FrozenEnumValues) {
    EXPECT_EQ(static_cast<int>(kp::KEY_ENVELOPE_FORMAT_UNSPECIFIED), 0);
    EXPECT_EQ(static_cast<int>(kp::KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1), 1);
    EXPECT_EQ(static_cast<int>(kp::WRAPPING_SUITE_UNSPECIFIED), 0);
    EXPECT_EQ(static_cast<int>(kp::WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM), 2);
    EXPECT_EQ(static_cast<int>(kp::KEY_PURPOSE_UNSPECIFIED), 0);
    EXPECT_EQ(static_cast<int>(kp::KEY_PURPOSE_UPLINK_AEAD), 1);
    EXPECT_EQ(static_cast<int>(kp::KEY_PURPOSE_DOWNLINK_AEAD), 2);
}

TEST(KeyprovProtoLock, FrozenFieldLayout) {
    const google::protobuf::Descriptor* d = kp::EcdhEsP256EnvelopeParametersV1::descriptor();
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->FindFieldByNumber(1)->name(), "format_version");
    EXPECT_EQ(d->FindFieldByNumber(2)->name(), "server_ephemeral_public_key");
    EXPECT_EQ(d->FindFieldByNumber(3)->name(), "hkdf_salt");
    EXPECT_EQ(d->FindFieldByNumber(4)->name(), "hkdf_context_version");
    EXPECT_EQ(d->FindFieldByNumber(5)->name(), "nonce");
    EXPECT_EQ(d->FindFieldByNumber(6)->name(), "authentication_tag");
    EXPECT_EQ(d->FindFieldByNumber(7)->name(), "canonical_aad");
    EXPECT_EQ(d->FindFieldByNumber(8)->name(), "aad_digest");
    EXPECT_EQ(d->FindFieldByNumber(9)->name(), "root_key_version");
    EXPECT_EQ(d->FindFieldByNumber(10)->name(), "derivation_version");
    EXPECT_EQ(d->FindFieldByNumber(11)->name(), "recipient_certificate_digest");
    EXPECT_EQ(d->FindFieldByNumber(12)->name(), "operation_id");
}

// CR-022 §5/§6：fixture manifest 锁版——VEH-PROTO 修订、本地 proto source hash、
// 生成工具 hash、逐文件 hash 与 manifest 内容 hash 全部一致。
TEST(KeyprovProtoLock, FixtureManifestLocked) {
    const std::string manifest_path = std::string(SEC_TEST_FIXTURE_DIR) + "/keyprov_fixture_manifest.json";
    std::ifstream ifs(manifest_path);
    ASSERT_TRUE(ifs.is_open());
    nlohmann::json m;
    ifs >> m;

    EXPECT_EQ(m["veh_proto_revision"].get<std::string>(), std::string(kPinnedVehProtoRevision));
    EXPECT_EQ(m["par_proto_release"].get<std::string>(), std::string(kPinnedParProtoRelease));

    // 本地 proto source hash 与 manifest 记录一致
    EXPECT_EQ(sha256_file(std::string(SEC_PROTO_SOURCE_FILE)),
              m["local_proto"]["sha256"].get<std::string>());
    // 生成工具 hash 与 manifest 记录一致
    EXPECT_EQ(sha256_file(std::string(SEC_TEST_FIXTURE_DIR) + "/gen_keyprov_ecdh_es_v1_vector.py"),
              m["generator_tool"]["sha256"].get<std::string>());
    // 每个向量文件 hash 与 manifest 记录一致
    for (const auto& [name, meta] : m["files"].items()) {
        EXPECT_EQ(sha256_file(std::string(SEC_TEST_FIXTURE_DIR) + "/" + name),
                  meta["sha256"].get<std::string>())
            << "fixture file " << name;
        EXPECT_EQ((size_t)meta["bytes"], (size_t)std::filesystem::file_size(
                                             std::string(SEC_TEST_FIXTURE_DIR) + "/" + name));
    }
    // 本地 DescriptorSet（protoc 产物）hash 已记录且为 64 位十六进制
    const std::string ds = m["descriptor"]["sha256"].get<std::string>();
    EXPECT_EQ(ds.size(), 64u);
    EXPECT_EQ(m["descriptor"]["protoc_version"].get<std::string>(), "35.1");

    // manifest 内容 hash 锁定：任一项变化（重新生成/手工修改）必须显式更新
    std::string manifest_content((std::istreambuf_iterator<char>(ifs)),
                                 std::istreambuf_iterator<char>());
    ifs.clear();
    ifs.seekg(0);
    manifest_content.assign((std::istreambuf_iterator<char>(ifs)),
                            std::istreambuf_iterator<char>());
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(manifest_content.data()),
           manifest_content.size(), digest);
    EXPECT_EQ(hex(digest, sizeof(digest)), std::string(kPinnedManifestContentSha256));
}
