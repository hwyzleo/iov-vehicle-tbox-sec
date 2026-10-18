//
// PAR-PROTO / DescriptorSet 锁版校验（TBOX-SEC-DSN-CR-020 §13/§14）。
//
// 从受控 proto 生成的 DescriptorSet 计算 SHA-256 并与固定值比较；同时冻结
// 首期枚举数值与关键字段号。任何 proto 同步/重编号/生成器变更都会使本测试失败，
// 必须显式更新锁定常量并复核 PAR-PROTO 原文。
//
#include <gtest/gtest.h>

#include "proto/security/keyprov/v1/key_provisioning.pb.h"

#include <google/protobuf/descriptor.h>
#include <google/protobuf/descriptor.pb.h>

#include <openssl/sha.h>

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

// 生成器：libprotoc 35.1（PAR-PROTO-DSN-CR-007 2026-10-18）。
// 更新除 generator 变更外的 proto 定义时必须同步刷新该常量。
constexpr const char* kPinnedDescriptorSetSha256 =
    "08c79dd490cea54f32b80f150d93db25f70f2504cb89fc75ac9d3e99addd46de";

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
    EXPECT_EQ(static_cast<int>(kp::WRAPPING_SUITE_ECDH_ES_P256_HKDF_SHA256_AES256GCM), 1);
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
