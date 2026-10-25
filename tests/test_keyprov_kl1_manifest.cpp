//
// KL1 本地 fixture manifest 校验（TBOX-SEC-DSN-CR-023 §12.11.5）。
//
// - lifecycle-vectors.json 为 PAR-PROTO-DSN-CR-010 交付原件的 SEC 仓受控本地副本，
//   SHA256 必须等于 5226b927...855e3；修改任一用例/expected 均须显式评审后更新；
// - keyprov_kl1_manifest.json 登记 24 场景组/57 子例的责任映射（direct/cross-end/
//   sec-derived/other），必须覆盖向量全部 case_id，且 sec_derived 引用存在；
// - 责任标注规则（见 manifest responsibility_notes）：LC07/LC20/LC24 属其他端或
//   派生测试，不能把改解释后的用例记为原用例 PASS。
//
#include <gtest/gtest.h>

#include "canonical_encoding.h"

#include <nlohmann/json.hpp>

#include <openssl/sha.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace tbox::sec;
using json = nlohmann::json;

namespace {

#ifndef SEC_TEST_FIXTURE_DIR
#error "SEC_TEST_FIXTURE_DIR must be defined by CMake"
#endif

constexpr const char* kKl1VectorRelativePath = "/keyprov-kl1-v1/lifecycle-vectors.json";
constexpr const char* kKl1ManifestRelativePath = "/keyprov-kl1-v1/keyprov_kl1_manifest.json";

// PAR-PROTO-DSN-CR-010 交付原件 SHA256（不得改动；改动须跨端联合评审）。
constexpr const char* kPinnedVectorSha256 =
    "5226b92733a93634d9bdd11ec7090b1ba655979e3beca0399784e9db7de855e3";

std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) return "";
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

std::string sha256_hex(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    return canonical::toHex(std::vector<uint8_t>(digest, digest + SHA256_DIGEST_LENGTH));
}

std::string vector_path() { return std::string(SEC_TEST_FIXTURE_DIR) + kKl1VectorRelativePath; }
std::string manifest_path() {
    return std::string(SEC_TEST_FIXTURE_DIR) + kKl1ManifestRelativePath;
}

} // namespace

TEST(KeyprovKl1Manifest, VectorSha256Pinned) {
    const std::string data = read_file(vector_path());
    ASSERT_FALSE(data.empty()) << "cannot read " << vector_path();
    EXPECT_EQ(sha256_hex(data), kPinnedVectorSha256);
}

TEST(KeyprovKl1Manifest, VectorStructure) {
    const std::string data = read_file(vector_path());
    ASSERT_FALSE(data.empty());
    json v;
    ASSERT_NO_THROW(v = json::parse(data));
    EXPECT_EQ(v.value("profile", ""), "KEYPROV-LIFECYCLE-1");
    EXPECT_EQ(v.value("case_set", ""), "keyprov-lifecycle-kl1-v1");
    EXPECT_EQ(v.value("T0", 0LL), 1800000000000LL);
    ASSERT_TRUE(v.contains("cases") && v["cases"].is_array());
    EXPECT_EQ(v["cases"].size(), 57u);  // 24 场景组/57 子例
    for (const auto& c : v["cases"]) {
        EXPECT_TRUE(c.contains("case_id"));
        EXPECT_TRUE(c.contains("input"));
        EXPECT_TRUE(c.contains("expected"));
        EXPECT_TRUE(c.contains("input_hash"));
        EXPECT_TRUE(c.contains("expected_hash"));
        EXPECT_EQ(c["input_hash"].get<std::string>().size(), 64u);
        EXPECT_EQ(c["expected_hash"].get<std::string>().size(), 64u);
    }
}

TEST(KeyprovKl1Manifest, CoversAllVectorCases) {
    const json v = json::parse(read_file(vector_path()));
    const json m = json::parse(read_file(manifest_path()));
    ASSERT_TRUE(v.contains("cases") && m.contains("cases"));
    // 每个向量 case_id 都必须在 manifest 中登记。
    std::vector<std::string> vector_ids;
    for (const auto& c : v["cases"]) vector_ids.push_back(c["case_id"]);
    std::vector<std::string> manifest_ids;
    for (const auto& c : m["cases"]) {
        ASSERT_TRUE(c.contains("case_id")) << "manifest case missing case_id";
        manifest_ids.push_back(c["case_id"]);
    }
    EXPECT_EQ(vector_ids.size(), manifest_ids.size());
    for (const auto& id : vector_ids) {
        EXPECT_NE(std::find(manifest_ids.begin(), manifest_ids.end(), id), manifest_ids.end())
            << "vector case " << id << " missing in manifest";
    }
}

TEST(KeyprovKl1Manifest, BucketsAndResponsibilityTags) {
    const json m = json::parse(read_file(manifest_path()));
    const std::vector<std::string> buckets = {"direct", "cross-end", "sec-derived", "other"};
    for (const auto& c : m["cases"]) {
        const std::string b = c.value("bucket", "");
        EXPECT_NE(std::find(buckets.begin(), buckets.end(), b), buckets.end())
            << "case " << c.value("case_id", "?") << " invalid bucket " << b;
        EXPECT_FALSE(c.value("owner", "").empty());
        EXPECT_FALSE(c.value("reason", "").empty());
    }
}

TEST(KeyprovKl1Manifest, ParametersMatchVector) {
    const json v = json::parse(read_file(vector_path()));
    const json m = json::parse(read_file(manifest_path()));
    ASSERT_TRUE(v.contains("parameters") && m.contains("parameters"));
    EXPECT_EQ(v["parameters"].dump(), m["parameters"].dump());
}

TEST(KeyprovKl1Manifest, SecDerivedReferencesExist) {
    const json m = json::parse(read_file(manifest_path()));
    ASSERT_TRUE(m.contains("sec_derived_cases"));
    std::vector<std::string> manifest_ids;
    for (const auto& c : m["cases"]) manifest_ids.push_back(c["case_id"]);
    for (const auto& d : m["sec_derived_cases"]) {
        EXPECT_TRUE(d.contains("sec_case_id"));
        EXPECT_TRUE(d.contains("based_on"));
        EXPECT_TRUE(d.contains("assert"));
        // based_on 可能为“LC02.0/LC02.1”“LC21.*”等多值/通配形式；
        // 每个 token 都必须能匹配真实向量 case_id 前缀（原语义，不能臆造）。
        std::string based = d["based_on"];
        std::stringstream ss(based);
        std::string token;
        bool any = false;
        while (std::getline(ss, token, '/')) {
            // 支持“LC21.*”通配：去掉尾部通配符后按前缀匹配。
            if (token.size() >= 2 && token.compare(token.size() - 2, 2, ".*") == 0) {
                token.resize(token.size() - 1);  // "LC21."
            }
            bool matched = false;
            for (const auto& id : manifest_ids) {
                if (id.rfind(token, 0) == 0) { matched = true; break; }
            }
            EXPECT_TRUE(matched) << "sec_derived " << d.value("sec_case_id", "?")
                                 << " based_on token " << token << " not in manifest cases";
            any = any || matched;
        }
        EXPECT_TRUE(any) << "sec_derived " << d.value("sec_case_id", "?")
                         << " based_on " << based << " matches nothing";
    }
}

TEST(KeyprovKl1Manifest, ResponsibilityNotesPresent) {
    const json m = json::parse(read_file(manifest_path()));
    ASSERT_TRUE(m.contains("responsibility_notes"));
    EXPECT_GE(m["responsibility_notes"].size(), 1u);
    // 修正过的归属必须体现在注释：LC07 为 VMD 内容幂等、LC20 为云端 issue、
    // LC24 为 VMD replay store、LC01/03/04/05/19 为 VMD 签发/ACK。
    const std::string notes = m["responsibility_notes"].dump();
    EXPECT_NE(notes.find("LC07"), std::string::npos);
    EXPECT_NE(notes.find("LC20"), std::string::npos);
    EXPECT_NE(notes.find("LC24"), std::string::npos);
    EXPECT_NE(notes.find("LC19"), std::string::npos);
}

TEST(KeyprovKl1Manifest, VectorExpectedHashesUnchanged) {
    // 任何 expected 修改都会改变 case 的 expected_hash 一致性；这里只做完整性断言：
    // expected_hash 必须与向量文件内声明一致（文件本身 SHA256 已锁定）。
    const json v = json::parse(read_file(vector_path()));
    for (const auto& c : v["cases"]) {
        EXPECT_EQ(c["expected_hash"].get<std::string>().size(), 64u);
    }
}
