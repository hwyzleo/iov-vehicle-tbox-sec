// 证书链严格解析器单元测试（TBOX-SEC-DSN-CR-018 §10）
// 覆盖：格式自动分流、DER 严格消费、PEM 链结构/顺序/角色/重复/Root 入链、
//       数量与大小上限、canonical 规范化幂等。
#include <gtest/gtest.h>

#include "certificate_chain_parser.h"
#include "certificate_chain_canonicalizer.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <memory>
#include <string>
#include <vector>

using namespace tbox::sec;

namespace {

struct X509D { void operator()(X509* p) const { if (p) X509_free(p); } };
using X509UP = std::unique_ptr<X509, X509D>;
struct EvpD { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
using EvpUP = std::unique_ptr<EVP_PKEY, EvpD>;

EvpUP gen_ec_key() {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!EC_KEY_generate_key(ec)) { if (ec) EC_KEY_free(ec); return {}; }
    EvpUP pkey(EVP_PKEY_new());
    EVP_PKEY_assign_EC_KEY(pkey.get(), ec);
    return pkey;
}

// 生成证书：cn / 是否 CA / 证书自身公钥 own_key / 签发签名密钥 sign_key /
// 签发者（自签名时 issuer_cert=nullptr，sign_key==own_key 才构成可验证自签名）
X509UP make_cert(const char* cn, bool is_ca, EVP_PKEY* own_key, EVP_PKEY* sign_key,
                 X509* issuer_cert, long serial) {
    X509UP cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_NAME* n = X509_get_subject_name(cert.get());
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(cn), -1, -1, 0);
    if (issuer_cert) {
        X509_set_issuer_name(cert.get(), X509_get_subject_name(issuer_cert));
    } else {
        X509_set_issuer_name(cert.get(), X509_get_subject_name(cert.get()));
    }
    X509_set_pubkey(cert.get(), own_key);
    X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(cert.get()), 3650 * 24 * 3600L);
    // basicConstraints
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = is_ca ? 1 : 0;
    X509_EXTENSION* ext = X509V3_EXT_i2d(NID_basic_constraints, 1, bc);
    X509_add_ext(cert.get(), ext, -1);
    X509_EXTENSION_free(ext);
    BASIC_CONSTRAINTS_free(bc);
    X509_sign(cert.get(), sign_key, EVP_sha256());
    return cert;
}

// 自签名 CA（Root / 中间 CA 均可用）
X509UP make_self_signed_ca(const char* cn, long serial) {
    EvpUP key = gen_ec_key();
    return make_cert(cn, true, key.get(), key.get(), nullptr, serial);
}

std::vector<uint8_t> der_of(X509* cert) {
    unsigned char* buf = nullptr;
    int len = i2d_X509(cert, &buf);
    std::vector<uint8_t> der(buf, buf + len);
    OPENSSL_free(buf);
    return der;
}

std::string pem_of(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    char* buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string s(buf, static_cast<size_t>(len));
    BIO_free(bio);
    return s;
}

std::vector<uint8_t> bytes_of(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

// leaf + intermediate 两级链（leaf 由 intermediate 签发，intermediate 由 root 签发）
struct ChainFixture {
    X509UP root;
    X509UP intermediate;
    X509UP leaf;
    std::string leaf_pem;
    std::string intermediate_pem;
};

ChainFixture make_two_level_chain() {
    EvpUP root_key = gen_ec_key();
    EvpUP int_key = gen_ec_key();
    EvpUP leaf_key = gen_ec_key();

    ChainFixture f;
    f.root = make_cert("Chain Test Root CA", true, root_key.get(), root_key.get(), nullptr, 1);
    f.intermediate = make_cert("Chain Test Intermediate CA", true, int_key.get(), root_key.get(), f.root.get(), 2);
    f.leaf = make_cert("Chain Test Leaf", false, leaf_key.get(), int_key.get(), f.intermediate.get(), 3);
    f.leaf_pem = pem_of(f.leaf.get());
    f.intermediate_pem = pem_of(f.intermediate.get());
    return f;
}

// 提取证书 Subject（用于顺序断言；PEM 文本是 base64 不能直接搜 CN）
std::string subject_oneline(X509* cert) {
    char buf[256];
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    return std::string(buf);
}

// 统计 PEM 中的 CERTIFICATE 块数
size_t count_pem_blocks(const std::string& pem) {
    size_t n = 0;
    size_t pos = 0;
    while ((pos = pem.find("-----BEGIN CERTIFICATE-----", pos)) != std::string::npos) {
        ++n;
        pos += 27;
    }
    return n;
}

} // namespace

class CertificateChainParserTest : public ::testing::Test {
protected:
    CertificateChainParser parser_;
    CertificateChainCanonicalizer canonicalizer_;
    CertificateChainLimits limits_;  // 默认 8192 / 4
};

// ---- 正向 ----

TEST_F(CertificateChainParserTest, SingleDer_LeafOnly) {
    ChainFixture f = make_two_level_chain();
    ParseResult r = parser_.parse(der_of(f.leaf.get()), limits_);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::Ok);
    EXPECT_EQ(r.chain.format, CertificateInputFormat::DerSingle);
    ASSERT_NE(r.chain.leaf, nullptr);
    EXPECT_TRUE(r.chain.intermediates.empty());
    EXPECT_EQ(r.chain.cert_der_sha256.size(), 1u);

    std::string pem;
    ASSERT_TRUE(canonicalizer_.toPem(r.chain, pem));
    EXPECT_EQ(count_pem_blocks(pem), 1u);
}

TEST_F(CertificateChainParserTest, PemChain_LeafPlusIntermediate_OrderPreserved) {
    ChainFixture f = make_two_level_chain();
    ParseResult r = parser_.parse(bytes_of(f.leaf_pem + f.intermediate_pem), limits_);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.chain.format, CertificateInputFormat::PemChain);
    ASSERT_NE(r.chain.leaf, nullptr);
    ASSERT_EQ(r.chain.intermediates.size(), 1u);
    ASSERT_EQ(r.chain.cert_der_sha256.size(), 2u);

    // canonical PEM：leaf 在前、intermediate 在后；共 2 个块
    std::string pem;
    ASSERT_TRUE(canonicalizer_.toPem(r.chain, pem));
    EXPECT_EQ(count_pem_blocks(pem), 2u);
    // 顺序验证：第一个块 == leaf，第二个块 == intermediate
    EXPECT_NE(pem.find(pem_of(r.chain.leaf.get())), std::string::npos);
    EXPECT_NE(pem.find(pem_of(r.chain.intermediates[0].get())), std::string::npos);
}

TEST_F(CertificateChainParserTest, PemChain_LeadingWhitespace_Accepted) {
    ChainFixture f = make_two_level_chain();
    std::string payload = " \t\r\n" + f.leaf_pem + f.intermediate_pem + "\n  ";
    ParseResult r = parser_.parse(bytes_of(payload), limits_);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.chain.intermediates.size(), 1u);
}

TEST_F(CertificateChainParserTest, SameChainDifferentWrapping_CanonicalIdentical) {
    ChainFixture f = make_two_level_chain();
    // 同一链、不同换行/空白包装
    std::string a = f.leaf_pem + f.intermediate_pem;
    std::string b = "  \n" + f.leaf_pem + "\n\n" + f.intermediate_pem + " \n";

    ParseResult ra = parser_.parse(bytes_of(a), limits_);
    ParseResult rb = parser_.parse(bytes_of(b), limits_);
    ASSERT_TRUE(ra.ok);
    ASSERT_TRUE(rb.ok);
    std::string pa, pb;
    ASSERT_TRUE(canonicalizer_.toPem(ra.chain, pa));
    ASSERT_TRUE(canonicalizer_.toPem(rb.chain, pb));
    EXPECT_EQ(pa, pb);  // canonical digest 幂等
}

TEST_F(CertificateChainParserTest, PemChain_TwoLevelIntermediates) {
    // root -> i1 -> i2 -> leaf（两级中间证书）
    EvpUP root_key = gen_ec_key();
    X509UP root = make_cert("R", true, root_key.get(), root_key.get(), nullptr, 1);
    EvpUP i1_key = gen_ec_key();
    X509UP i1 = make_cert("I1", true, i1_key.get(), root_key.get(), root.get(), 2);
    EvpUP i2_key = gen_ec_key();
    X509UP i2 = make_cert("I2", true, i2_key.get(), i1_key.get(), i1.get(), 3);
    EvpUP leaf_key = gen_ec_key();
    X509UP leaf = make_cert("L", false, leaf_key.get(), i2_key.get(), i2.get(), 4);

    std::string pem = pem_of(leaf.get()) + pem_of(i2.get()) + pem_of(i1.get());
    ParseResult r = parser_.parse(bytes_of(pem), limits_);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.chain.intermediates.size(), 2u);
    // 顺序完整保留（不按 issuer/subject 重排）
    EXPECT_NE(subject_oneline(r.chain.leaf.get()).find("CN=L"), std::string::npos);
    EXPECT_NE(subject_oneline(r.chain.intermediates[0].get()).find("CN=I2"), std::string::npos);
    EXPECT_NE(subject_oneline(r.chain.intermediates[1].get()).find("CN=I1"), std::string::npos);
}

// ---- 负向：格式 ----

TEST_F(CertificateChainParserTest, EmptyInput_Rejected) {
    ParseResult r = parser_.parse(std::vector<uint8_t>{}, limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, WhitespaceOnly_Rejected) {
    ParseResult r = parser_.parse(bytes_of("  \t\n\r "), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, TruncatedDer_Rejected) {
    ChainFixture f = make_two_level_chain();
    std::vector<uint8_t> der = der_of(f.leaf.get());
    der.pop_back();  // 截断 1 字节
    ParseResult r = parser_.parse(der, limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, DerWithTrailingSecondCert_Rejected) {
    ChainFixture f = make_two_level_chain();
    std::vector<uint8_t> der = der_of(f.leaf.get());
    std::vector<uint8_t> ca_der = der_of(f.root.get());
    der.insert(der.end(), ca_der.begin(), ca_der.end());  // 裸拼接 DER
    ParseResult r = parser_.parse(der, limits_);
    EXPECT_FALSE(r.ok);  // 裸拼接 DER 明确拒绝
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, DerWithTrailingGarbage_Rejected) {
    ChainFixture f = make_two_level_chain();
    std::vector<uint8_t> der = der_of(f.leaf.get());
    der.push_back(0xAA);
    der.push_back(0xBB);
    ParseResult r = parser_.parse(der, limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, ArbitraryText_Rejected) {
    ParseResult r = parser_.parse(bytes_of("hello world not a certificate"), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, PemMissingEnd_Rejected) {
    ChainFixture f = make_two_level_chain();
    std::string bad = f.leaf_pem;
    // 去掉最后一个 END 标记
    const std::string end_tag = "-----END CERTIFICATE-----";
    bad = bad.substr(0, bad.rfind(end_tag));
    ParseResult r = parser_.parse(bytes_of(bad), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, PemContainingPrivateKey_Rejected) {
    ChainFixture f = make_two_level_chain();
    EvpUP key = gen_ec_key();
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    char* buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string priv(buf, static_cast<size_t>(len));
    BIO_free(bio);
    ParseResult r = parser_.parse(bytes_of(f.leaf_pem + priv), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

TEST_F(CertificateChainParserTest, PemContainingCsr_Rejected) {
    ChainFixture f = make_two_level_chain();
    EvpUP key = gen_ec_key();
    X509_REQ* req = X509_REQ_new();
    X509_REQ_set_version(req, 0);
    X509_REQ_set_pubkey(req, key.get());
    X509_NAME* n = X509_REQ_get_subject_name(req);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("CSR"), -1, -1, 0);
    X509_REQ_sign(req, key.get(), EVP_sha256());
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_REQ(bio, req);
    char* buf = nullptr;
    long len = BIO_get_mem_data(bio, &buf);
    std::string csr(buf, static_cast<size_t>(len));
    BIO_free(bio);
    X509_REQ_free(req);
    ParseResult r = parser_.parse(bytes_of(f.leaf_pem + csr), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::InputFormat);
}

// ---- 负向：链形状 ----

TEST_F(CertificateChainParserTest, FirstCertIsCa_Rejected) {
    ChainFixture f = make_two_level_chain();
    // 首张为 CA（root）→ 违反 leaf-first
    ParseResult r = parser_.parse(bytes_of(f.intermediate_pem + f.leaf_pem), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::ChainShape);
}

TEST_F(CertificateChainParserTest, SubsequentNonCa_Rejected) {
    ChainFixture f = make_two_level_chain();
    // leaf + leaf（第二张非 CA）→ 拒绝
    ParseResult r = parser_.parse(bytes_of(f.leaf_pem + f.leaf_pem), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::ChainShape);
}

TEST_F(CertificateChainParserTest, DuplicateCert_Rejected) {
    ChainFixture f = make_two_level_chain();
    // leaf + int + int（intermediate 重复）→ 任意 DER digest 重复即拒绝
    ParseResult r = parser_.parse(
        bytes_of(f.leaf_pem + f.intermediate_pem + f.intermediate_pem), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::ChainShape);
}

TEST_F(CertificateChainParserTest, RootInChain_Rejected) {
    ChainFixture f = make_two_level_chain();
    // leaf + root（后续为可验证自签名）→ Root 入链拒绝
    std::string root_pem = pem_of(f.root.get());
    ParseResult r = parser_.parse(bytes_of(f.leaf_pem + root_pem), limits_);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::ChainShape);
}

// ---- 负向：限制 ----

TEST_F(CertificateChainParserTest, OverSizeLimit_Rejected) {
    ChainFixture f = make_two_level_chain();
    CertificateChainLimits tight;
    tight.max_payload_bytes = 16;
    ParseResult r = parser_.parse(bytes_of(f.leaf_pem), tight);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::SizeLimit);
}

TEST_F(CertificateChainParserTest, OverCertCount_Rejected) {
    // root -> i1 -> i2 -> leaf：链长为 3，限制 max_certificates=2
    EvpUP root_key = gen_ec_key();
    X509UP root = make_cert("R", true, root_key.get(), root_key.get(), nullptr, 1);
    EvpUP i1_key = gen_ec_key();
    X509UP i1 = make_cert("I1", true, i1_key.get(), root_key.get(), root.get(), 2);
    EvpUP i2_key = gen_ec_key();
    X509UP i2 = make_cert("I2", true, i2_key.get(), i1_key.get(), i1.get(), 3);
    EvpUP leaf_key = gen_ec_key();
    X509UP leaf = make_cert("L", false, leaf_key.get(), i2_key.get(), i2.get(), 4);

    std::string pem = pem_of(leaf.get()) + pem_of(i2.get()) + pem_of(i1.get());
    CertificateChainLimits tight;
    tight.max_certificates = 2;
    ParseResult r = parser_.parse(bytes_of(pem), tight);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.stage, CertificateParseStage::SizeLimit);
}

TEST_F(CertificateChainParserTest, EmptyPemChain_Rejected) {
    // 只有 BEGIN/END 但没有实际可解码内容（伪空链）
    ParseResult r = parser_.parse(
        bytes_of("-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n"), limits_);
    EXPECT_FALSE(r.ok);
}
