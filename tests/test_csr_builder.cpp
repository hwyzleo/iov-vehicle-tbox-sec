#include <gtest/gtest.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <cstdio>
#include <memory>
#include "csr_builder.h"
#include "key_engine.h"
#include "hsm_interface.h"

using namespace tbox::sec;

class CsrBuilderTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string test_dir = "/tmp/test_csr";
        std::string cmd = "mkdir -p " + test_dir;
        std::system(cmd.c_str());

        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, test_dir);
        key_engine = std::make_unique<KeyEngine>(std::move(hsm));
        key_engine->initialize();
        key_engine->generate_device_key(test_vin, test_ecu_uid, key_pair_);

        builder = std::make_unique<CsrBuilder>(key_engine.get());
    }

    void TearDown() override {
        std::string cmd = "rm -rf /tmp/test_csr";
        std::system(cmd.c_str());
    }

    std::unique_ptr<KeyEngine> key_engine;
    std::unique_ptr<CsrBuilder> builder;
    KeyPair key_pair_;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "TBOX-ECU-001";
};

TEST_F(CsrBuilderTest, BuildCsrSubjectCN) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);
    ASSERT_FALSE(csr_der.empty());

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr) << "Failed to parse CSR DER";

    X509_NAME* subject = X509_REQ_get_subject_name(req);
    ASSERT_NE(subject, nullptr);

    char cn[256];
    X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
    EXPECT_STREQ(cn, test_ecu_uid.c_str());

    char ou[256];
    X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, ou, sizeof(ou));
    EXPECT_STREQ(ou, "TBOX-TSP");

    char org[256];
    X509_NAME_get_text_by_NID(subject, NID_organizationName, org, sizeof(org));
    EXPECT_STREQ(org, "OpenIOV");

    char country[256];
    X509_NAME_get_text_by_NID(subject, NID_countryName, country, sizeof(country));
    EXPECT_STREQ(country, "CN");

    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrSAN) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    ASSERT_NE(exts, nullptr);

    bool found_san = false;
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2nid(obj) == NID_subject_alt_name) {
            found_san = true;
            GENERAL_NAMES* gens = static_cast<GENERAL_NAMES*>(
                X509V3_EXT_d2i(ext));
            ASSERT_NE(gens, nullptr);

            bool has_device_sn = false;
            for (int j = 0; j < sk_GENERAL_NAME_num(gens); j++) {
                GENERAL_NAME* gn = sk_GENERAL_NAME_value(gens, j);
                if (gn->type == GEN_URI) {
                    std::string uri(
                        reinterpret_cast<const char*>(
                            ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier)),
                        ASN1_STRING_length(gn->d.uniformResourceIdentifier));
                    if (uri.find(test_ecu_uid) != std::string::npos)
                        has_device_sn = true;
                }
            }
            sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
            EXPECT_TRUE(has_device_sn) << "device_sn not found in SAN";
            break;
        }
    }
    EXPECT_TRUE(found_san) << "SAN extension missing";

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, SanExtensionWithoutVin) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr("", config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    ASSERT_NE(exts, nullptr);

    bool found_san = false;
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2nid(obj) == NID_subject_alt_name) {
            found_san = true;
            GENERAL_NAMES* gens = static_cast<GENERAL_NAMES*>(
                X509V3_EXT_d2i(ext));
            ASSERT_NE(gens, nullptr);

            bool has_vin = false;
            bool has_device_sn = false;
            for (int j = 0; j < sk_GENERAL_NAME_num(gens); j++) {
                GENERAL_NAME* gn = sk_GENERAL_NAME_value(gens, j);
                if (gn->type == GEN_URI) {
                    std::string uri(
                        reinterpret_cast<const char*>(
                            ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier)),
                        ASN1_STRING_length(gn->d.uniformResourceIdentifier));
                    if (uri.find("urn:vin:") != std::string::npos)
                        has_vin = true;
                    if (uri.find(test_ecu_uid) != std::string::npos)
                        has_device_sn = true;
                }
            }
            sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
            EXPECT_FALSE(has_vin) << "VIN should not be in SAN when empty";
            EXPECT_TRUE(has_device_sn) << "device_sn not found in SAN";
            break;
        }
    }
    EXPECT_TRUE(found_san) << "SAN extension missing";

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrKeyUsage) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    ASSERT_NE(exts, nullptr);

    bool found_ku = false;
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2nid(obj) == NID_key_usage) {
            found_ku = true;
            ASN1_BIT_STRING* ku = static_cast<ASN1_BIT_STRING*>(
                X509V3_EXT_d2i(ext));
            ASSERT_NE(ku, nullptr);
            ASSERT_GT(ku->length, 0);
            EXPECT_TRUE(ku->data[0] & 0x80)
                << "digitalSignature bit not set";
            ASN1_BIT_STRING_free(ku);
            break;
        }
    }
    EXPECT_TRUE(found_ku) << "KeyUsage extension missing";

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrExtendedKeyUsage) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    STACK_OF(X509_EXTENSION)* exts = X509_REQ_get_extensions(req);
    ASSERT_NE(exts, nullptr);

    bool found_eku = false;
    for (int i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
        X509_EXTENSION* ext = sk_X509_EXTENSION_value(exts, i);
        ASN1_OBJECT* obj = X509_EXTENSION_get_object(ext);
        if (OBJ_obj2nid(obj) == NID_ext_key_usage) {
            found_eku = true;
            EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(
                X509V3_EXT_d2i(ext));
            ASSERT_NE(eku, nullptr);
            ASSERT_GT(sk_ASN1_OBJECT_num(eku), 0);

            ASN1_OBJECT* first = sk_ASN1_OBJECT_value(eku, 0);
            char buf[128];
            OBJ_obj2txt(buf, sizeof(buf), first, 1);
            EXPECT_STREQ(buf, "1.3.6.1.5.5.7.3.2") << "clientAuth OID mismatch";

            sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
            break;
        }
    }
    EXPECT_TRUE(found_eku) << "ExtendedKeyUsage extension missing";

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrPublicKey) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    EVP_PKEY* pubkey = X509_REQ_get0_pubkey(req);
    ASSERT_NE(pubkey, nullptr);
    EXPECT_EQ(EVP_PKEY_id(pubkey), EVP_PKEY_EC);

    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pubkey);
    ASSERT_NE(ec, nullptr);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    ASSERT_NE(group, nullptr);
    EXPECT_EQ(EC_GROUP_get_curve_name(group), NID_X9_62_prime256v1);

    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrSignature) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    const ASN1_BIT_STRING* sig = nullptr;
    const X509_ALGOR* sig_alg = nullptr;
    X509_REQ_get0_signature(req, &sig, &sig_alg);
    ASSERT_NE(sig, nullptr);
    ASSERT_GT(sig->length, 0);
    ASSERT_NE(sig->data, nullptr);

    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrSelfSignatureVerify) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    EVP_PKEY* pubkey = X509_REQ_get0_pubkey(req);
    ASSERT_NE(pubkey, nullptr);

    int rc = X509_REQ_verify(req, pubkey);
    EXPECT_EQ(rc, 1) << "CSR self-signature verification failed";

    X509_REQ_free(req);
}

TEST_F(CsrBuilderTest, BuildCsrWithNullEngine) {
    auto null_builder = std::make_unique<CsrBuilder>(nullptr);

    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    EXPECT_EQ(null_builder->build_csr(test_vin, config, csr_der),
              ErrorCode::INVALID_PARAMETER);
}

TEST_F(CsrBuilderTest, BuildCsrWithMissingKey) {
    CsrConfig config;
    config.device_sn = "NONEXISTENTECU";
    config.key_id = "NONEXISTENTECU";
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    EXPECT_EQ(builder->build_csr("NONEXISTENTVIN", config, csr_der), ErrorCode::KEY_NOT_FOUND);
}
