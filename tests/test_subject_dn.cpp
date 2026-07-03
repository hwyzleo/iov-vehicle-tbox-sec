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
#include "constants.h"

using namespace tbox::sec;

class SubjectDnTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string test_dir = "/tmp/test_subject_dn";
        std::string cmd = "mkdir -p " + test_dir;
        std::system(cmd.c_str());

        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, test_dir);
        key_engine = std::make_unique<KeyEngine>(std::move(hsm));
        key_engine->initialize();
        key_engine->generate_device_key(test_vin, test_ecu_uid, key_pair_);

        builder = std::make_unique<CsrBuilder>(key_engine.get());
    }

    void TearDown() override {
        std::string cmd = "rm -rf /tmp/test_subject_dn";
        std::system(cmd.c_str());
    }

    std::unique_ptr<KeyEngine> key_engine;
    std::unique_ptr<CsrBuilder> builder;
    KeyPair key_pair_;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "00000000000000000000000000000001";
};

TEST_F(SubjectDnTest, FullSubjectDn) {
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
    EXPECT_STREQ(ou, CSR_SUBJECT_OU);

    char org[256];
    X509_NAME_get_text_by_NID(subject, NID_organizationName, org, sizeof(org));
    EXPECT_STREQ(org, CSR_SUBJECT_O);

    char country[256];
    X509_NAME_get_text_by_NID(subject, NID_countryName, country, sizeof(country));
    EXPECT_STREQ(country, CSR_SUBJECT_C);

    X509_REQ_free(req);
}

TEST_F(SubjectDnTest, SubjectDnFixedFields) {
    CsrConfig config;
    config.device_sn = test_ecu_uid;
    config.key_id = test_ecu_uid;
    config.algorithm = "SHA256withECDSA";

    std::vector<uint8_t> csr_der;
    ASSERT_EQ(builder->build_csr(test_vin, config, csr_der), ErrorCode::SUCCESS);

    const unsigned char* p = csr_der.data();
    X509_REQ* req = d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size()));
    ASSERT_NE(req, nullptr);

    X509_NAME* subject = X509_REQ_get_subject_name(req);
    ASSERT_NE(subject, nullptr);

    char ou[256];
    X509_NAME_get_text_by_NID(subject, NID_organizationalUnitName, ou, sizeof(ou));
    EXPECT_STREQ(ou, "TBOX-TSP") << "OU should be TBOX-TSP";

    char org[256];
    X509_NAME_get_text_by_NID(subject, NID_organizationName, org, sizeof(org));
    EXPECT_STREQ(org, "OpenIOV") << "O should be OpenIOV";

    char country[256];
    X509_NAME_get_text_by_NID(subject, NID_countryName, country, sizeof(country));
    EXPECT_STREQ(country, "CN") << "C should be CN";

    X509_REQ_free(req);
}

TEST_F(SubjectDnTest, SanContainsDeviceSn) {
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
            EXPECT_TRUE(has_device_sn) << "device_sn should be in SAN";
            break;
        }
    }
    EXPECT_TRUE(found_san) << "SAN extension missing";

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    X509_REQ_free(req);
}
