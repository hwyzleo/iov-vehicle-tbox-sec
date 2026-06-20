#include <gtest/gtest.h>
#include <cstdio>
#include "cert_validator.h"
#include "key_engine.h"
#include "hsm_interface.h"

using namespace tbox::sec;

class CertValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::string test_dir = "/tmp/test_cert";
        std::string cmd = "mkdir -p " + test_dir;
        std::system(cmd.c_str());

        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, test_dir);
        key_engine = std::make_unique<KeyEngine>(std::move(hsm));
        key_engine->initialize();

        // Generate test key
        KeyPair key_pair;
        key_engine->generate_device_key("TESTVIN1234567890", "TBOX-ECU-001", key_pair);

        validator = std::make_unique<CertValidator>(key_engine.get());
    }

    void TearDown() override {
        std::string cmd = "rm -rf /tmp/test_cert";
        std::system(cmd.c_str());
    }

    std::unique_ptr<KeyEngine> key_engine;
    std::unique_ptr<CertValidator> validator;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "TBOX-ECU-001";
};

TEST_F(CertValidatorTest, ValidateCertificate_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, empty_cert, valid);
    EXPECT_EQ(result, ErrorCode::CERT_EXPIRED);
    EXPECT_FALSE(valid);
}

TEST_F(CertValidatorTest, ValidateCertificate_InvalidDer) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER
    bool valid = false;
    ErrorCode result = validator->validate_certificate(test_vin, test_ecu_uid, cert_der, valid);
    EXPECT_NE(result, ErrorCode::SUCCESS);
    EXPECT_FALSE(valid);
}

TEST_F(CertValidatorTest, ExtractCertificateInfo_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    CertificateInfo info;
    ErrorCode result = validator->extract_certificate_info(empty_cert, info);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
}

TEST_F(CertValidatorTest, ExtractCertificateInfo_InvalidDer) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER
    CertificateInfo info;
    ErrorCode result = validator->extract_certificate_info(cert_der, info);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
}

TEST_F(CertValidatorTest, IsCertificateExpired_EmptyCert) {
    std::vector<uint8_t> empty_cert;
    EXPECT_TRUE(validator->is_certificate_expired(empty_cert));
}

TEST_F(CertValidatorTest, IsCertificateExpired_InvalidDer) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER
    EXPECT_TRUE(validator->is_certificate_expired(cert_der));
}

TEST_F(CertValidatorTest, ValidateCertificateChain_EmptyChain) {
    std::vector<std::vector<uint8_t>> empty_chain;
    bool valid = false;
    ErrorCode result = validator->validate_certificate_chain(empty_chain, valid);
    EXPECT_EQ(result, ErrorCode::CERT_VALIDATION_FAILED);
    EXPECT_FALSE(valid);
}

TEST_F(CertValidatorTest, ValidateCertificateChain_InvalidCert) {
    std::vector<std::vector<uint8_t>> chain = {{0x30, 0x82, 0x01, 0x00}};
    bool valid = false;
    ErrorCode result = validator->validate_certificate_chain(chain, valid);
    EXPECT_NE(result, ErrorCode::SUCCESS);
    EXPECT_FALSE(valid);
}
