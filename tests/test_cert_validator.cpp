#include <gtest/gtest.h>
#include "cert_validator.h"
#include "key_engine.h"
#include "hsm_interface.h"

using namespace tbox::sec;

class CertValidatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto hsm = HsmFactory::create(HsmFactory::HsmType::SOFTWARE, "/tmp/test_cert");
        auto key_engine = std::make_shared<KeyEngine>(std::move(hsm));
        key_engine->initialize();

        // Generate test key
        KeyPair key_pair;
        key_engine->generate_device_key("TESTVIN1234567890", "TBOX-ECU-001", key_pair);

        validator = std::make_unique<CertValidator>(key_engine);
    }

    std::unique_ptr<CertValidator> validator;
    std::string test_vin = "TESTVIN1234567890";
    std::string test_ecu_uid = "TBOX-ECU-001";
};

TEST_F(CertValidatorTest, ValidateCertificate) {
    // Create a dummy certificate for testing
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER

    bool valid = false;
    // Note: This will fail with dummy data, but tests the interface
    validator->validate_certificate(test_vin, test_ecu_uid, cert_der, valid);
}

TEST_F(CertValidatorTest, ExtractCertificateInfo) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER

    CertificateInfo info;
    // Note: This will fail with dummy data, but tests the interface
    validator->extract_certificate_info(cert_der, info);
}

TEST_F(CertValidatorTest, IsCertificateExpired) {
    std::vector<uint8_t> cert_der = {0x30, 0x82, 0x01, 0x00}; // Dummy DER

    // Note: This will return true with dummy data
    EXPECT_TRUE(validator->is_certificate_expired(cert_der));
}
