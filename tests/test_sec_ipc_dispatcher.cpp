#include "gtest/gtest.h"
#include "sec_ipc_dispatcher.h"
#include "sec_service.h"
#include "ipc_protocol.h"
#include <nlohmann/json.hpp>

using namespace tbox::sec;
using json = nlohmann::json;

// ============================================================
// MockSecService - overrides virtual methods for testing
// ============================================================
class MockSecService : public SecService {
public:
    MockSecService() : SecService() {}

    // Control flags
    ErrorCode init_result = ErrorCode::SUCCESS;
    ErrorCode gen_key_result = ErrorCode::SUCCESS;
    ErrorCode export_key_result = ErrorCode::SUCCESS;
    ErrorCode get_csr_result = ErrorCode::SUCCESS;
    ErrorCode submit_csr_result = ErrorCode::SUCCESS;
    ErrorCode inject_cert_result = ErrorCode::SUCCESS;
    ErrorCode apply_cert_result = ErrorCode::SUCCESS;
    ErrorCode set_ca_cert_result = ErrorCode::SUCCESS;
    ErrorCode get_seed_result = ErrorCode::SUCCESS;
    ErrorCode verify_key_result = ErrorCode::SUCCESS;
    ErrorCode reset_result = ErrorCode::SUCCESS;

    // Test data
    std::vector<uint8_t> mock_private_key = {0x01, 0x02, 0x03};
    std::vector<uint8_t> mock_csr = {0x30, 0x82, 0x01, 0x00};
    std::vector<uint8_t> mock_seed = {0xAA, 0xBB, 0xCC, 0xDD};
    ProvisionStatus mock_status;
    std::string mock_device_info = "TBOX-DEV-001";

    // Track calls
    bool initialize_called = false;
    bool generate_key_pair_called = false;
    bool export_private_key_called = false;
    bool get_csr_called = false;
    bool submit_csr_called = false;
    bool inject_certificate_called = false;
    bool apply_certificate_called = false;
    bool set_ca_certificate_called = false;
    bool get_seed_called = false;
    bool verify_key_called = false;
    bool get_provision_status_called = false;
    bool get_device_info_called = false;
    bool reset_provision_status_called = false;

    // Last received params
    std::vector<uint8_t> last_cert_der;
    std::vector<uint8_t> last_ca_cert_der;
    std::vector<uint8_t> last_key;
    uint8_t last_seed_level = 0;
    uint8_t last_verify_level = 0;

    ErrorCode initialize() override {
        initialize_called = true;
        return init_result;
    }

    ErrorCode generate_key_pair() override {
        generate_key_pair_called = true;
        return gen_key_result;
    }

    ErrorCode export_private_key(std::vector<uint8_t>& private_key) override {
        export_private_key_called = true;
        private_key = mock_private_key;
        return export_key_result;
    }

    ErrorCode get_csr(std::vector<uint8_t>& csr_der) override {
        get_csr_called = true;
        csr_der = mock_csr;
        return get_csr_result;
    }

    ErrorCode submit_csr() override {
        submit_csr_called = true;
        return submit_csr_result;
    }

    ErrorCode inject_certificate(const std::vector<uint8_t>& cert_der) override {
        inject_certificate_called = true;
        last_cert_der = cert_der;
        return inject_cert_result;
    }

    ErrorCode apply_certificate() override {
        apply_certificate_called = true;
        return apply_cert_result;
    }

    ErrorCode set_ca_certificate(const std::vector<uint8_t>& ca_cert_der) override {
        set_ca_certificate_called = true;
        last_ca_cert_der = ca_cert_der;
        return set_ca_cert_result;
    }

    ErrorCode get_seed(uint8_t level, std::vector<uint8_t>& seed) override {
        get_seed_called = true;
        last_seed_level = level;
        seed = mock_seed;
        return get_seed_result;
    }

    ErrorCode verify_key(uint8_t level, const std::vector<uint8_t>& key) override {
        verify_key_called = true;
        last_verify_level = level;
        last_key = key;
        return verify_key_result;
    }

    ProvisionStatus get_provision_status() const override {
        const_cast<MockSecService*>(this)->get_provision_status_called = true;
        return mock_status;
    }

    std::string get_device_info() const override {
        const_cast<MockSecService*>(this)->get_device_info_called = true;
        return mock_device_info;
    }

    ErrorCode reset_provision_status() override {
        reset_provision_status_called = true;
        return reset_result;
    }
};

// ============================================================
// Test fixture
// ============================================================
class SecIpcDispatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        mock_service_ = std::make_unique<MockSecService>();
        dispatcher_ = std::make_unique<SecIpcDispatcher>(mock_service_.get());

        // Set up default mock status
        mock_service_->mock_status.vin = "TESTVIN1234567890";
        mock_service_->mock_status.ecu_uid = "TBOX-DEV-001";
        mock_service_->mock_status.state = ProvisionState::NONE;
        mock_service_->mock_status.last_error = "";
        mock_service_->mock_status.retry_count = 0;
    }

    void TearDown() override {}

    /// Parse dispatcher response JSON and extract status field
    int32_t extract_status(const std::string& response_json) {
        try {
            auto j = json::parse(response_json);
            return j.value("status", -1);
        } catch (...) {
            return -1;
        }
    }

    std::unique_ptr<MockSecService> mock_service_;
    std::unique_ptr<SecIpcDispatcher> dispatcher_;
};

// ============================================================
// Method dispatch tests
// ============================================================

TEST_F(SecIpcDispatcherTest, DispatchInitialize) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::INITIALIZE), "{}", 0);

    EXPECT_TRUE(mock_service_->initialize_called);
    EXPECT_EQ(extract_status(response), 0);

    auto j = json::parse(response);
    EXPECT_TRUE(j.value("success", false));
}

TEST_F(SecIpcDispatcherTest, DispatchGenerateKeyPair) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GENERATE_KEY_PAIR), "{}", 0);

    EXPECT_TRUE(mock_service_->generate_key_pair_called);
    EXPECT_EQ(extract_status(response), 0);
}

TEST_F(SecIpcDispatcherTest, DispatchExportPrivateKey) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::EXPORT_PRIVATE_KEY), "{}", 0);

    EXPECT_TRUE(mock_service_->export_private_key_called);
    EXPECT_EQ(extract_status(response), 0);

    auto j = json::parse(response);
    EXPECT_FALSE(j.value("private_key", "").empty());
}

TEST_F(SecIpcDispatcherTest, DispatchGetCsr) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_CSR), "{}", 0);

    EXPECT_TRUE(mock_service_->get_csr_called);
    EXPECT_EQ(extract_status(response), 0);

    auto j = json::parse(response);
    EXPECT_FALSE(j.value("csr", "").empty());
}

TEST_F(SecIpcDispatcherTest, DispatchSubmitCsr) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SUBMIT_CSR), "{}", 0);

    EXPECT_TRUE(mock_service_->submit_csr_called);
    EXPECT_EQ(extract_status(response), 0);
}

TEST_F(SecIpcDispatcherTest, DispatchInjectCertificate) {
    std::vector<uint8_t> cert = {0x30, 0x82, 0x01, 0x00};
    json params;
    params["cert"] = "MIIBAQA=";  // base64 of some data
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE),
        params.dump(), 0);

    EXPECT_TRUE(mock_service_->inject_certificate_called);
    EXPECT_FALSE(mock_service_->last_cert_der.empty());
}

TEST_F(SecIpcDispatcherTest, DispatchInjectCertificateMissingParam) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE),
        "{}", 0);

    EXPECT_FALSE(mock_service_->inject_certificate_called);
    EXPECT_EQ(extract_status(response),
        static_cast<int32_t>(ErrorCode::INVALID_PARAMETER));
}

TEST_F(SecIpcDispatcherTest, DispatchApplyCertificate) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::APPLY_CERTIFICATE), "{}", 0);

    EXPECT_TRUE(mock_service_->apply_certificate_called);
    EXPECT_EQ(extract_status(response), 0);
}

TEST_F(SecIpcDispatcherTest, DispatchSetCaCertificate) {
    json params;
    params["cert"] = "MIIBAQA=";
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::SET_CA_CERTIFICATE),
        params.dump(), 0);

    EXPECT_TRUE(mock_service_->set_ca_certificate_called);
    EXPECT_FALSE(mock_service_->last_ca_cert_der.empty());
}

TEST_F(SecIpcDispatcherTest, DispatchGetSeed) {
    json params;
    params["level"] = 0x29;
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_SEED),
        params.dump(), 0);

    EXPECT_TRUE(mock_service_->get_seed_called);
    EXPECT_EQ(mock_service_->last_seed_level, 0x29);
    EXPECT_EQ(extract_status(response), 0);

    auto j = json::parse(response);
    EXPECT_FALSE(j.value("seed", "").empty());
}

TEST_F(SecIpcDispatcherTest, DispatchVerifyKey) {
    json params;
    params["level"] = 0x29;
    params["key"] = "MIIBAQA=";
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY),
        params.dump(), 0);

    EXPECT_TRUE(mock_service_->verify_key_called);
    EXPECT_EQ(mock_service_->last_verify_level, 0x29);
    EXPECT_FALSE(mock_service_->last_key.empty());
}

TEST_F(SecIpcDispatcherTest, DispatchVerifyKeyMissingParam) {
    json params;
    params["level"] = 0x29;
    // Missing "key" field
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY),
        params.dump(), 0);

    EXPECT_FALSE(mock_service_->verify_key_called);
    EXPECT_EQ(extract_status(response),
        static_cast<int32_t>(ErrorCode::INVALID_PARAMETER));
}

TEST_F(SecIpcDispatcherTest, DispatchGetStatus) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_STATUS), "{}", 0);

    EXPECT_TRUE(mock_service_->get_provision_status_called);
    EXPECT_EQ(extract_status(response), 0);

    auto j = json::parse(response);
    EXPECT_EQ(j.value("vin", ""), "TESTVIN1234567890");
    EXPECT_EQ(j.value("ecu_uid", ""), "TBOX-DEV-001");
    EXPECT_EQ(j.value("state", ""), "NONE");
}

TEST_F(SecIpcDispatcherTest, DispatchGetDeviceInfo) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_DEVICE_INFO), "{}", 0);

    EXPECT_TRUE(mock_service_->get_device_info_called);
    EXPECT_EQ(extract_status(response), 0);

    auto j = json::parse(response);
    EXPECT_EQ(j.value("device_info", ""), "TBOX-DEV-001");
}

TEST_F(SecIpcDispatcherTest, DispatchResetStatus) {
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::RESET_STATUS), "{}", 0);

    EXPECT_TRUE(mock_service_->reset_provision_status_called);
    EXPECT_EQ(extract_status(response), 0);
}

// ============================================================
// Error handling tests
// ============================================================

TEST_F(SecIpcDispatcherTest, DispatchUnknownMethod) {
    std::string response = dispatcher_->dispatch(9999, "{}", 0);

    // FW-0306 = handler failed
    EXPECT_EQ(extract_status(response), 306);

    auto j = json::parse(response);
    EXPECT_EQ(j.value("error", ""), "Unknown method");
}

TEST_F(SecIpcDispatcherTest, DispatchInvalidJson) {
    // Inject certificate with invalid JSON
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE),
        "not valid json", 0);

    // FW-0305 = serialization failed
    EXPECT_EQ(extract_status(response), 305);
}

TEST_F(SecIpcDispatcherTest, DispatchBusinessError) {
    mock_service_->get_seed_result = ErrorCode::SEED_GENERATION_FAILED;

    json params;
    params["level"] = 0x29;
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::GET_SEED),
        params.dump(), 0);

    EXPECT_EQ(extract_status(response),
        static_cast<int32_t>(ErrorCode::SEED_GENERATION_FAILED));
}

TEST_F(SecIpcDispatcherTest, ResponseContainsStatusField) {
    // All responses must have a "status" field (business status code)
    std::string response = dispatcher_->dispatch(
        static_cast<uint32_t>(ipc::MethodId::INITIALIZE), "{}", 0);

    auto j = json::parse(response);
    EXPECT_TRUE(j.contains("status"));
}
