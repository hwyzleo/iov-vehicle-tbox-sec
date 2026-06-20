#include <gtest/gtest.h>
#include "uds_handler.h"
#include "sec_service.h"

using namespace tbox::sec;

class UdsHandlerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create mock SEC service
        auto sec_service = std::make_shared<SecService>();
        sec_service->initialize();
        handler = std::make_unique<UdsHandler>(sec_service);
        handler->initialize();
    }
    
    std::unique_ptr<UdsHandler> handler;
};

TEST_F(UdsHandlerTest, DiagnosticSessionControl) {
    UdsRequest request;
    request.service = UdsService::DIAGNOSTIC_SESSION_CONTROL;
    request.sub_function = 0x01; // Default session
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_FALSE(response.is_negative);
    EXPECT_EQ(handler->get_current_session(), 0x01);
}

TEST_F(UdsHandlerTest, SecurityAccess) {
    // Request seed
    UdsRequest request;
    request.service = UdsService::SECURITY_ACCESS;
    request.sub_function = 0x29; // Level 0x29
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_FALSE(response.is_negative);
    EXPECT_FALSE(response.data.empty());
    
    // Send key (simplified)
    request.sub_function = 0x2A; // Response for level 0x29
    request.data = {0x01, 0x02, 0x03, 0x04}; // Dummy key
    
    response = handler->handle_request(request);
    EXPECT_FALSE(response.is_negative);
    EXPECT_TRUE(handler->is_security_access_granted(UdsSecurityLevel::LEVEL_29));
}

TEST_F(UdsHandlerTest, ReadProvisionState) {
    // First get security access
    UdsRequest sec_request;
    sec_request.service = UdsService::SECURITY_ACCESS;
    sec_request.sub_function = 0x29;
    handler->handle_request(sec_request);
    
    sec_request.sub_function = 0x2A;
    sec_request.data = {0x01, 0x02, 0x03, 0x04};
    handler->handle_request(sec_request);
    
    // Read provision state
    UdsRequest request;
    request.service = UdsService::READ_DATA_BY_IDENTIFIER;
    request.did = 0xF100;
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_FALSE(response.is_negative);
}

TEST_F(UdsHandlerTest, SecurityAccessDenied) {
    // Try to read provision state without security access
    UdsRequest request;
    request.service = UdsService::READ_DATA_BY_IDENTIFIER;
    request.did = 0xF100;
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_TRUE(response.is_negative);
    EXPECT_EQ(response.negative_response_code, 0x33); // Security access denied
}

TEST_F(UdsHandlerTest, InvalidService) {
    UdsRequest request;
    request.service = static_cast<UdsService>(0xFF); // Invalid service
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_TRUE(response.is_negative);
    EXPECT_EQ(response.negative_response_code, 0x11); // Service not supported
}

TEST_F(UdsHandlerTest, InvalidSession) {
    UdsRequest request;
    request.service = UdsService::DIAGNOSTIC_SESSION_CONTROL;
    request.sub_function = 0x04; // Invalid session
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_TRUE(response.is_negative);
    EXPECT_EQ(response.negative_response_code, 0x12); // Sub-function not supported
}

TEST_F(UdsHandlerTest, WriteCertificate) {
    // First get security access
    UdsRequest sec_request;
    sec_request.service = UdsService::SECURITY_ACCESS;
    sec_request.sub_function = 0x29;
    handler->handle_request(sec_request);
    
    sec_request.sub_function = 0x2A;
    sec_request.data = {0x01, 0x02, 0x03, 0x04};
    handler->handle_request(sec_request);
    
    // Write certificate
    UdsRequest request;
    request.service = UdsService::WRITE_DATA_BY_IDENTIFIER;
    request.did = 0xF102;
    request.data = {0x30, 0x82, 0x01, 0x22}; // Dummy certificate data
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_FALSE(response.is_negative);
}

TEST_F(UdsHandlerTest, GenerateKeyPair) {
    // First get security access
    UdsRequest sec_request;
    sec_request.service = UdsService::SECURITY_ACCESS;
    sec_request.sub_function = 0x29;
    handler->handle_request(sec_request);
    
    sec_request.sub_function = 0x2A;
    sec_request.data = {0x01, 0x02, 0x03, 0x04};
    handler->handle_request(sec_request);
    
    // Generate key pair
    UdsRequest request;
    request.service = UdsService::ROUTINE_CONTROL;
    request.rid = 0xFF00;
    
    UdsResponse response = handler->handle_request(request);
    EXPECT_FALSE(response.is_negative);
}

TEST_F(UdsHandlerTest, UninitializedHandler) {
    auto sec_service = std::make_shared<SecService>();
    auto uninitialized_handler = std::make_unique<UdsHandler>(sec_service);
    
    UdsRequest request;
    request.service = UdsService::DIAGNOSTIC_SESSION_CONTROL;
    request.sub_function = 0x01;
    
    UdsResponse response = uninitialized_handler->handle_request(request);
    EXPECT_TRUE(response.is_negative);
    EXPECT_EQ(response.negative_response_code, 0x22); // Conditions not correct
}
