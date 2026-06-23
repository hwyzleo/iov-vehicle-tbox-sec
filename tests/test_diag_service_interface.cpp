#include <gtest/gtest.h>
#include "diag_service_interface.h"

using namespace tbox::sec;

class DiagServiceInterfaceTest : public ::testing::Test {
protected:
    void SetUp() override {
    }
};

TEST_F(DiagServiceInterfaceTest, RequestTypeEnumeration) {
    EXPECT_EQ(static_cast<uint8_t>(DiagRequestType::GENERATE_KEY_PAIR), 0x01);
    EXPECT_EQ(static_cast<uint8_t>(DiagRequestType::READ_CSR), 0x02);
    EXPECT_EQ(static_cast<uint8_t>(DiagRequestType::INJECT_CERTIFICATE), 0x03);
    EXPECT_EQ(static_cast<uint8_t>(DiagRequestType::READ_PROVISION_STATE), 0x04);
    EXPECT_EQ(static_cast<uint8_t>(DiagRequestType::SUBMIT_CSR), 0x05);
    EXPECT_EQ(static_cast<uint8_t>(DiagRequestType::APPLY_CERTIFICATE), 0x06);
}

TEST_F(DiagServiceInterfaceTest, ResponseStructure) {
    DiagResponse response;
    response.error_code = ErrorCode::SUCCESS;
    response.data = {0x01, 0x02, 0x03};
    response.error_message = "Test";

    EXPECT_EQ(response.error_code, ErrorCode::SUCCESS);
    EXPECT_EQ(response.data.size(), 3);
    EXPECT_EQ(response.error_message, "Test");
}
