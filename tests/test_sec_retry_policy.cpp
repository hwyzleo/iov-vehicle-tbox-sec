#include "gtest/gtest.h"
#include "sec_retry_policy.h"
#include "ipc_protocol.h"

using namespace tbox::sec;

class SecRetryPolicyTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// ============================================================
// categorize() tests
// ============================================================

TEST_F(SecRetryPolicyTest, CategorizeReadOnlyMethods) {
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GET_STATUS)),
        SecRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GET_DEVICE_INFO)),
        SecRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GET_CSR)),
        SecRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::EXPORT_PRIVATE_KEY)),
        SecRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::RESET_STATUS)),
        SecRetryPolicy::Category::kReadOnly);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::INITIALIZE)),
        SecRetryPolicy::Category::kReadOnly);
}

TEST_F(SecRetryPolicyTest, CategorizeBusinessIdempotent) {
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GENERATE_KEY_PAIR)),
        SecRetryPolicy::Category::kBusinessIdempotent);
}

TEST_F(SecRetryPolicyTest, CategorizeOneShot) {
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::GET_SEED)),
        SecRetryPolicy::Category::kOneShot);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY)),
        SecRetryPolicy::Category::kOneShot);
}

TEST_F(SecRetryPolicyTest, CategorizeWrite) {
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE)),
        SecRetryPolicy::Category::kWrite);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::APPLY_CERTIFICATE)),
        SecRetryPolicy::Category::kWrite);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::SET_CA_CERTIFICATE)),
        SecRetryPolicy::Category::kWrite);
    EXPECT_EQ(SecRetryPolicy::categorize(
        static_cast<uint32_t>(ipc::MethodId::SUBMIT_CSR)),
        SecRetryPolicy::Category::kWrite);
}

TEST_F(SecRetryPolicyTest, CategorizeUnknownMethodIsOneShot) {
    // Unknown method IDs should be conservative (kOneShot = no retry)
    EXPECT_EQ(SecRetryPolicy::categorize(9999),
        SecRetryPolicy::Category::kOneShot);
    EXPECT_EQ(SecRetryPolicy::categorize(0),
        SecRetryPolicy::Category::kOneShot);
}

// ============================================================
// should_retry() tests
// ============================================================

TEST_F(SecRetryPolicyTest, ShouldRetryReadOnlyMethods) {
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_STATUS)));
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_DEVICE_INFO)));
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_CSR)));
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::EXPORT_PRIVATE_KEY)));
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::RESET_STATUS)));
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::INITIALIZE)));
}

TEST_F(SecRetryPolicyTest, ShouldRetryBusinessIdempotent) {
    EXPECT_TRUE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GENERATE_KEY_PAIR)));
}

TEST_F(SecRetryPolicyTest, ShouldNotRetryOneShot) {
    EXPECT_FALSE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::GET_SEED)));
    EXPECT_FALSE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::VERIFY_KEY)));
}

TEST_F(SecRetryPolicyTest, ShouldNotRetryWrite) {
    EXPECT_FALSE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::INJECT_CERTIFICATE)));
    EXPECT_FALSE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::APPLY_CERTIFICATE)));
    EXPECT_FALSE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::SET_CA_CERTIFICATE)));
    EXPECT_FALSE(SecRetryPolicy::should_retry(
        static_cast<uint32_t>(ipc::MethodId::SUBMIT_CSR)));
}

TEST_F(SecRetryPolicyTest, ShouldNotRetryUnknown) {
    EXPECT_FALSE(SecRetryPolicy::should_retry(9999));
    EXPECT_FALSE(SecRetryPolicy::should_retry(0));
}
