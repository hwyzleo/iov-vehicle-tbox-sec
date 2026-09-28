// CertificateStore 单元测试（TBOX-SEC-DSN-CR-014 §4.1）
// 验证跨键原子提交：immutable generation + commit manifest + 单文件 CURRENT 指针，
// 启动恢复（orphan / CURRENT.tmp / 损坏 generation / previous_generation 回退），
// 以及“任一时刻只存在旧完整代或新完整代、无跨代混合”的故障注入语义。
#include <gtest/gtest.h>

#include "certificate_store.h"
#include "tbox/sec/errors.h"

#include <cstdio>
#include <fstream>
#include <filesystem>
#include <system_error>

using namespace tbox::sec;

namespace fs = std::filesystem;

namespace {

std::string readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    return std::string((std::istreambuf_iterator<char>(f)),
                       std::istreambuf_iterator<char>());
}

CertificateCommit makeCommit(const std::string& pem, uint64_t version) {
    CertificateCommit c;
    c.device_cert_chain_pem = pem;
    nlohmann::json dc;
    dc["cert_id"] = "vin:ecu";
    dc["bound_vin"] = "vin";
    dc["bound_ecu_uid"] = "ecu";
    dc["status"] = "ACTIVE";
    dc["version"] = version;
    c.device_cert_json = dc.dump();
    c.provision_state = "CERT_INSTALLED";
    c.version = version;
    return c;
}

} // namespace

class CertificateStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        root_ = "/tmp/test_cert_store_" + std::to_string(::getpid());
        std::system(("rm -rf " + root_).c_str());
    }
    void TearDown() override {
        std::system(("rm -rf " + root_).c_str());
    }

    std::string root_;
};

TEST_F(CertificateStoreTest, FreshStore_NoCurrent) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    EXPECT_FALSE(store.hasCurrent());
    EXPECT_EQ(store.currentDeviceCertChain(), "");
    EXPECT_EQ(store.currentChainDigest(), "");
}

TEST_F(CertificateStoreTest, Commit_ThenCurrentVisible) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    EXPECT_EQ(store.commit(makeCommit("PEM-A", 1)), ErrorCode::SUCCESS);
    EXPECT_TRUE(store.hasCurrent());
    EXPECT_EQ(store.currentDeviceCertChain(), "PEM-A");
    EXPECT_EQ(store.currentChainDigest().size(), 64u);
    auto snap = store.currentSnapshot();
    ASSERT_TRUE(snap.has_value());
    EXPECT_EQ(snap->version, 1u);
    EXPECT_EQ(snap->provision_state, "CERT_INSTALLED");
    EXPECT_EQ(snap->device_cert.value("bound_ecu_uid", ""), "ecu");
}

TEST_F(CertificateStoreTest, Commit_VersionMonotonic) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    ASSERT_EQ(store.commit(makeCommit("PEM-1", 1)), ErrorCode::SUCCESS);
    ASSERT_EQ(store.commit(makeCommit("PEM-2", 2)), ErrorCode::SUCCESS);
    ASSERT_EQ(store.commit(makeCommit("PEM-3", 3)), ErrorCode::SUCCESS);
    auto snap = store.currentSnapshot();
    ASSERT_TRUE(snap.has_value());
    EXPECT_EQ(snap->version, 3u);
    EXPECT_EQ(snap->device_cert_chain_pem, "PEM-3");
}

TEST_F(CertificateStoreTest, Commit_EmptyPem_Rejected) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    CertificateCommit c;
    c.device_cert_chain_pem = "";
    c.device_cert_json = "{}";
    c.version = 1;
    EXPECT_NE(store.commit(c), ErrorCode::SUCCESS);
    EXPECT_FALSE(store.hasCurrent());
}

TEST_F(CertificateStoreTest, Reopen_PersistsCurrent) {
    {
        CertificateStore store(root_);
        ASSERT_TRUE(store.openAndRecover());
        ASSERT_EQ(store.commit(makeCommit("PEM-PERSIST", 7)), ErrorCode::SUCCESS);
    }
    CertificateStore store2(root_);
    ASSERT_TRUE(store2.openAndRecover());
    EXPECT_TRUE(store2.hasCurrent());
    EXPECT_EQ(store2.currentDeviceCertChain(), "PEM-PERSIST");
    auto snap = store2.currentSnapshot();
    ASSERT_TRUE(snap.has_value());
    EXPECT_EQ(snap->version, 7u);
}

TEST_F(CertificateStoreTest, OrphanCandidate_CleanedOnRecover) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    ASSERT_EQ(store.commit(makeCommit("PEM-KEEP", 1)), ErrorCode::SUCCESS);

    // 模拟未切换 CURRENT 的候选 generation（手动创建孤儿目录）
    fs::create_directories(root_ + "/generations/g-orphan");
    { std::ofstream f(root_ + "/generations/g-orphan/manifest.json"); f << "{}"; }
    { std::ofstream f(root_ + "/generations/g-orphan/device_cert_chain.pem"); f << "junk"; }

    CertificateStore store2(root_);
    ASSERT_TRUE(store2.openAndRecover());
    EXPECT_TRUE(store2.hasCurrent());
    EXPECT_EQ(store2.currentDeviceCertChain(), "PEM-KEEP");
    // orphan 已被清理
    EXPECT_FALSE(fs::exists(root_ + "/generations/g-orphan"));
}

TEST_F(CertificateStoreTest, LeftoverCurrentTmp_Ignored) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    ASSERT_EQ(store.commit(makeCommit("PEM-CURRENT", 2)), ErrorCode::SUCCESS);

    // 残留 CURRENT.tmp（切换中断）：不得生效，旧 CURRENT 继续有效
    { std::ofstream f(root_ + "/CURRENT.tmp"); f << "g-bogus\n"; }

    CertificateStore store2(root_);
    ASSERT_TRUE(store2.openAndRecover());
    EXPECT_EQ(store2.currentDeviceCertChain(), "PEM-CURRENT");
}

TEST_F(CertificateStoreTest, CorruptCurrent_RollbackToPrevious) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    ASSERT_EQ(store.commit(makeCommit("PEM-V1", 1)), ErrorCode::SUCCESS);
    ASSERT_EQ(store.commit(makeCommit("PEM-V2", 2)), ErrorCode::SUCCESS);

    // 破坏 CURRENT 指向的 V2 的证书链文件（截断）→ 校验失败 → 回退 V1
    std::string cur = readFile(root_ + "/CURRENT");
    std::string gid = cur.substr(0, cur.find('\n'));
    ASSERT_FALSE(gid.empty());
    { std::ofstream f(root_ + "/generations/" + gid + "/device_cert_chain.pem", std::ios::trunc); f << "broken"; }

    CertificateStore store2(root_);
    ASSERT_TRUE(store2.openAndRecover());
    EXPECT_EQ(store2.currentDeviceCertChain(), "PEM-V1");
    auto snap = store2.currentSnapshot();
    ASSERT_TRUE(snap.has_value());
    EXPECT_EQ(snap->version, 1u);
}

TEST_F(CertificateStoreTest, CorruptCurrent_NoValidChain_RecoverFails) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    // CURRENT 指向不存在且无 previous 链的 gid
    { std::ofstream f(root_ + "/CURRENT"); f << "g-nonexistent\n"; }
    CertificateStore store2(root_);
    // 回退链耗尽：保持无当前，进入 ERROR
    EXPECT_FALSE(store2.openAndRecover());
    EXPECT_FALSE(store2.hasCurrent());
}

TEST_F(CertificateStoreTest, TamperedManifestDigest_Rejected) {
    CertificateStore store(root_);
    ASSERT_TRUE(store.openAndRecover());
    ASSERT_EQ(store.commit(makeCommit("PEM-A", 1)), ErrorCode::SUCCESS);

    // 篡改 CURRENT generation 的 manifest 中 sha256（校验失败 → 视作损坏 → 回退）
    std::string cur = readFile(root_ + "/CURRENT");
    std::string gid = cur.substr(0, cur.find('\n'));
    std::string manifest_path = root_ + "/generations/" + gid + "/manifest.json";
    auto m = nlohmann::json::parse(readFile(manifest_path));
    m["files"]["device_cert_chain.pem"]["sha256"] = std::string(64, '0');
    { std::ofstream f(manifest_path, std::ios::trunc); f << m.dump(); }

    CertificateStore store2(root_);
    // 唯一 generation 已损坏且无 previous 可回退 → 保持无当前、进入 ERROR（fail-closed）
    EXPECT_FALSE(store2.openAndRecover());
    EXPECT_FALSE(store2.hasCurrent());
}
