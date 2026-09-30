#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <openssl/x509.h>

namespace tbox {
namespace sec {

/// RAII 所有权：X509 对象（OpenSSL X509_free）
struct X509Deleter {
    void operator()(X509* p) const { if (p) X509_free(p); }
};
using UniqueX509 = std::unique_ptr<X509, X509Deleter>;

/// 轻量只读字节视图（C++17 兼容，等价 std::span<const uint8_t>）。
/// 仅借用调用方内存，不持有所有权。
struct ByteView {
    const uint8_t* data = nullptr;
    size_t size = 0;

    ByteView() = default;
    ByteView(const uint8_t* d, size_t n) : data(d), size(n) {}
    ByteView(const std::vector<uint8_t>& v) : data(v.data()), size(v.size()) {}
    ByteView(const std::string& s)
        : data(reinterpret_cast<const uint8_t*>(s.data())), size(s.size()) {}

    const uint8_t* begin() const { return data; }
    const uint8_t* end() const { return data + size; }
    bool empty() const { return size == 0; }
};

/// 证书输入格式（TBOX-SEC-DSN-CR-018 §3.1 自动分流）
enum class CertificateInputFormat { DerSingle, PemChain };

/// 解析失败阶段（TBOX-SEC-DSN-CR-018 §7 错误映射）。
/// 内部事件/测试可区分阶段；对外仍映射既有 wire code。
enum class CertificateParseStage {
    Ok = 0,        ///< 成功
    InputFormat,   ///< 非 DER/PEM、混合块、尾随数据、缺 END、块内容非法
    ChainShape,    ///< 空链、顺序错误、Root 入链、重复证书
    SizeLimit      ///< 总长或证书数量超限
};

/// 阶段 → 可读字符串（日志 failure_stage 字段用；不得输出 payload/证书内容）
const char* certificate_parse_stage_to_string(CertificateParseStage stage);

/// 一次解析的结果：ParsedCertificateChain 只在本次请求生命周期内存在（RAII 管理 X509）。
struct ParsedCertificateChain {
    CertificateInputFormat format = CertificateInputFormat::DerSingle;
    UniqueX509 leaf;                          ///< 第一张证书（leaf）
    std::vector<UniqueX509> intermediates;    ///< leaf 之后的 intermediate(s)
    /// 各证书 DER 的 SHA-256（重复检测 / Root 比对用；日志不得输出 digest 全值或原始证书）
    std::vector<std::array<uint8_t, 32>> cert_der_sha256;
};

/// 链解析限制（TBOX-SEC-DSN-CR-018 §3.3 / §8）
struct CertificateChainLimits {
    size_t max_payload_bytes{8192};  ///< 总输入上限（含前导空白）
    size_t max_certificates{4};      ///< 证书数量上限 1..max_certificates
};

/// 统一证书链解析结果
struct ParseResult {
    bool ok = false;
    CertificateParseStage stage = CertificateParseStage::InputFormat;
    ParsedCertificateChain chain;
};

/// 严格证书链解析器（TBOX-SEC-DSN-CR-018 §3）。
///
/// 职责边界：
///  - 自动分流：首非空字节以 -----BEGIN CERTIFICATE----- 开头 → PEM 链，否则 legacy 单 DER；
///  - 严格格式：DER 必须消费到末尾（裸拼接 DER 拒绝）；PEM 只允许 CERTIFICATE 块与空白；
///  - 链形状：leaf-first（首张非 CA）、后续 basicConstraints CA=TRUE、无重复证书、
///    Root 入链拒绝（后续可验证自签名证书拒绝）；
///  - 数量 1..max_certificates、总长 ≤ max_payload_bytes。
///
/// 不访问 Root Store / TrustedTimeProvider / HSM / Provider，不做签名/path validation。
/// 与 Loader 导入 Root 同证书的拒绝在独立的安装策略检查（SecService）中执行。
class CertificateChainParser {
public:
    /// 严格解析完整输入；所选模式解析失败即拒绝，不猜测多种格式。
    ParseResult parse(ByteView payload,
                      const CertificateChainLimits& limits) const;

private:
    static ParseResult parseDerSingle(ByteView payload,
                                      const CertificateChainLimits& limits);
    static ParseResult parsePemChain(ByteView payload,
                                     const CertificateChainLimits& limits);

    static bool isCaCert(const X509* cert);
    static bool isVerifiableSelfSigned(const X509* cert);
};

} // namespace sec
} // namespace tbox
