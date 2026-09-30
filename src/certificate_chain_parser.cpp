#include "certificate_chain_parser.h"

#include <cctype>
#include <cstring>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

namespace tbox {
namespace sec {

namespace {

bool isAsciiSpace(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

bool isBase64Char(char c) {
    const unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) != 0 || c == '+' || c == '/' || c == '=';
}

// X509 DER 的 SHA-256（不输出原始 DER）
std::array<uint8_t, 32> derSha256(const X509* cert) {
    std::array<uint8_t, 32> digest{};
    unsigned char* der = nullptr;
    const int len = i2d_X509(const_cast<X509*>(cert), &der);
    if (len > 0 && der) {
        SHA256(der, static_cast<size_t>(len), digest.data());
    }
    OPENSSL_free(der);
    return digest;
}

} // namespace

const char* certificate_parse_stage_to_string(CertificateParseStage stage) {
    switch (stage) {
        case CertificateParseStage::Ok: return "ok";
        case CertificateParseStage::InputFormat: return "input_format";
        case CertificateParseStage::ChainShape: return "chain_shape";
        case CertificateParseStage::SizeLimit: return "size_limit";
    }
    return "unknown";
}

ParseResult CertificateChainParser::parse(ByteView payload,
                                          const CertificateChainLimits& limits) const {
    // §3.1 / §7 size_limit：总长（含前导空白）超过上限即拒绝
    if (payload.size > limits.max_payload_bytes) {
        ParseResult r;
        r.ok = false;
        r.stage = CertificateParseStage::SizeLimit;
        return r;
    }

    // §3.1 自动分流：跳过前导 ASCII 空白（计入总长，但格式判定从首个非空字节开始）
    size_t start = 0;
    while (start < payload.size && isAsciiSpace(payload.data[start])) {
        ++start;
    }
    if (start == payload.size) {
        // 纯空白输入：既非 DER 亦非 PEM
        ParseResult r;
        r.ok = false;
        r.stage = CertificateParseStage::InputFormat;
        return r;
    }

    static const char kBeginCert[] = "-----BEGIN CERTIFICATE-----";
    const size_t begin_len = sizeof(kBeginCert) - 1;
    const bool is_pem = (payload.size - start >= begin_len) &&
                        std::memcmp(payload.data + start, kBeginCert, begin_len) == 0;

    // 不允许失败后反复猜测多种格式而接受模糊输入：所选模式解析失败即拒绝。
    return is_pem ? parsePemChain(payload, limits) : parseDerSingle(payload, limits);
}

ParseResult CertificateChainParser::parseDerSingle(ByteView payload,
                                                   const CertificateChainLimits& limits) {
    ParseResult r;
    r.ok = false;
    r.stage = CertificateParseStage::InputFormat;

    // §3.2 单 DER 模式：d2i_X509 解析一个对象，指针须恰好到达 payload 末尾。
    // （前导 ASCII 空白在分流时已跳过；此处从首个非空字节解析）
    size_t start = 0;
    while (start < payload.size && isAsciiSpace(payload.data[start])) {
        ++start;
    }

    const unsigned char* p = payload.data + start;
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(payload.size - start));
    if (!cert) {
        return r;  // input_format
    }

    // 任何尾随非空字节均拒绝（裸拼接 DER 不会静默丢弃第二张证书）
    const unsigned char* end = payload.data + payload.size;
    const unsigned char* q = p;
    while (q < end && isAsciiSpace(*q)) {
        ++q;
    }
    if (q != end) {
        X509_free(cert);
        return r;  // input_format：尾随数据
    }

    ParsedCertificateChain chain;
    chain.format = CertificateInputFormat::DerSingle;
    chain.leaf.reset(cert);
    chain.cert_der_sha256.push_back(derSha256(chain.leaf.get()));

    r.ok = true;
    r.stage = CertificateParseStage::Ok;
    r.chain = std::move(chain);
    return r;
}

ParseResult CertificateChainParser::parsePemChain(ByteView payload,
                                                  const CertificateChainLimits& limits) {
    ParseResult r;
    r.ok = false;
    r.stage = CertificateParseStage::InputFormat;

    const std::string data(reinterpret_cast<const char*>(payload.data), payload.size);

    // §3.3 严格结构：仅允许 -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----
    // 块与空白；私钥、CSR、TRUSTED CERTIFICATE、参数块或任意文本均拒绝。
    static const char kBeginCert[] = "-----BEGIN CERTIFICATE-----";
    static const char kEndCert[] = "-----END CERTIFICATE-----";
    const size_t begin_len = sizeof(kBeginCert) - 1;
    const size_t end_len = sizeof(kEndCert) - 1;

    size_t pos = 0;
    size_t block_count = 0;
    while (pos < data.size()) {
        while (pos < data.size() && isAsciiSpace(static_cast<uint8_t>(data[pos]))) {
            ++pos;
        }
        if (pos >= data.size()) break;

        if (data.compare(pos, begin_len, kBeginCert) != 0) {
            r.stage = CertificateParseStage::InputFormat;  // 混合块 / 非证书文本
            return r;
        }
        pos += begin_len;

        const size_t end_pos = data.find(kEndCert, pos);
        if (end_pos == std::string::npos) {
            r.stage = CertificateParseStage::InputFormat;  // 缺 END
            return r;
        }
        // 块内容仅允许 base64 与空白
        for (size_t i = pos; i < end_pos; ++i) {
            const char c = data[i];
            if (!isBase64Char(c) && !isAsciiSpace(static_cast<uint8_t>(c))) {
                r.stage = CertificateParseStage::InputFormat;
                return r;
            }
        }
        pos = end_pos + end_len;
        ++block_count;
        if (block_count > limits.max_certificates) {
            r.stage = CertificateParseStage::SizeLimit;  // 证书数量超限
            return r;
        }
    }

    // 结构已校验：剩余只能是 CERTIFICATE 块与空白。实际解析（base64 解码 + d2i）。
    std::vector<UniqueX509> certs;
    certs.reserve(block_count);
    BIO* bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
    if (!bio) {
        r.stage = CertificateParseStage::InputFormat;
        return r;
    }
    X509* c = nullptr;
    while ((c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) != nullptr) {
        certs.emplace_back(c);
        if (certs.size() > limits.max_certificates) {
            BIO_free(bio);
            r.stage = CertificateParseStage::SizeLimit;
            return r;
        }
    }
    BIO_free(bio);

    // 结构扫描到的块数与实际解析数必须一致：任一 CERTIFICATE 块解码失败即拒绝
    // （不能静默丢弃解析失败的块）。
    if (certs.size() != block_count) {
        r.stage = CertificateParseStage::InputFormat;
        return r;
    }
    if (certs.empty()) {
        r.stage = CertificateParseStage::ChainShape;  // 空链
        return r;
    }

    // §3.3 顺序/角色：首张必须为非 CA leaf；后续必须 basicConstraints CA=TRUE。
    // 保留输入证书顺序，不按 issuer/subject 重排。
    if (isCaCert(certs.front().get())) {
        r.stage = CertificateParseStage::ChainShape;  // 首张为 CA
        return r;
    }
    for (size_t i = 1; i < certs.size(); ++i) {
        if (!isCaCert(certs[i].get())) {
            r.stage = CertificateParseStage::ChainShape;  // 后续非 CA
            return r;
        }
        // Root 入链拒绝：后续证书若为可验证自签名则拒绝（leaf 自签名由 CertValidator 处理）
        if (isVerifiableSelfSigned(certs[i].get())) {
            r.stage = CertificateParseStage::ChainShape;
            return r;
        }
    }

    // §3.3 重复检测：任意证书 DER digest 重复即拒绝
    std::vector<std::array<uint8_t, 32>> digests;
    digests.reserve(certs.size());
    for (const auto& cc : certs) {
        const std::array<uint8_t, 32> d = derSha256(cc.get());
        for (const auto& prev : digests) {
            if (prev == d) {
                r.stage = CertificateParseStage::ChainShape;  // 重复证书
                return r;
            }
        }
        digests.push_back(d);
    }

    ParsedCertificateChain chain;
    chain.format = CertificateInputFormat::PemChain;
    chain.leaf = std::move(certs.front());
    for (size_t i = 1; i < certs.size(); ++i) {
        chain.intermediates.push_back(std::move(certs[i]));
    }
    chain.cert_der_sha256 = std::move(digests);

    r.ok = true;
    r.stage = CertificateParseStage::Ok;
    r.chain = std::move(chain);
    return r;
}

bool CertificateChainParser::isCaCert(const X509* cert) {
    BASIC_CONSTRAINTS* bc = static_cast<BASIC_CONSTRAINTS*>(
        X509_get_ext_d2i(const_cast<X509*>(cert), NID_basic_constraints, nullptr, nullptr));
    if (!bc) return false;
    const bool is_ca = (bc->ca != 0);
    BASIC_CONSTRAINTS_free(bc);
    return is_ca;
}

bool CertificateChainParser::isVerifiableSelfSigned(const X509* cert) {
    if (X509_NAME_cmp(X509_get_subject_name(const_cast<X509*>(cert)),
                      X509_get_issuer_name(const_cast<X509*>(cert))) != 0) {
        return false;
    }
    EVP_PKEY* pkey = X509_get_pubkey(const_cast<X509*>(cert));
    if (!pkey) return false;
    const int r = X509_verify(const_cast<X509*>(cert), pkey);
    EVP_PKEY_free(pkey);
    return r == 1;
}

} // namespace sec
} // namespace tbox
