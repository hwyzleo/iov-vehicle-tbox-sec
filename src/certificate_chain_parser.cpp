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

// base64 解码（仅 CERTIFICATE 块内容；输入已在上层校验仅含 base64 字符与空白）。
// 返回解码后的原始 DER 字节（即收到时的原始证书字节，非 i2d 重编码）。
bool base64Decode(const std::string& text, std::vector<uint8_t>& out) {
    static const int8_t kDec[256] = {
        // 标准 base64 索引表；非 base64 字符置 -1
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    out.clear();
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        const int8_t v = kDec[c];
        if (c == '=') break;  // padding：终止
        if (v < 0) continue;  // 空白
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    return !out.empty();
}

// 原始证书字节（收到的原文）的 SHA-256；zero 数组表示不可用。
std::array<uint8_t, 32> sha256OfBytes(const uint8_t* data, size_t len) {
    std::array<uint8_t, 32> digest{};
    if (data && len > 0) {
        SHA256(data, len, digest.data());
    }
    return digest;
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

    // 原始 leaf DER 字节（收到的原文）的 SHA-256（CR-020 §7.2：禁止 i2d 重编码口径）。
    // 前导/尾随空白可容忍；中间字节即原始证书 DER。
    size_t der_end = payload.size;
    while (der_end > start && isAsciiSpace(payload.data[der_end - 1])) {
        --der_end;
    }
    chain.leaf_der_original_sha256 =
        sha256OfBytes(payload.data + start, der_end - start);

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
    size_t first_block_b64_begin = 0;
    size_t first_block_b64_end = 0;
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
        if (block_count == 0) {
            first_block_b64_begin = pos;
            first_block_b64_end = end_pos;
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

    // 原始 leaf DER（收到的 base64 解码字节，非 i2d 重编码）的 SHA-256（CR-020 §7.2）。
    std::vector<uint8_t> leaf_orig_der;
    if (base64Decode(data.substr(first_block_b64_begin,
                                 first_block_b64_end - first_block_b64_begin),
                      leaf_orig_der)) {
        chain.leaf_der_original_sha256 =
            sha256OfBytes(leaf_orig_der.data(), leaf_orig_der.size());
    }

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
