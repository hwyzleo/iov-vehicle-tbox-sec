#pragma once

#include <string>

#include "certificate_chain_parser.h"

namespace tbox {
namespace sec {

/// 证书链 canonical PEM 规范化（TBOX-SEC-DSN-CR-018 §5）。
///
/// 以解析后的 X509 对象重新序列化，不复制输入 PEM 的空白、换行或 header 文本。
/// 输出固定 LF 换行；每张证书使用标准 PEM_write_bio_X509 结果；顺序为 leaf 后跟
/// intermediates，Root 永不输出。canonical PEM 的 SHA-256 作为 CR-014 幂等键。
class CertificateChainCanonicalizer {
public:
    /// 成功返回 true 并写入 canonical PEM；失败返回 false（out 保持原值）。
    bool toPem(const ParsedCertificateChain& chain, std::string& out) const;
};

} // namespace sec
} // namespace tbox
