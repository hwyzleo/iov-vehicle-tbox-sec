#include "certificate_chain_canonicalizer.h"

#include <openssl/bio.h>
#include <openssl/pem.h>

namespace tbox {
namespace sec {

bool CertificateChainCanonicalizer::toPem(const ParsedCertificateChain& chain,
                                          std::string& out) const {
    if (!chain.leaf) {
        return false;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return false;
    }

    bool ok = true;
    // leaf 后跟 intermediates；Root 永不输出（ParsedCertificateChain 本就不含 Root）。
    if (PEM_write_bio_X509(bio, chain.leaf.get()) != 1) {
        ok = false;
    }
    for (const auto& ic : chain.intermediates) {
        if (ok && ic && PEM_write_bio_X509(bio, ic.get()) != 1) {
            ok = false;
            break;
        }
    }

    if (ok) {
        char* buf = nullptr;
        const long len = BIO_get_mem_data(bio, &buf);
        if (len > 0 && buf) {
            out.assign(buf, static_cast<size_t>(len));
        } else {
            ok = false;
        }
    }

    BIO_free(bio);
    return ok;
}

} // namespace sec
} // namespace tbox
