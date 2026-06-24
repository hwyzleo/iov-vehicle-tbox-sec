#include "csr_builder.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>


namespace tbox {
namespace sec {

CsrBuilder::CsrBuilder(KeyEngine* key_engine)
    : key_engine_(key_engine) {}

// --- ASN.1 DER encoding helpers ---

static void der_encode_length(uint16_t len, std::vector<uint8_t>& out) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
    } else if (len <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(len));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(len & 0xFF));
    }
}

static void der_encode_oid(const std::vector<uint8_t>& oid,
                           std::vector<uint8_t>& out) {
    out.push_back(0x06);
    der_encode_length(static_cast<uint16_t>(oid.size()), out);
    out.insert(out.end(), oid.begin(), oid.end());
}

static void der_encode_integer(uint8_t value, std::vector<uint8_t>& out) {
    out.push_back(0x02);
    out.push_back(0x01);
    out.push_back(value);
}

static void der_encode_bit_string(const std::vector<uint8_t>& data,
                                  uint8_t unused_bits,
                                  std::vector<uint8_t>& out) {
    out.push_back(0x03);
    der_encode_length(static_cast<uint16_t>(data.size() + 1), out);
    out.push_back(unused_bits);
    out.insert(out.end(), data.begin(), data.end());
}

static void der_encode_octet_string(const std::vector<uint8_t>& data,
                                    std::vector<uint8_t>& out) {
    out.push_back(0x04);
    der_encode_length(static_cast<uint16_t>(data.size()), out);
    out.insert(out.end(), data.begin(), data.end());
}

static void der_wrap_tag_length(uint8_t tag, const std::vector<uint8_t>& inner,
                                std::vector<uint8_t>& out) {
    out.push_back(tag);
    der_encode_length(static_cast<uint16_t>(inner.size()), out);
    out.insert(out.end(), inner.begin(), inner.end());
}

static void der_wrap_sequence(const std::vector<uint8_t>& inner,
                              std::vector<uint8_t>& out) {
    der_wrap_tag_length(0x30, inner, out);
}

static void der_wrap_set(const std::vector<uint8_t>& inner,
                         std::vector<uint8_t>& out) {
    der_wrap_tag_length(0x31, inner, out);
}

static bool marshal_raw_eckey(EVP_PKEY* pkey,
                              std::vector<uint8_t>& raw_pubkey_out) {
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (!ec) return false;
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const EC_POINT* point = EC_KEY_get0_public_key(ec);
    if (!group || !point) return false;
    size_t len = EC_POINT_point2oct(group, point,
                                     POINT_CONVERSION_UNCOMPRESSED,
                                     nullptr, 0, nullptr);
    if (len == 0) return false;
    raw_pubkey_out.resize(len);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                       raw_pubkey_out.data(), len, nullptr);
    return true;
}

ErrorCode CsrBuilder::marshal_ec_pubkey_info(
    const std::vector<uint8_t>& raw_pubkey,
    std::vector<uint8_t>& out_der) {

    static const uint8_t OID_EC[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    static const uint8_t OID_PRIME256V1[] = {0x2A, 0x86, 0x48,
        0xCE, 0x3D, 0x03, 0x01, 0x07};

    std::vector<uint8_t> alg_params;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_PRIME256V1), std::end(OID_PRIME256V1)), alg_params);

    std::vector<uint8_t> alg_seq_inner;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_EC), std::end(OID_EC)), alg_seq_inner);
    alg_seq_inner.insert(alg_seq_inner.end(),
                         alg_params.begin(), alg_params.end());

    std::vector<uint8_t> alg_seq;
    der_wrap_sequence(alg_seq_inner, alg_seq);

    std::vector<uint8_t> pubkey_bs;
    der_encode_bit_string(raw_pubkey, 0, pubkey_bs);

    std::vector<uint8_t> inner;
    inner.insert(inner.end(), alg_seq.begin(), alg_seq.end());
    inner.insert(inner.end(), pubkey_bs.begin(), pubkey_bs.end());

    der_wrap_sequence(inner, out_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::marshal_x509_name(const std::string& cn,
                                        std::vector<uint8_t>& out_der) {
    static const uint8_t OID_CN[] = {0x55, 0x04, 0x03};

    std::vector<uint8_t> cn_val(cn.begin(), cn.end());

    std::vector<uint8_t> attr_type;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_CN), std::end(OID_CN)), attr_type);

    // Attribute value: UTF8String
    std::vector<uint8_t> attr_value;
    attr_value.push_back(0x0C);  // UTF8String tag
    der_encode_length(static_cast<uint16_t>(cn_val.size()), attr_value);
    attr_value.insert(attr_value.end(), cn_val.begin(), cn_val.end());

    // SEQUENCE { OID, value }
    std::vector<uint8_t> attr_seq_inner;
    attr_seq_inner.insert(attr_seq_inner.end(), attr_type.begin(), attr_type.end());
    attr_seq_inner.insert(attr_seq_inner.end(), attr_value.begin(), attr_value.end());

    std::vector<uint8_t> attr_seq;
    der_wrap_sequence(attr_seq_inner, attr_seq);

    // SET OF { attr_seq }
    std::vector<uint8_t> set_of;
    der_wrap_set(attr_seq, set_of);

    // SEQUENCE { set_of }
    der_wrap_sequence(set_of, out_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::marshal_san_extension(
    const std::string& vin,
    const std::string& ecu_uid,
    std::vector<uint8_t>& ext_der) {

    static const uint8_t OID_SAN[] = {0x55, 0x1D, 0x11};

    std::vector<uint8_t> san_entries;

    // URI for VIN — use URN scheme to avoid URI:URI: duplication
    std::string vin_uri = "urn:vin:" + vin;
    san_entries.push_back(0x86);  // [6] URI IMPLICIT
    der_encode_length(static_cast<uint16_t>(vin_uri.size()), san_entries);
    san_entries.insert(san_entries.end(), vin_uri.begin(), vin_uri.end());

    // URI for ECU_UID
    std::string ecu_uri = "urn:ecu-uid:" + ecu_uid;
    san_entries.push_back(0x86);  // [6] URI IMPLICIT
    der_encode_length(static_cast<uint16_t>(ecu_uri.size()), san_entries);
    san_entries.insert(san_entries.end(), ecu_uri.begin(), ecu_uri.end());

    std::vector<uint8_t> san_seq;
    der_wrap_sequence(san_entries, san_seq);

    std::vector<uint8_t> octet;
    der_encode_octet_string(san_seq, octet);

    std::vector<uint8_t> oid;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_SAN), std::end(OID_SAN)), oid);

    std::vector<uint8_t> inner;
    inner.insert(inner.end(), oid.begin(), oid.end());
    inner.insert(inner.end(), octet.begin(), octet.end());

    der_wrap_sequence(inner, ext_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::marshal_ku_extension(std::vector<uint8_t>& ext_der) {
    static const uint8_t OID_KU[] = {0x55, 0x1D, 0x0F};

    // digitalSignature = bit 0 → 0x80
    std::vector<uint8_t> ku_data = {0x80};
    std::vector<uint8_t> bs;
    der_encode_bit_string(ku_data, 0, bs);

    std::vector<uint8_t> octet;
    der_encode_octet_string(bs, octet);

    std::vector<uint8_t> oid;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_KU), std::end(OID_KU)), oid);

    std::vector<uint8_t> inner;
    inner.insert(inner.end(), oid.begin(), oid.end());
    inner.insert(inner.end(), octet.begin(), octet.end());

    der_wrap_sequence(inner, ext_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::marshal_eku_extension(std::vector<uint8_t>& ext_der) {
    static const uint8_t OID_EKU[] = {0x55, 0x1D, 0x25};
    static const uint8_t OID_CLIENT_AUTH[] = {
        0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02};

    std::vector<uint8_t> oids;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_CLIENT_AUTH), std::end(OID_CLIENT_AUTH)), oids);

    std::vector<uint8_t> seq;
    der_wrap_sequence(oids, seq);

    std::vector<uint8_t> octet;
    der_encode_octet_string(seq, octet);

    std::vector<uint8_t> oid;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_EKU), std::end(OID_EKU)), oid);

    std::vector<uint8_t> inner;
    inner.insert(inner.end(), oid.begin(), oid.end());
    inner.insert(inner.end(), octet.begin(), octet.end());

    der_wrap_sequence(inner, ext_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::build_csr_info(const CsrConfig& config,
                                     const KeyPair& key_pair,
                                     std::vector<uint8_t>& csr_info_der) {
    // Version INTEGER(0)
    std::vector<uint8_t> version;
    der_encode_integer(0, version);

    // Subject name
    std::vector<uint8_t> subject_der;
    if (marshal_x509_name(config.common_name, subject_der) != ErrorCode::SUCCESS) {
        return ErrorCode::CSR_BUILD_FAILED;
    }

    // Public key info from HSM key pair (raw uncompressed EC point)
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) return ErrorCode::CSR_BUILD_FAILED;
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec) { EVP_PKEY_free(pkey); return ErrorCode::CSR_BUILD_FAILED; }
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* pt = EC_POINT_new(group);
    if (!pt) { EC_KEY_free(ec); EVP_PKEY_free(pkey); return ErrorCode::CSR_BUILD_FAILED; }
    if (!EC_POINT_oct2point(group, pt,
            key_pair.public_key.data(),
            key_pair.public_key.size(), nullptr)) {
        EC_POINT_free(pt); EC_KEY_free(ec);
        EVP_PKEY_free(pkey); return ErrorCode::CSR_BUILD_FAILED;
    }
    EC_KEY_set_public_key(ec, pt);
    EC_POINT_free(pt);
    EVP_PKEY_assign_EC_KEY(pkey, ec);

    std::vector<uint8_t> raw_pubkey;
    if (!marshal_raw_eckey(pkey, raw_pubkey)) {
        EVP_PKEY_free(pkey);
        return ErrorCode::CSR_BUILD_FAILED;
    }
    EVP_PKEY_free(pkey);

    std::vector<uint8_t> pubkey_info;
    if (marshal_ec_pubkey_info(raw_pubkey, pubkey_info) != ErrorCode::SUCCESS) {
        return ErrorCode::CSR_BUILD_FAILED;
    }

    // Build extensions
    std::vector<uint8_t> san_ext, ku_ext, eku_ext;
    if (marshal_san_extension(config.vin, config.ecu_uid, san_ext) != ErrorCode::SUCCESS ||
        marshal_ku_extension(ku_ext) != ErrorCode::SUCCESS ||
        marshal_eku_extension(eku_ext) != ErrorCode::SUCCESS) {
        return ErrorCode::CSR_BUILD_FAILED;
    }

    // Extension request attribute: SEQUENCE { OID, SET OF { SEQUENCE of extensions } }
    static const uint8_t OID_EXTENSION_REQUEST[] = {
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E};

    std::vector<uint8_t> ext_set_content;
    ext_set_content.insert(ext_set_content.end(), san_ext.begin(), san_ext.end());
    ext_set_content.insert(ext_set_content.end(), ku_ext.begin(), ku_ext.end());
    ext_set_content.insert(ext_set_content.end(), eku_ext.begin(), eku_ext.end());

    // ExtensionRequest ::= SEQUENCE OF Extension
    std::vector<uint8_t> ext_seq;
    der_wrap_sequence(ext_set_content, ext_seq);

    std::vector<uint8_t> oid_ext;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_EXTENSION_REQUEST),
        std::end(OID_EXTENSION_REQUEST)), oid_ext);

    // Attribute: SEQUENCE { oid, SET OF { ExtensionRequest } }
    std::vector<uint8_t> ext_value_set;
    der_wrap_set(ext_seq, ext_value_set);

    std::vector<uint8_t> attr_inner;
    attr_inner.insert(attr_inner.end(), oid_ext.begin(), oid_ext.end());
    attr_inner.insert(attr_inner.end(), ext_value_set.begin(), ext_value_set.end());

    std::vector<uint8_t> attr_seq;
    der_wrap_sequence(attr_inner, attr_seq);

    // [0] IMPLICIT SET OF Attribute
    // The [0] replaces the SET OF tag, content is the Attribute SEQUENCE(s)
    std::vector<uint8_t> attrs_implicit;
    der_wrap_tag_length(0xA0, attr_seq, attrs_implicit);

    // Final SEQUENCE: { version, subject, pubkey_info, [0] attrs }
    std::vector<uint8_t> seq_inner;
    seq_inner.insert(seq_inner.end(), version.begin(), version.end());
    seq_inner.insert(seq_inner.end(), subject_der.begin(), subject_der.end());
    seq_inner.insert(seq_inner.end(), pubkey_info.begin(), pubkey_info.end());
    seq_inner.insert(seq_inner.end(),
                     attrs_implicit.begin(), attrs_implicit.end());

    der_wrap_sequence(seq_inner, csr_info_der);
    return ErrorCode::SUCCESS;
}

ErrorCode CsrBuilder::build_csr(const CsrConfig& config,
                                std::vector<uint8_t>& csr_der) {
    if (!key_engine_) {
        return ErrorCode::INVALID_PARAMETER;
    }

    KeyPair key_pair;
    ErrorCode result = key_engine_->get_device_key(
        config.vin, config.ecu_uid, key_pair);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    // Build TBS (certificationRequestInfo)
    std::vector<uint8_t> csr_info;
    result = build_csr_info(config, key_pair, csr_info);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    // Sign TBS via HSM
    std::vector<uint8_t> signature;
    result = key_engine_->sign(config.vin, config.ecu_uid,
                               csr_info, signature);
    if (result != ErrorCode::SUCCESS) {
        return ErrorCode::CSR_SIGN_FAILED;
    }

    // Algorithm: ecdsaWithSHA256 = 1.2.840.10045.4.3.2
    static const uint8_t OID_ECDSA_SHA256[] = {
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};

    std::vector<uint8_t> alg_oid;
    der_encode_oid(std::vector<uint8_t>(
        std::begin(OID_ECDSA_SHA256),
        std::end(OID_ECDSA_SHA256)), alg_oid);

    std::vector<uint8_t> alg_seq;
    der_wrap_sequence(alg_oid, alg_seq);

    // Encode signature as BIT STRING (unused bits = 0)
    std::vector<uint8_t> sig_bs;
    der_encode_bit_string(signature, 0, sig_bs);

    // Final PKCS#10: SEQUENCE { certReqInfo, algorithm, signature }
    std::vector<uint8_t> final_inner;
    final_inner.insert(final_inner.end(),
                       csr_info.begin(), csr_info.end());
    final_inner.insert(final_inner.end(),
                       alg_seq.begin(), alg_seq.end());
    final_inner.insert(final_inner.end(),
                       sig_bs.begin(), sig_bs.end());

    der_wrap_sequence(final_inner, csr_der);
    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox
