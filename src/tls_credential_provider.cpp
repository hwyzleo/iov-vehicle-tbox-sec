#include "tls_credential_provider.h"
#include "sec_log_adapter.h"
#include "log_types.h"
#include "error_codes.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>
#include <algorithm>

namespace tbox {
namespace sec {

namespace {

// RAII helpers
struct X509Deleter { void operator()(X509* p) const { if (p) X509_free(p); } };
using X509UniquePtr = std::unique_ptr<X509, X509Deleter>;
struct EvpPkeyDeleter { void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); } };
using EvpPkeyUniquePtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
struct EvpCtxDeleter { void operator()(EVP_CIPHER_CTX* p) const { if (p) EVP_CIPHER_CTX_free(p); } };
using EvpCtxUniquePtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter>;
struct StoreCtxDeleter { void operator()(X509_STORE_CTX* p) const { if (p) X509_STORE_CTX_free(p); } };
using StoreCtxUniquePtr = std::unique_ptr<X509_STORE_CTX, StoreCtxDeleter>;
struct StoreDeleter { void operator()(X509_STORE* p) const { if (p) X509_STORE_free(p); } };
using StoreUniquePtr = std::unique_ptr<X509_STORE, StoreDeleter>;

constexpr size_t kGcmNonceLen = 12;
constexpr size_t kGcmTagLen = 16;
constexpr size_t kAesKeyLen = 32;

/// clientAuth OID 1.3.6.1.5.5.7.3.2
constexpr const char* kOidClientAuth = "1.3.6.1.5.5.7.3.2";
/// serverAuth OID 1.3.6.1.5.5.7.3.1
constexpr const char* kOidServerAuth = "1.3.6.1.5.5.7.3.1";

/// 从内存中的 PEM/DER 内容加载一个或多个 X509（支持 PEM 多证书 / DER 单证书）
std::vector<X509UniquePtr> load_certs_from_string(const std::string& content) {
    std::vector<X509UniquePtr> certs;
    if (content.empty()) return certs;

    // 尝试 PEM（可能含多个 -----BEGIN CERTIFICATE-----）
    if (content.find("-----BEGIN") != std::string::npos) {
        BIO* bio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));
        if (!bio) return certs;
        while (true) {
            X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
            if (!cert) break;
            certs.emplace_back(cert);
        }
        BIO_free(bio);
    } else {
        // DER 单证书
        const unsigned char* p = reinterpret_cast<const unsigned char*>(content.data());
        X509* cert = d2i_X509(nullptr, &p, static_cast<long>(content.size()));
        if (cert) certs.emplace_back(cert);
    }
    return certs;
}

std::vector<uint8_t> cert_to_der(X509* cert) {
    std::vector<uint8_t> der;
    unsigned char* buf = nullptr;
    int len = i2d_X509(cert, &buf);
    if (len > 0 && buf) {
        der.assign(buf, buf + len);
        OPENSSL_free(buf);
    }
    return der;
}

/// 合并多证书为连续 DER bundle（root_ca_bundle_der）
std::vector<uint8_t> certs_to_der_bundle(const std::vector<X509UniquePtr>& certs) {
    std::vector<uint8_t> bundle;
    for (auto& c : certs) {
        auto der = cert_to_der(c.get());
        bundle.insert(bundle.end(), der.begin(), der.end());
    }
    return bundle;
}

/// 提取证书 EKU OID 列表
std::vector<std::string> get_eku_oids(X509* cert) {
    std::vector<std::string> oids;
    EXTENDED_KEY_USAGE* eku = static_cast<EXTENDED_KEY_USAGE*>(
        X509_get_ext_d2i(cert, NID_ext_key_usage, nullptr, nullptr));
    if (!eku) return oids;
    for (int i = 0; i < sk_ASN1_OBJECT_num(eku); ++i) {
        ASN1_OBJECT* obj = sk_ASN1_OBJECT_value(eku, i);
        char buf[64];
        OBJ_obj2txt(buf, sizeof(buf), obj, 1);
        oids.emplace_back(buf);
    }
    EXTENDED_KEY_USAGE_free(eku);
    return oids;
}

/// 证书是否为 CA（basicConstraints CA=TRUE）
bool is_ca_cert(X509* cert) {
    BASIC_CONSTRAINTS* bc = static_cast<BASIC_CONSTRAINTS*>(
        X509_get_ext_d2i(cert, NID_basic_constraints, nullptr, nullptr));
    if (!bc) return false;
    bool is_ca = (bc->ca != 0);
    BASIC_CONSTRAINTS_free(bc);
    return is_ca;
}

/// 证书有效期：返回 not_before/not_after（unix epoch 秒）
void get_validity(X509* cert, int64_t& not_before, int64_t& not_after) {
    const ASN1_TIME* nb = X509_get0_notBefore(cert);
    const ASN1_TIME* na = X509_get0_notAfter(cert);
    struct tm tm_nb = {}, tm_na = {};
    ASN1_TIME_to_tm(nb, &tm_nb);
    ASN1_TIME_to_tm(na, &tm_na);
    not_before = static_cast<int64_t>(timegm(&tm_nb));
    not_after = static_cast<int64_t>(timegm(&tm_na));
}

/// 提取证书原始公钥字节（未压缩 EC point）
std::vector<uint8_t> get_raw_public_key(X509* cert) {
    std::vector<uint8_t> out;
    // X509_get0_pubkey 返回借用指针，不得 free
    EVP_PKEY* pk = X509_get0_pubkey(cert);
    if (!pk) return out;
    // OpenSSL 3.0 下 EVP_PKEY_get_raw_public_key 对 legacy EC_KEY 可能失败，
    // 改用 EC_KEY 提取未压缩点。
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pk);  // 返回新引用，需 free
    if (!ec) return out;
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    const EC_POINT* pt = EC_KEY_get0_public_key(ec);
    if (group && pt) {
        size_t len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                                         nullptr, 0, nullptr);
        if (len > 0) {
            out.resize(len);
            EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
                               out.data(), len, nullptr);
        }
    }
    EC_KEY_free(ec);
    return out;
}

bool now_in_range(int64_t not_before, int64_t not_after) {
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    return now >= not_before && now <= not_after;
}

} // anonymous namespace

// ============================================================
// 构造 / 析构
// ============================================================

TlsCredentialProvider::TlsCredentialProvider(HsmInterface* hsm,
                                             DeviceKeyIdResolver key_id_resolver,
                                             TlsMaterialResolver material_resolver,
                                             TlsCredentialNotifyCallback notify)
    : hsm_(hsm),
      key_id_resolver_(std::move(key_id_resolver)),
      notify_(std::move(notify)),
      material_resolver_(std::move(material_resolver)),
      process_key_(generateProcessKey()),
      boot_epoch_(generateBootEpoch()) {
}

TlsCredentialProvider::~TlsCredentialProvider() {
    // 安全清零进程密钥
    if (!process_key_.empty()) {
        OPENSSL_cleanse(process_key_.data(), process_key_.size());
    }
}

std::vector<uint8_t> TlsCredentialProvider::generateProcessKey() {
    std::vector<uint8_t> key(kAesKeyLen);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        // 极端情况：填充固定值，fail-closed（解密校验仍会拒绝）
        std::fill(key.begin(), key.end(), 0);
    }
    return key;
}

uint64_t TlsCredentialProvider::generateBootEpoch() {
    uint64_t epoch = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&epoch), sizeof(epoch)) != 1) {
        epoch = static_cast<uint64_t>(std::time(nullptr));
    }
    return epoch;
}

std::string TlsCredentialProvider::hashId(const std::string& id) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(id.data()), id.size(), hash);
    char hex[17];
    for (int i = 0; i < 8; ++i) {
        std::snprintf(hex + i * 2, 3, "%02x", hash[i]);
    }
    return std::string(hex, 16);
}

TlsCredentialProvider::ProfileState* TlsCredentialProvider::findProfile(const std::string& profile) {
    auto it = profiles_.find(profile);
    return it == profiles_.end() ? nullptr : &it->second;
}

const TlsCredentialProvider::ProfileState* TlsCredentialProvider::findProfile(const std::string& profile) const {
    auto it = profiles_.find(profile);
    return it == profiles_.end() ? nullptr : &it->second;
}

void TlsCredentialProvider::configureProfile(const TlsProfileConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& ps = profiles_[config.profile_name];
    ps.config = config;
    if (ps.version == 0) {
        ps.status = TlsCredentialStatus::NOT_READY;
    }
}

bool TlsCredentialProvider::isAuthorized(const std::string& profile,
                                         const PeerIdentity& peer) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto* ps = findProfile(profile);
    if (!ps) return false;
    // fail-closed：peer 无效或 service_name 不匹配均拒绝
    if (!peer.valid) return false;
    if (ps->config.peer_service.empty()) return false;
    return peer.service_name == ps->config.peer_service;
}

TlsCredentialStatus TlsCredentialProvider::getStatus(const std::string& profile) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto* ps = findProfile(profile);
    return ps ? ps->status : TlsCredentialStatus::NOT_READY;
}

uint64_t TlsCredentialProvider::bootEpoch() const {
    return boot_epoch_;
}

bool TlsCredentialProvider::algorithmAllowed(const ProfileState& ps,
                                             SignatureAlgorithm alg) const {
    if (ps.config.allowed_signature_algorithms.empty()) {
        // 未配置则只允许默认 ECDSA_SECP256R1_SHA256
        return alg == SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    }
    for (auto a : ps.config.allowed_signature_algorithms) {
        if (a == alg) return true;
    }
    return false;
}

void TlsCredentialProvider::publishChanged(const std::string& profile,
                                           ProfileState& ps,
                                           TlsCredentialStatus status,
                                           int32_t reason_code) {
    if (!ps.config.notify_on_change || !notify_) return;
    TlsCredentialChangedEvent ev;
    ev.profile = profile;
    ev.credential_id = ps.config.credential_id;
    ev.version = ps.version;
    ev.status = status;
    ev.reason_code = reason_code;
    notify_(profile, ev);
}

// ============================================================
// 材料加载与校验
// ============================================================

ErrorCode TlsCredentialProvider::validateAndStoreMaterials(ProfileState& ps) {
    if (ps.config.root_ca_key.empty() || ps.config.client_cert_chain_key.empty()
        || !material_resolver_) {
        ps.status = TlsCredentialStatus::NOT_READY;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_NOT_READY);
        return ErrorCode::TLS_CREDENTIAL_NOT_READY;
    }

    // 从 SEC 受控存储按 key 读取 PEM 材料（root_ca 为共享信任根，device_cert_chain 为设备证书链）
    std::string root_pem = material_resolver_(ps.config.root_ca_key);
    std::string chain_pem = material_resolver_(ps.config.client_cert_chain_key);
    auto root_certs = load_certs_from_string(root_pem);
    auto chain_certs = load_certs_from_string(chain_pem);
    if (root_certs.empty() || chain_certs.empty()) {
        SecLogAdapter::certificate().warn(
            "sec.tls_credential.rejected",
            "TLS 材料加载失败：根 CA 或客户端证书链为空",
            {{"profile", tbox::fw::log::FieldValue::makeString(ps.config.profile_name)},
             {"reason_code", tbox::fw::log::FieldValue::makeInt(
                 static_cast<int>(ErrorCode::TLS_CREDENTIAL_NOT_READY))}}
        );
        ps.status = TlsCredentialStatus::NOT_READY;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_NOT_READY);
        return ErrorCode::TLS_CREDENTIAL_NOT_READY;
    }

    X509* leaf = chain_certs.front().get();

    // 1. 叶子证书 EKU 含 clientAuth
    auto eku = get_eku_oids(leaf);
    bool has_client_auth = std::find(eku.begin(), eku.end(), kOidClientAuth) != eku.end();
    if (!has_client_auth) {
        ps.status = TlsCredentialStatus::ERROR;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_INVALID);
        SecLogAdapter::certificate().warn(
            "sec.tls_credential.rejected",
            "叶子证书缺少 clientAuth EKU",
            {{"profile", tbox::fw::log::FieldValue::makeString(ps.config.profile_name)},
             {"credential_id_hash", tbox::fw::log::FieldValue::makeString(hashId(ps.config.credential_id))}}
        );
        return ErrorCode::TLS_CREDENTIAL_INVALID;
    }

    // 2. 证书有效期
    int64_t nb = 0, na = 0;
    get_validity(leaf, nb, na);
    if (!now_in_range(nb, na)) {
        ps.status = TlsCredentialStatus::EXPIRED;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_INVALID);
        ps.not_before = nb;
        ps.not_after = na;
        return ErrorCode::TLS_CREDENTIAL_INVALID;
    }
    ps.not_before = nb;
    ps.not_after = na;

    // 3. 叶子公钥 ↔ HSM 私钥匹配
    std::string key_id = key_id_resolver_ ? key_id_resolver_() : "";
    if (key_id.empty() || !hsm_->key_exists(key_id)) {
        ps.status = TlsCredentialStatus::NOT_READY;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_NOT_READY);
        return ErrorCode::TLS_CREDENTIAL_NOT_READY;
    }
    std::vector<uint8_t> hsm_pub;
    if (hsm_->export_public_key(key_id, hsm_pub) != ErrorCode::SUCCESS) {
        ps.status = TlsCredentialStatus::ERROR;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_HSM_SIGN_FAILED);
        return ErrorCode::TLS_HSM_SIGN_FAILED;
    }
    std::vector<uint8_t> cert_pub = get_raw_public_key(leaf);
    if (cert_pub.empty() || cert_pub != hsm_pub) {
        ps.status = TlsCredentialStatus::ERROR;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_INVALID);
        SecLogAdapter::certificate().warn(
            "sec.tls_credential.rejected",
            "叶子证书公钥与 HSM 私钥不匹配",
            {{"profile", tbox::fw::log::FieldValue::makeString(ps.config.profile_name)}}
        );
        return ErrorCode::TLS_CREDENTIAL_INVALID;
    }

    // 4. 根 CA 为 CA 证书（允许 serverAuth 校验）
    bool root_is_ca = false;
    for (auto& rc : root_certs) {
        if (is_ca_cert(rc.get())) { root_is_ca = true; break; }
    }
    if (!root_is_ca) {
        ps.status = TlsCredentialStatus::ERROR;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_INVALID);
        return ErrorCode::TLS_CREDENTIAL_INVALID;
    }

    // 5. 链完整性：用 root CA bundle 校验客户端证书链
    StoreUniquePtr store(X509_STORE_new());
    if (!store) {
        ps.status = TlsCredentialStatus::ERROR;
        ps.reason_code = static_cast<int32_t>(ErrorCode::INTERNAL_ERROR);
        return ErrorCode::INTERNAL_ERROR;
    }
    for (auto& rc : root_certs) {
        X509_STORE_add_cert(store.get(), rc.get());
    }
    StoreCtxUniquePtr ctx(X509_STORE_CTX_new());
    X509_STORE_CTX_init(ctx.get(), store.get(), leaf, nullptr);
    // 中间证书作为 untrusted chain
    STACK_OF(X509)* untrusted = sk_X509_new_null();
    for (size_t i = 1; i < chain_certs.size(); ++i) {
        sk_X509_push(untrusted, X509_dup(chain_certs[i].get()));
    }
    X509_STORE_CTX_set0_untrusted(ctx.get(), untrusted);
    bool chain_ok = (X509_verify_cert(ctx.get()) == 1);
    sk_X509_pop_free(untrusted, X509_free);

    if (!chain_ok) {
        ps.status = TlsCredentialStatus::ERROR;
        ps.reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_INVALID);
        SecLogAdapter::certificate().warn(
            "sec.tls_credential.rejected",
            "证书链校验失败",
            {{"profile", tbox::fw::log::FieldValue::makeString(ps.config.profile_name)}}
        );
        return ErrorCode::TLS_CREDENTIAL_INVALID;
    }

    // 全部校验通过
    ps.root_ca_bundle_der = certs_to_der_bundle(root_certs);
    ps.client_cert_chain_der = certs_to_der_bundle(chain_certs);
    ps.key_algorithm = KeyAlgorithm::ECDSA_P256;
    ps.status = TlsCredentialStatus::READY;
    ps.reason_code = 0;

    SecLogAdapter::certificate().info(
        "sec.tls_credential.loaded",
        "TLS 凭据加载就绪",
        {{"profile", tbox::fw::log::FieldValue::makeString(ps.config.profile_name)},
         {"credential_id_hash", tbox::fw::log::FieldValue::makeString(hashId(ps.config.credential_id))},
         {"version", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(ps.version))},
         {"status", tbox::fw::log::FieldValue::makeString(tls_credential_status_to_string(ps.status))}}
    );
    return ErrorCode::SUCCESS;
}

ErrorCode TlsCredentialProvider::loadMaterials(const std::string& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto* ps = findProfile(profile);
    if (!ps) return ErrorCode::INVALID_PARAMETER;
    if (ps->version == 0) ps->version = 1;
    ErrorCode rc = validateAndStoreMaterials(*ps);
    return rc;
}

// ============================================================
// private_key_ref 编解码（AES-256-GCM）
// ============================================================

OpaqueKeyRef TlsCredentialProvider::encodeRef(const RefPayload& payload) {
    OpaqueKeyRef ref;
    nlohmann::json j;
    j["caller"] = payload.caller_service;
    j["profile"] = payload.profile;
    j["credential_id"] = payload.credential_id;
    j["version"] = payload.version;
    j["key_id"] = payload.key_id;
    j["allowed_algs"] = payload.allowed_algorithms;  // vector<uint8_t-ish> -> ints
    j["boot_epoch"] = payload.boot_epoch;
    j["expiry"] = payload.expiry;
    std::string plaintext = j.dump();

    unsigned char nonce[kGcmNonceLen];
    if (RAND_bytes(nonce, kGcmNonceLen) != 1) return ref;

    EvpCtxUniquePtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return ref;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return ref;
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr);
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                           process_key_.data(), nonce) != 1) return ref;

    std::vector<uint8_t> ciphertext(plaintext.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outlen,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1) return ref;
    int finlen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outlen, &finlen) != 1) return ref;
    ciphertext.resize(outlen + finlen);

    unsigned char tag[kGcmTagLen];
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagLen, tag);

    // output = nonce || ciphertext || tag
    ref.data.reserve(kGcmNonceLen + ciphertext.size() + kGcmTagLen);
    ref.data.insert(ref.data.end(), nonce, nonce + kGcmNonceLen);
    ref.data.insert(ref.data.end(), ciphertext.begin(), ciphertext.end());
    ref.data.insert(ref.data.end(), tag, tag + kGcmTagLen);
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    return ref;
}

bool TlsCredentialProvider::decodeRef(const OpaqueKeyRef& ref, RefPayload& payload) {
    if (ref.data.size() < kGcmNonceLen + kGcmTagLen) return false;
    size_t ct_len = ref.data.size() - kGcmNonceLen - kGcmTagLen;
    const unsigned char* nonce = ref.data.data();
    const unsigned char* ct = ref.data.data() + kGcmNonceLen;
    const unsigned char* tag = ref.data.data() + kGcmNonceLen + ct_len;

    EvpCtxUniquePtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kGcmNonceLen, nullptr);
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                           process_key_.data(), nonce) != 1) return false;

    std::vector<uint8_t> plaintext(ct_len);
    int outlen = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outlen, ct,
                          static_cast<int>(ct_len)) != 1) return false;
    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagLen,
                        const_cast<unsigned char*>(tag));
    int finlen = 0;
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outlen, &finlen) != 1) {
        // MAC 校验失败 / 篡改
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        return false;
    }
    plaintext.resize(outlen + finlen);

    bool ok = false;
    try {
        std::string s(plaintext.begin(), plaintext.end());
        auto j = nlohmann::json::parse(s);
        payload.caller_service = j.value("caller", "");
        payload.profile = j.value("profile", "");
        payload.credential_id = j.value("credential_id", "");
        payload.version = j.value("version", 0ULL);
        payload.key_id = j.value("key_id", "");
        payload.allowed_algorithms.clear();
        for (auto& a : j["allowed_algs"]) {
            payload.allowed_algorithms.push_back(
                static_cast<SignatureAlgorithm>(a.get<int>()));
        }
        payload.boot_epoch = j.value("boot_epoch", 0ULL);
        payload.expiry = j.value("expiry", 0LL);
        ok = true;
    } catch (...) {
        ok = false;
    }
    OPENSSL_cleanse(plaintext.data(), plaintext.size());
    return ok;
}

// ============================================================
// API
// ============================================================

ErrorCode TlsCredentialProvider::getTlsCredential(const std::string& profile,
                                                  const PeerIdentity& caller,
                                                  TlsCredentialBundle& bundle) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto* ps = findProfile(profile);
    if (!ps) return ErrorCode::INVALID_PARAMETER;

    if (ps->status != TlsCredentialStatus::READY) {
        SecLogAdapter::certificate().debug(
            "sec.tls_credential.rejected",
            "凭据未就绪，拒绝 getTlsCredential",
            {{"profile", tbox::fw::log::FieldValue::makeString(profile)},
             {"status", tbox::fw::log::FieldValue::makeString(tls_credential_status_to_string(ps->status))},
             {"reason_code", tbox::fw::log::FieldValue::makeInt(ps->reason_code)}}
        );
        return static_cast<ErrorCode>(ps->reason_code ? ps->reason_code
                                                      : static_cast<int>(ErrorCode::TLS_CREDENTIAL_NOT_READY));
    }

    // 生成调用方绑定的 private_key_ref
    std::string key_id = key_id_resolver_ ? key_id_resolver_() : "";
    RefPayload rp;
    rp.caller_service = caller.service_name;
    rp.profile = profile;
    rp.credential_id = ps->config.credential_id;
    rp.version = ps->version;
    rp.key_id = key_id;
    rp.allowed_algorithms = ps->config.allowed_signature_algorithms;
    if (rp.allowed_algorithms.empty()) {
        rp.allowed_algorithms.push_back(SignatureAlgorithm::ECDSA_SECP256R1_SHA256);
    }
    rp.boot_epoch = boot_epoch_;
    rp.expiry = static_cast<int64_t>(std::time(nullptr)) + ps->config.ref_ttl_sec;

    OpaqueKeyRef ref = encodeRef(rp);
    if (ref.empty()) {
        return ErrorCode::INTERNAL_ERROR;
    }

    bundle.credential_id = ps->config.credential_id;
    bundle.version = ps->version;
    bundle.root_ca_bundle_der = ps->root_ca_bundle_der;
    bundle.client_cert_chain_der = ps->client_cert_chain_der;
    bundle.private_key_ref = std::move(ref);
    bundle.key_algorithm = ps->key_algorithm;
    bundle.not_before = ps->not_before;
    bundle.not_after = ps->not_after;
    bundle.status = ps->status;
    return ErrorCode::SUCCESS;
}

ErrorCode TlsCredentialProvider::getTlsCredentialState(const std::string& profile,
                                                      TlsCredentialState& state) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto* ps = findProfile(profile);
    if (!ps) return ErrorCode::INVALID_PARAMETER;
    state.credential_id = ps->config.credential_id;
    state.version = ps->version;
    state.status = ps->status;
    state.reason_code = ps->reason_code;
    return ErrorCode::SUCCESS;
}

ErrorCode TlsCredentialProvider::signTls(const TlsSignRequest& request,
                                         const PeerIdentity& caller,
                                         std::vector<uint8_t>& signature) {
    auto start = std::chrono::steady_clock::now();

    // 1. 解码引用（完整性 + 机密性）
    RefPayload rp;
    if (!decodeRef(request.private_key_ref, rp)) {
        SecLogAdapter::certificate().warn(
            "sec.tls_credential.sign.failed",
            "私钥引用解码/MAC 校验失败",
            {{"profile", tbox::fw::log::FieldValue::makeString(rp.profile)},
             {"request_id", tbox::fw::log::FieldValue::makeString(request.request_id)}}
        );
        return ErrorCode::TLS_KEY_REF_INVALID;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    // 2. 调用方身份校验：ref.caller 必须与当前 peer 一致
    if (!caller.valid || rp.caller_service != caller.service_name) {
        return ErrorCode::ACL_DENIED;
    }

    auto* ps = findProfile(rp.profile);
    if (!ps) return ErrorCode::TLS_KEY_REF_INVALID;

    // 3. 版本校验：ref.version 必须等于当前版本
    if (rp.version != ps->version) {
        return ErrorCode::TLS_KEY_REF_INVALID;
    }
    // 4. boot_epoch 校验：SEC 重启后失效
    if (rp.boot_epoch != boot_epoch_) {
        return ErrorCode::TLS_KEY_REF_INVALID;
    }
    // 5. 生命周期校验
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (rp.expiry <= now) {
        return ErrorCode::TLS_KEY_REF_INVALID;
    }
    // 6. 状态校验：非 READY 拒绝签名
    if (ps->status != TlsCredentialStatus::READY) {
        return static_cast<ErrorCode>(ps->reason_code ? ps->reason_code
                                                      : static_cast<int>(ErrorCode::TLS_CREDENTIAL_NOT_READY));
    }
    // 7. 算法/用途校验
    bool alg_ok = false;
    for (auto a : rp.allowed_algorithms) {
        if (a == request.algorithm) { alg_ok = true; break; }
    }
    if (!alg_ok || !algorithmAllowed(*ps, request.algorithm)) {
        SecLogAdapter::certificate().warn(
            "sec.tls_credential.sign.failed",
            "签名算法或用途不允许",
            {{"profile", tbox::fw::log::FieldValue::makeString(rp.profile)},
             {"algorithm", tbox::fw::log::FieldValue::makeString(signature_algorithm_to_string(request.algorithm))},
             {"request_id", tbox::fw::log::FieldValue::makeString(request.request_id)}}
        );
        return ErrorCode::TLS_SIGN_ALGORITHM_NOT_ALLOWED;
    }
    // 8. digest 长度校验（ecdsa_secp256r1_sha256 -> 32 字节）
    if (request.algorithm == SignatureAlgorithm::ECDSA_SECP256R1_SHA256 &&
        request.digest.size() != SHA256_DIGEST_LENGTH) {
        return ErrorCode::TLS_SIGN_ALGORITHM_NOT_ALLOWED;
    }

    // 9. 调用 HSM/SE 签名（对预计算摘要直接 ECDSA）
    ErrorCode rc = hsm_->sign_digest(rp.key_id, request.digest, signature);

    auto end = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (rc != ErrorCode::SUCCESS) {
        SecLogAdapter::certificate().error(
            "sec.tls_credential.sign.failed",
            "HSM/SE TLS 签名失败",
            {{"profile", tbox::fw::log::FieldValue::makeString(rp.profile)},
             {"algorithm", tbox::fw::log::FieldValue::makeString(signature_algorithm_to_string(request.algorithm))},
             {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)},
             {"request_id", tbox::fw::log::FieldValue::makeString(request.request_id)},
             {"reason_code", tbox::fw::log::FieldValue::makeInt(static_cast<int>(rc))}}
        );
        return ErrorCode::TLS_HSM_SIGN_FAILED;
    }

    SecLogAdapter::certificate().debug(
        "sec.tls_credential.sign.succeeded",
        "TLS 签名完成",
        {{"profile", tbox::fw::log::FieldValue::makeString(rp.profile)},
         {"credential_id_hash", tbox::fw::log::FieldValue::makeString(hashId(rp.credential_id))},
         {"version", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(rp.version))},
         {"algorithm", tbox::fw::log::FieldValue::makeString(signature_algorithm_to_string(request.algorithm))},
         {"duration_ms", tbox::fw::log::FieldValue::makeInt(duration_ms)},
         {"peer_service", tbox::fw::log::FieldValue::makeString(caller.service_name)}}
    );
    return ErrorCode::SUCCESS;
}

ErrorCode TlsCredentialProvider::rotateCredential(const std::string& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto* ps = findProfile(profile);
    if (!ps) return ErrorCode::INVALID_PARAMETER;
    ps->version++;  // 版本单调递增，旧引用立即失效
    ErrorCode rc = validateAndStoreMaterials(*ps);
    publishChanged(profile, *ps, ps->status,
                   rc == ErrorCode::SUCCESS ? 0 : static_cast<int>(rc));
    return rc;
}

ErrorCode TlsCredentialProvider::revokeCredential(const std::string& profile) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto* ps = findProfile(profile);
    if (!ps) return ErrorCode::INVALID_PARAMETER;
    ps->status = TlsCredentialStatus::REVOKED;
    ps->reason_code = static_cast<int32_t>(ErrorCode::TLS_CREDENTIAL_INVALID);
    ps->version++;
    publishChanged(profile, *ps, TlsCredentialStatus::REVOKED,
                   static_cast<int>(ErrorCode::TLS_CREDENTIAL_INVALID));
    SecLogAdapter::certificate().warn(
        "sec.tls_credential.changed",
        "凭据已撤销",
        {{"profile", tbox::fw::log::FieldValue::makeString(profile)},
         {"credential_id_hash", tbox::fw::log::FieldValue::makeString(hashId(ps->config.credential_id))},
         {"version", tbox::fw::log::FieldValue::makeInt(static_cast<int64_t>(ps->version))},
         {"status", tbox::fw::log::FieldValue::makeString(tls_credential_status_to_string(ps->status))}}
    );
    return ErrorCode::SUCCESS;
}

} // namespace sec
} // namespace tbox
