#!/usr/bin/env python3
"""TBOX-SEC 本地 VEH-PROTO fixtures 再生工具（TBOX-SEC-DSN-CR-022 §5）。

生成 tests/fixtures/keyprov_ecdh_es_v1_vector.json（含跨端 primary/boundary/
negative 与 SEC 本地 builder 段），并支持 --check 逐字节比对 committed fixtures。

本工具仅是 SEC 仓库测试工具：
  * 输入与编码规则严格对应 VEH-PROTO（10 段 PAR_PROTO_KEYPROV_AAD_V1、
    9 字段 wireEnvelopeDigest、wrappingSuite 登记值 2、uint64be/businessKeyVersion
    边界、deterministic parameters bytes）；
  * 不得被视为新的协议 SSOT，也不得在量产运行时参与编码；
  * fixture manifest（keyprov_fixture_manifest.json）由 scripts/
    regenerate_keyprov_fixtures.sh 汇总本地 proto/DescriptorSet/工具 hash 生成。

primary 段固定输入（TBOX-SEC-DSN-CR-022 §5 跨端对账）：
  requestId=req-kp-0009, businessDomain=V2C_COMM, keyId=biz-key-up-0009,
  purpose=1, businessKeyVersion=3, wrappingSuite=2, rootKeyVersion=7,
  derivationVersion=openiov|v2c|v1, recipientCertificateDigest=0x61*32。
primary 段与 boundary 段期望字节必须与 VMD/Java（同一 PAR-PROTO CR-009
canonical 语义）逐字节一致；该比对是发布证据，不构成对 PAR-PROTO 仓库依赖。

依赖：cryptography（仅 builder 段真实 ECDH/HKDF/AES-GCM 与 RFC6979 签名用）。
运行：
  python3 tests/fixtures/gen_keyprov_ecdh_es_v1_vector.py            # 生成（写文件）
  python3 tests/fixtures/gen_keyprov_ecdh_es_v1_vector.py --check    # 再生后与 committed 逐字节比对
"""

import argparse
import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ===================== framing primitives（VEH-PROTO §7.2.2） =================

def u32be(v):
    return v.to_bytes(4, "big")


def seg(value: bytes) -> bytes:
    """lengthPrefixed(segment) = uint32be(len) + value bytes。"""
    return u32be(len(value)) + value


def varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def enum_seg(v: int) -> bytes:
    return seg(varint(v))


def u64be_seg(v: int) -> bytes:
    return seg(v.to_bytes(8, "big"))


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


# ===================== deterministic protobuf encoding =======================

def proto_bytes(field: int, wire: int, value: bytes) -> bytes:
    return varint((field << 3) | wire) + value


def pb_bytes(field: int, value: bytes) -> bytes:
    return proto_bytes(field, 2, varint(len(value)) + value)


def pb_varint(field: int, value: int) -> bytes:
    return proto_bytes(field, 0, varint(value))


# ===================== CR-009 / VEH-PROTO canonical constants ================

WIRE_PROFILE = "PAR_PROTO_KEYPROV_ECDH_ES_P256_V1"
AAD_PROFILE = "PAR_PROTO_KEYPROV_AAD_V1"
PROOF_DOMAIN = "openiov|keyprov-ack|v1"
WRAP_INFO_DOMAIN = "openiov|keyprov-wrap|v1"
PROOF_ALGORITHM = "ECDSA_P256_SHA256_P1363"

# ---- 跨端固定 primary input（TBOX-SEC-DSN-CR-022 §5）----
PRIMARY = {
    "request_id": "req-kp-0009",
    "business_domain": "V2C_COMM",
    "key_id": "biz-key-up-0009",
    "purpose": 1,                       # KEY_PURPOSE_UPLINK_AEAD
    "business_key_version": 3,
    "envelope_format": 1,               # KEY_ENVELOPE_FORMAT_ECDH_ES_P256_V1
    "wrapping_suite": 2,                # ECDH_ES_P256_HKDF_SHA256_AES256GCM（登记值）
    "root_key_version": 7,
    "derivation_version": "openiov|v2c|v1",
    "operation_id": "op-kp-0009",
    "recipient_certificate_digest": b"\x61" * 32,
    # ---- 跨端 wire-contract 固定密码学输入（与 VMD/Java 一致；非真实密钥材料）----
    "server_ephemeral_public_key": bytes.fromhex(
        "04" + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
        + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),  # P-256 G
    "hkdf_salt": b"\x21" * 32,
    "nonce": b"\x31" * 12,
    "authentication_tag": b"\x41" * 16,
    "wrapped_key": b"\x71" * 64,
    "business_key": b"\x81" * 32,       # UPLINK business key（KCV 推导演示）
    "key_algorithm": "AES-256",
    "hkdf_context_version": "v1",
}
DOWNLINK_KEY_ID = "biz-key-down-0009"
DOWNLINK_BUSINESS_KEY = b"\x91" * 32


# ===================== canonical builders（VEH-PROTO §7.2.2） ================

def build_aad_v1(efmt: int, suite: int, purpose: int, biz_ver: int, root_ver: int,
                 cert_digest: bytes, request_id: str, domain: str, key_id: str,
                 derivation: str) -> bytes:
    """PAR_PROTO_KEYPROV_AAD_V1：固定 10 段；nonce 不进入 AAD。"""
    return (
        enum_seg(efmt)
        + enum_seg(suite)
        + enum_seg(purpose)
        + u64be_seg(biz_ver)
        + u64be_seg(root_ver)
        + seg(cert_digest)
        + seg(request_id.encode("utf-8"))
        + seg(domain.encode("utf-8"))
        + seg(key_id.encode("utf-8"))
        + seg(derivation.encode("utf-8"))
    )


def wire_digest_input(efmt: int, request_id: str, domain: str, purpose: int,
                      key_id: str, biz_ver: int, suite: int, wrapped_key: bytes,
                      parameters: bytes) -> bytes:
    """PAR_PROTO_KEYPROV_ECDH_ES_P256_V1：共且仅有 9 个顶层 segment。"""
    return (
        enum_seg(efmt)
        + seg(request_id.encode("utf-8"))
        + seg(domain.encode("utf-8"))
        + enum_seg(purpose)
        + seg(key_id.encode("utf-8"))
        + u64be_seg(biz_ver)
        + enum_seg(suite)
        + seg(wrapped_key)
        + seg(parameters)
    )


def proof_input_v1(request_id: str, domain: str, purpose: int, key_id: str,
                   biz_ver: int, envelope_digest: bytes, kcv: bytes) -> bytes:
    """CR-008 proofInputV1：八段扁平编码。"""
    return (
        seg(PROOF_DOMAIN.encode("utf-8"))
        + seg(request_id.encode("utf-8"))
        + seg(domain.encode("utf-8"))
        + enum_seg(purpose)
        + seg(sha256(key_id.encode("utf-8")))
        + u64be_seg(biz_ver)
        + seg(envelope_digest)
        + seg(kcv)
    )


def hkdf_info(request_id: str, domain: str, purpose_name: str, key_id: str,
              biz_ver: int, recipient_fp: bytes) -> bytes:
    return (
        f"{WRAP_INFO_DOMAIN}|{request_id}|{domain}|{purpose_name}|{key_id}|"
        f"{biz_ver}|{recipient_fp.hex()}"
    ).encode("utf-8")


def encode_params(fmt_ver, eph_pub, salt, hkdf_ctx, nonce, tag, canonical_aad,
                  aad_digest, root_ver, derivation, cert_digest, operation_id) -> bytes:
    """deterministic protobuf（字段号升序；所有字段均有值，无默认值省略）。"""
    out = bytearray()
    out += pb_varint(1, fmt_ver)
    out += pb_bytes(2, eph_pub)
    out += pb_bytes(3, salt)
    out += pb_bytes(4, hkdf_ctx.encode("utf-8"))
    out += pb_bytes(5, nonce)
    out += pb_bytes(6, tag)
    out += pb_bytes(7, canonical_aad)
    out += pb_bytes(8, aad_digest)
    out += pb_varint(9, root_ver)
    out += pb_bytes(10, derivation.encode("utf-8"))
    out += pb_bytes(11, cert_digest)
    out += pb_bytes(12, operation_id.encode("utf-8"))
    return bytes(out)


# ===================== P-256 / RFC 6979（builder 段签名用） ==================

P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def _point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P256_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + P256_A) * pow(2 * y1, -1, P256_P) % P256_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P256_P) % P256_P
    x3 = (lam * lam - x1 - x2) % P256_P
    y3 = (lam * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _point_mul(k: int, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _rfc6979_candidates(x: int, h1: bytes, hlen: int = 32):
    qlen = P256_N.bit_length()

    def bits2int(b: bytes) -> int:
        v = int.from_bytes(b, "big")
        blen = len(b) * 8
        return v >> (blen - qlen) if blen > qlen else v

    def int2octets(v: int) -> bytes:
        return v.to_bytes(hlen, "big")

    def bits2octets(b: bytes) -> bytes:
        z1 = bits2int(b)
        z2 = z1 - P256_N
        return int2octets(z2 if z2 >= 0 else z1)

    V = b"\x01" * hlen
    K = b"\x00" * hlen
    K = hmac.new(K, V + b"\x00" + int2octets(x) + bits2octets(h1), hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + int2octets(x) + bits2octets(h1), hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        T = b""
        while len(T) < (qlen + 7) // 8:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = bits2int(T)
        if 1 <= k < P256_N:
            yield k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def ecdsa_p1363_low_s(priv_int: int, msg: bytes) -> bytes:
    digest = hashlib.sha256(msg).digest()
    z = int.from_bytes(digest, "big")
    for k in _rfc6979_candidates(priv_int, digest):
        R = _point_mul(k, P256_G)
        if R is None:
            continue
        r = R[0] % P256_N
        if r == 0:
            continue
        s = (pow(k, -1, P256_N) * (z + r * priv_int)) % P256_N
        if s == 0:
            continue
        if s > P256_N // 2:
            s = P256_N - s
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise AssertionError("unreachable")


# ===================== builder 段（真实 ECDH/HKDF/AES-GCM，固定密钥） ========

BUILDER_INPUTS = {
    "device_private_key": bytes.fromhex(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
    "server_ephemeral_private_key": bytes.fromhex(
        "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"),
    "hkdf_salt": bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    "nonce": bytes.fromhex("aabbccddeeff001122334455"),
    "business_key": bytes.fromhex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
    "recipient_certificate_digest": b"\xaa" * 32,
    "request_id": "req-golden-0001",
    "business_domain": "V2C_COMM",
    "purpose_name": "UPLINK_AEAD",
    "key_id": "kid-golden-uplink",
    "business_key_version": 1,
    "root_key_version": 1,
    "derivation_version": "v1",
    "operation_id": "op-golden-0001",
    "hkdf_context_version": "v1",
    "wrapping_suite": "ECDH_ES_P256_HKDF_SHA256_AES256GCM",
    "key_algorithm": "AES-256",
}


def builder_section():
    """独立参考实现的封装方向 golden：固定密钥的真实 ECDH/HKDF/AES-GCM。"""
    in_ = BUILDER_INPUTS
    device_priv = ec.derive_private_key(int.from_bytes(in_["device_private_key"], "big"),
                                        ec.SECP256R1())
    device_pub = device_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    eph_priv = ec.derive_private_key(int.from_bytes(in_["server_ephemeral_private_key"], "big"),
                                     ec.SECP256R1())
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    purpose = 1  # UPLINK_AEAD
    suite = 2
    canonical_aad = build_aad_v1(
        1, suite, purpose, in_["business_key_version"], in_["root_key_version"],
        in_["recipient_certificate_digest"], in_["request_id"], in_["business_domain"],
        in_["key_id"], in_["derivation_version"])
    aad_digest = sha256(canonical_aad)
    info = hkdf_info(in_["request_id"], in_["business_domain"], in_["purpose_name"],
                     in_["key_id"], in_["business_key_version"],
                     in_["recipient_certificate_digest"])

    shared = eph_priv.exchange(ec.ECDH(), device_priv.public_key())
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=in_["hkdf_salt"],
               info=info).derive(shared)

    ct_tag = AESGCM(kek).encrypt(in_["nonce"], in_["business_key"], canonical_aad)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]

    parameters = encode_params(1, eph_pub, in_["hkdf_salt"], in_["hkdf_context_version"],
                               in_["nonce"], tag, canonical_aad, aad_digest,
                               in_["root_key_version"], in_["derivation_version"],
                               in_["recipient_certificate_digest"], in_["operation_id"])

    wdi = wire_digest_input(1, in_["request_id"], in_["business_domain"], purpose,
                            in_["key_id"], in_["business_key_version"], suite,
                            ciphertext, parameters)
    env_dgst = sha256(wdi)
    kcv = sha256(in_["business_key"])[:3]
    pinput = proof_input_v1(in_["request_id"], in_["business_domain"], purpose,
                            in_["key_id"], in_["business_key_version"], env_dgst, kcv)
    proof = ecdsa_p1363_low_s(int.from_bytes(in_["device_private_key"], "big"), pinput)

    # 自检：用 cryptography 独立验签。
    r_int = int.from_bytes(proof[:32], "big")
    s_int = int.from_bytes(proof[32:], "big")
    device_priv.public_key().verify(
        utils.encode_dss_signature(r_int, s_int),
        hashlib.sha256(pinput).digest(),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    assert s_int <= P256_N // 2, "proof must be low-S"

    return {
        "inputs": {
            "device_private_key": in_["device_private_key"].hex(),
            "device_public_key": device_pub.hex(),
            "server_ephemeral_private_key": in_["server_ephemeral_private_key"].hex(),
            "hkdf_salt": in_["hkdf_salt"].hex(),
            "nonce": in_["nonce"].hex(),
            "business_key": in_["business_key"].hex(),
            "recipient_certificate_digest": in_["recipient_certificate_digest"].hex(),
            "request_id": in_["request_id"],
            "business_domain": in_["business_domain"],
            "purpose": in_["purpose_name"],
            "key_id": in_["key_id"],
            "business_key_version": in_["business_key_version"],
            "root_key_version": in_["root_key_version"],
            "derivation_version": in_["derivation_version"],
            "operation_id": in_["operation_id"],
            "hkdf_context_version": in_["hkdf_context_version"],
            "wrapping_suite": in_["wrapping_suite"],
            "key_algorithm": in_["key_algorithm"],
        },
        "expected": {
            "server_ephemeral_public_key": eph_pub.hex(),
            "canonical_aad": canonical_aad.hex(),
            "aad_digest": aad_digest.hex(),
            "hkdf_info": info.decode("utf-8"),
            "ecdh_shared_secret": shared.hex(),
            "kek": kek.hex(),
            "wrapped_key": ciphertext.hex(),
            "authentication_tag": tag.hex(),
            "parameters": parameters.hex(),
            "envelope_digest": env_dgst.hex(),
            "key_check_value": kcv.hex(),
            "proof_input": pinput.hex(),
            "import_proof": proof.hex(),
            "proof_algorithm": PROOF_ALGORITHM,
        },
    }


# ===================== negative vectors ======================================

def _mutate_aad_cases(aad: bytes):
    """逐段单字节篡改 AAD（每段首个 value byte 翻转）。"""
    cases = []
    names = ["envelopeFormat", "wrappingSuite", "purpose", "businessKeyVersion",
             "rootKeyVersion", "recipientCertificateDigest", "requestId",
             "businessDomain", "keyId", "derivationVersion"]
    off = 0
    for i in range(10):
        ln = int.from_bytes(aad[off:off + 4], "big")
        val_start = off + 4
        m = bytearray(aad)
        m[val_start] ^= 0xFF
        cases.append({
            "segment_index": i,
            "segment": names[i],
            "mutated_canonical_aad_hex": bytes(m).hex(),
            "mutated_aad_digest_hex": sha256(bytes(m)).hex(),
        })
        off = val_start + ln
    return cases


def _mutate_wire_cases(wdi: bytes):
    """逐段单字节篡改 wire digest input。"""
    cases = []
    names = ["envelopeFormat", "requestId", "businessDomain", "purpose", "keyId",
             "businessKeyVersion", "wrappingSuite", "wrappedKey", "parameters"]
    off = 0
    for i in range(9):
        ln = int.from_bytes(wdi[off:off + 4], "big")
        val_start = off + 4
        m = bytearray(wdi)
        m[val_start] ^= 0xFF
        cases.append({
            "segment_index": i,
            "segment": names[i],
            "mutated_wire_digest_input_hex": bytes(m).hex(),
            "mutated_wire_envelope_digest_hex": sha256(bytes(m)).hex(),
        })
        off = val_start + ln
    return cases


def _params_from_primary(p: dict, canonical_aad: bytes, aad_digest: bytes) -> bytes:
    return encode_params(1, p["server_ephemeral_public_key"], p["hkdf_salt"],
                         p["hkdf_context_version"], p["nonce"], p["authentication_tag"],
                         canonical_aad, aad_digest, p["root_key_version"],
                         p["derivation_version"], p["recipient_certificate_digest"],
                         p["operation_id"])


def negative_section(primary, canonical_aad, aad_digest, params, wdi, env_dgst):
    p = primary

    def mutate_params(**kw):
        return encode_params(kw.get("fmt_ver", 1), kw.get("eph", p["server_ephemeral_public_key"]),
                             kw.get("salt", p["hkdf_salt"]), kw.get("ctx", p["hkdf_context_version"]),
                             kw.get("nonce", p["nonce"]), kw.get("tag", p["authentication_tag"]),
                             kw.get("aad", canonical_aad), kw.get("aad_dg", aad_digest),
                             kw.get("root", p["root_key_version"]),
                             kw.get("deriv", p["derivation_version"]),
                             kw.get("cert", p["recipient_certificate_digest"]),
                             kw.get("op", p["operation_id"]))

    illegal_lengths = [
        {"name": "hkdf_salt_31", "parameters_hex": mutate_params(salt=b"\x21" * 31).hex()},
        {"name": "nonce_11", "parameters_hex": mutate_params(nonce=b"\x31" * 11).hex()},
        {"name": "auth_tag_15", "parameters_hex": mutate_params(tag=b"\x41" * 15).hex()},
        {"name": "cert_digest_31", "parameters_hex": mutate_params(cert=b"\x61" * 31).hex()},
        {"name": "aad_digest_31", "parameters_hex": mutate_params(aad_dg=b"\x11" * 31).hex()},
    ]

    unknown_format = mutate_params(fmt_ver=777)

    # unknown field 99 appended（varint 12345）
    unknown_field_params = params + varint(99 << 3) + varint(12345)
    digest_over_unknown = sha256(
        wire_digest_input(1, p["request_id"], p["business_domain"], p["purpose"],
                          p["key_id"], p["business_key_version"], p["wrapping_suite"],
                          p["wrapped_key"], unknown_field_params))

    # 语义相同但字段乱序的重编码（非 deterministic）→ digest 不同
    reencoded = (
        pb_bytes(12, p["operation_id"].encode("utf-8"))
        + pb_bytes(11, p["recipient_certificate_digest"])
        + pb_bytes(10, p["derivation_version"].encode("utf-8"))
        + pb_varint(9, p["root_key_version"])
        + pb_bytes(8, aad_digest)
        + pb_bytes(7, canonical_aad)
        + pb_bytes(6, p["authentication_tag"])
        + pb_bytes(5, p["nonce"])
        + pb_bytes(4, p["hkdf_context_version"].encode("utf-8"))
        + pb_bytes(3, p["hkdf_salt"])
        + pb_bytes(2, p["server_ephemeral_public_key"])
        + pb_varint(1, 1)
    )
    digest_over_reencoded = sha256(
        wire_digest_input(1, p["request_id"], p["business_domain"], p["purpose"],
                          p["key_id"], p["business_key_version"], p["wrapping_suite"],
                          p["wrapped_key"], reencoded))

    return {
        "parameters_illegal_lengths": illegal_lengths,
        "parameters_unknown_field": {
            "parameters_hex": unknown_field_params.hex(),
            "authoritative_wire_envelope_digest_hex": env_dgst.hex(),
            "digest_over_unknown_field_bytes_hex": digest_over_unknown.hex(),
        },
        "parameters_reencoded": {
            "original_parameters_hex": params.hex(),
            "reencoded_parameters_hex": reencoded.hex(),
            "authoritative_wire_envelope_digest_hex": env_dgst.hex(),
            "digest_over_reencoded_hex": digest_over_reencoded.hex(),
        },
        "parameters_unknown_format_version": {
            "parameters_hex": unknown_format.hex(),
        },
        "tamper_canonical_aad": {
            "authoritative_canonical_aad_hex": canonical_aad.hex(),
            "authoritative_aad_digest_hex": aad_digest.hex(),
            "cases": _mutate_aad_cases(canonical_aad),
        },
        "tamper_wire_digest_input": {
            "authoritative_wire_envelope_digest_hex": env_dgst.hex(),
            "cases": _mutate_wire_cases(wdi),
        },
    }


# ===================== main ==================================================

def build_fixture():
    p = PRIMARY

    canonical_aad = build_aad_v1(
        p["envelope_format"], p["wrapping_suite"], p["purpose"], p["business_key_version"],
        p["root_key_version"], p["recipient_certificate_digest"], p["request_id"],
        p["business_domain"], p["key_id"], p["derivation_version"])
    aad_digest = sha256(canonical_aad)
    params = _params_from_primary(p, canonical_aad, aad_digest)
    wdi = wire_digest_input(
        p["envelope_format"], p["request_id"], p["business_domain"], p["purpose"],
        p["key_id"], p["business_key_version"], p["wrapping_suite"], p["wrapped_key"],
        params)
    env_dgst = sha256(wdi)
    kcv = sha256(p["business_key"])[:3]
    pinput = proof_input_v1(
        p["request_id"], p["business_domain"], p["purpose"], p["key_id"],
        p["business_key_version"], env_dgst, kcv)

    # boundary：businessKeyVersion 1/127/128/255/256/2^32/2^63-1，purpose 1/2
    versions = [1, 127, 128, 255, 256, 1 << 32, (1 << 63) - 1]
    vnames = ["v1", "v127", "v128", "v255", "v256", "v2e32", "v2e63m1"]
    boundary = []
    for ver, name in zip(versions, vnames):
        wd = wire_digest_input(p["envelope_format"], p["request_id"], p["business_domain"],
                               p["purpose"], p["key_id"], ver, p["wrapping_suite"],
                               p["wrapped_key"], params)
        boundary.append({
            "name": name, "purpose": p["purpose"], "business_key_version": ver,
            "wire_digest_input_hex": wd.hex(), "wire_envelope_digest_hex": sha256(wd).hex(),
        })
    wd_down = wire_digest_input(p["envelope_format"], p["request_id"], p["business_domain"],
                                2, DOWNLINK_KEY_ID, p["business_key_version"],
                                p["wrapping_suite"], p["wrapped_key"], params)
    boundary.append({
        "name": "purpose_downlink", "purpose": 2, "key_id": DOWNLINK_KEY_ID,
        "business_key_version": p["business_key_version"],
        "wire_digest_input_hex": wd_down.hex(), "wire_envelope_digest_hex": sha256(wd_down).hex(),
    })

    fixture = {
        "_comment": "TBOX-SEC 本地 VEH-PROTO fixtures；由 gen_keyprov_ecdh_es_v1_vector.py 再生，"
                    "不得手工修改（keyprov_fixture_manifest.json 锁定逐文件 hash）。",
        "veh_proto_revision": "VEH-PROTO 2026-10-25（PAR-PROTO-DSN-CR-009 同步）",
        "profile": {
            "wire": WIRE_PROFILE,
            "aad": AAD_PROFILE,
            "wire_segments": 9,
            "aad_segments": 10,
            "wire_field_order": ["envelopeFormat", "requestId", "businessDomain", "purpose",
                                 "keyId", "businessKeyVersion", "wrappingSuite", "wrappedKey",
                                 "parameters"],
            "aad_field_order": ["envelopeFormat", "wrappingSuite", "purpose",
                                "businessKeyVersion", "rootKeyVersion",
                                "recipientCertificateDigest", "requestId", "businessDomain",
                                "keyId", "derivationVersion"],
        },
        "primary": {
            "request_id": p["request_id"],
            "business_domain": p["business_domain"],
            "key_id": p["key_id"],
            "purpose": p["purpose"],
            "business_key_version": p["business_key_version"],
            "envelope_format": p["envelope_format"],
            "wrapping_suite": p["wrapping_suite"],
            "root_key_version": p["root_key_version"],
            "derivation_version": p["derivation_version"],
            "operation_id": p["operation_id"],
            "recipient_certificate_digest_hex": p["recipient_certificate_digest"].hex(),
            "crypto": {
                "server_ephemeral_public_key_hex": p["server_ephemeral_public_key"].hex(),
                "hkdf_salt_hex": p["hkdf_salt"].hex(),
                "nonce_hex": p["nonce"].hex(),
                "authentication_tag_hex": p["authentication_tag"].hex(),
                "wrapped_key_hex": p["wrapped_key"].hex(),
                "business_key_hex": p["business_key"].hex(),
                "key_algorithm": p["key_algorithm"],
                "hkdf_context_version": p["hkdf_context_version"],
            },
            "expected": {
                "canonical_aad": canonical_aad.hex(),
                "aad_digest": aad_digest.hex(),
                "parameters": params.hex(),
                "wire_digest_input": wdi.hex(),
                "wire_envelope_digest": env_dgst.hex(),
                "key_check_value": kcv.hex(),
                "proof_input": pinput.hex(),
                "hkdf_info": hkdf_info(p["request_id"], p["business_domain"], "UPLINK_AEAD",
                                       p["key_id"], p["business_key_version"],
                                       p["recipient_certificate_digest"]).decode("utf-8"),
                "downlink_key_check_value": sha256(DOWNLINK_BUSINESS_KEY)[:3].hex(),
            },
        },
        "boundary_vectors": boundary,
        "varint_boundary": {
            "unsigned_varint_127_hex": varint(127).hex(),
            "unsigned_varint_128_hex": varint(128).hex(),
            "uint64be_127_hex": (127).to_bytes(8, "big").hex(),
            "uint64be_128_hex": (128).to_bytes(8, "big").hex(),
            "note": "127 编码为 1 字节 varint / 8 字节 uint64be；128 编码为 2 字节 varint "
                    "但仍为 8 字节 uint64be（阻断 protobuf varint 误用）",
        },
        "negative": negative_section(p, canonical_aad, aad_digest, params, wdi, env_dgst),
        "builder": builder_section(),
    }
    return fixture


def main():
    ap = argparse.ArgumentParser(description="TBOX-SEC keyprov VEH-PROTO fixtures regenerator")
    ap.add_argument("--check", action="store_true",
                    help="再生到内存并与 committed fixtures 逐字节比对；不一致返回非 0")
    ap.add_argument("--out", default=None, help="写入路径（默认 tests/fixtures/keyprov_ecdh_es_v1_vector.json）")
    args = ap.parse_args()

    fixture = build_fixture()
    out_bytes = (json.dumps(fixture, indent=2, sort_keys=True) + "\n").encode("utf-8")

    here = os.path.dirname(os.path.abspath(__file__))
    target = args.out or os.path.join(here, "keyprov_ecdh_es_v1_vector.json")

    if args.check:
        if not os.path.exists(target):
            print("ERROR: committed fixture missing:", target, file=sys.stderr)
            sys.exit(1)
        committed = open(target, "rb").read()
        if committed != out_bytes:
            print("ERROR: regenerated fixture differs from committed", target,
                  file=sys.stderr)
            sys.exit(1)
        print("OK: regenerated fixture byte-identical to committed", target)
        return

    with open(target, "wb") as f:
        f.write(out_bytes)
    print("wrote", target, f"({len(out_bytes)} bytes)")


if __name__ == "__main__":
    main()
