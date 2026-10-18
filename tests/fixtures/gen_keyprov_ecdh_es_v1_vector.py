#!/usr/bin/env python3
"""独立参考实现：生成 tests/fixtures/keyprov_ecdh_es_v1_vector.json。

用途（TBOX-SEC-DSN-CR-020 §13 / US-017/018/020）：
  * 以固定、非生产 P-256 私钥夹具离线计算 ECDH/HKDF/AES-GCM 与 canonical
    framing（AAD/envelopeDigest/KCV/proofInput）的期望值；
  * 作为 C++ `buildEcdhEsP256EnvelopeV1` 的跨实现 golden vector 断言源，避免
    C++ 侧自证。

重要：本脚本手写 `EcdhEsP256EnvelopeParametersV1` 的 deterministic protobuf bytes，
而非依赖 protoc/Python runtime 版本；字段号/类型与 proto/security/keyprov/v1 冻结定义一致，
其本身即对 wire 布局的独立复核。C++ 侧仍通过生成代码解析（禁止手写 wire codec）。

依赖：cryptography。运行：python3 tests/fixtures/gen_keyprov_ecdh_es_v1_vector.py
"""

import hashlib
import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---- 固定非生产夹具 ----
DEVICE_PRIV = bytes.fromhex(
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")
EPH_PRIV = bytes.fromhex(
    "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534")
HKDF_SALT = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
NONCE = bytes.fromhex("aabbccddeeff001122334455")
BUSINESS_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
RECIPIENT_CERT_DIGEST = bytes.fromhex(
    "aa" * 32)

REQUEST_ID = "req-golden-0001"
BUSINESS_DOMAIN = "V2C_COMM"
PURPOSE_NAME = "UPLINK_AEAD"
PURPOSE_ENUM = 1
KEY_ID = "kid-golden-uplink"
BUSINESS_KEY_VERSION = 1
ROOT_KEY_VERSION = 1
DERIVATION_VERSION = "v1"
OPERATION_ID = "op-golden-0001"
HKDF_CONTEXT_VERSION = "v1"
WRAPPING_SUITE_ENUM = 1
ENVELOPE_FORMAT_ENUM = 1


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


def proto_bytes(field: int, wire: int, value: bytes) -> bytes:
    return varint((field << 3) | wire) + value


def pb_bytes(field: int, value: bytes) -> bytes:
    """protobuf 长度分隔字段：tag + varint(len) + value（非 canonical u32be 长度）。"""
    return proto_bytes(field, 2, varint(len(value)) + value)


def encode_params(p) -> bytes:
    """确定性 protobuf（字段号升序；proto3 省略默认值）。"""
    out = bytearray()
    out += proto_bytes(1, 0, varint(p["format_version"]))
    out += pb_bytes(2, p["server_ephemeral_public_key"])
    out += pb_bytes(3, p["hkdf_salt"])
    out += pb_bytes(4, p["hkdf_context_version"].encode("utf-8"))
    out += pb_bytes(5, p["nonce"])
    out += pb_bytes(6, p["authentication_tag"])
    out += pb_bytes(7, p["canonical_aad"])
    out += pb_bytes(8, p["aad_digest"])
    out += proto_bytes(9, 0, varint(p["root_key_version"]))
    out += pb_bytes(10, p["derivation_version"].encode("utf-8"))
    out += pb_bytes(11, p["recipient_certificate_digest"])
    out += pb_bytes(12, p["operation_id"].encode("utf-8"))
    return bytes(out)


def build_aad_v1(recipient_fp: bytes) -> bytes:
    return (
        seg(b"v1")
        + enum_seg(WRAPPING_SUITE_ENUM)
        + seg(REQUEST_ID.encode("utf-8"))
        + seg(BUSINESS_DOMAIN.encode("utf-8"))
        + enum_seg(PURPOSE_ENUM)
        + seg(KEY_ID.encode("utf-8"))
        + u64be_seg(BUSINESS_KEY_VERSION)
        + u64be_seg(ROOT_KEY_VERSION)
        + seg(DERIVATION_VERSION.encode("utf-8"))
        + seg(recipient_fp)
    )


def envelope_digest(wrapped_key: bytes, parameters: bytes) -> bytes:
    buf = (
        enum_seg(ENVELOPE_FORMAT_ENUM)
        + seg(REQUEST_ID.encode("utf-8"))
        + seg(BUSINESS_DOMAIN.encode("utf-8"))
        + enum_seg(PURPOSE_ENUM)
        + seg(KEY_ID.encode("utf-8"))
        + u64be_seg(BUSINESS_KEY_VERSION)
        + enum_seg(WRAPPING_SUITE_ENUM)
        + seg(wrapped_key)
        + seg(parameters)
    )
    return hashlib.sha256(buf).digest()


def proof_input(envelope_dgst: bytes, kcv: bytes) -> bytes:
    return (
        seg(b"openiov|keyprov-ack|v1")
        + seg(REQUEST_ID.encode("utf-8"))
        + seg(BUSINESS_DOMAIN.encode("utf-8"))
        + enum_seg(PURPOSE_ENUM)
        + seg(hashlib.sha256(KEY_ID.encode("utf-8")).digest())
        + u64be_seg(BUSINESS_KEY_VERSION)
        + seg(envelope_dgst)
        + seg(kcv)
    )


def hkdf_info(recipient_fp: bytes) -> bytes:
    return (
        f"openiov|keyprov-wrap|v1|{REQUEST_ID}|{BUSINESS_DOMAIN}|{PURPOSE_NAME}|"
        f"{KEY_ID}|{BUSINESS_KEY_VERSION}|{recipient_fp.hex()}"
    ).encode("utf-8")


def main():
    device_priv = ec.derive_private_key(int.from_bytes(DEVICE_PRIV, "big"),
                                        ec.SECP256R1())
    device_pub = device_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)

    eph_priv = ec.derive_private_key(int.from_bytes(EPH_PRIV, "big"), ec.SECP256R1())
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint)

    recipient_fp = RECIPIENT_CERT_DIGEST
    canonical_aad = build_aad_v1(recipient_fp)
    aad_digest = hashlib.sha256(canonical_aad).digest()
    info = hkdf_info(recipient_fp)

    shared = eph_priv.exchange(ec.ECDH(), device_priv.public_key())
    kek = HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT,
               info=info).derive(shared)

    ct_tag = AESGCM(kek).encrypt(NONCE, BUSINESS_KEY, canonical_aad)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]

    params = encode_params({
        "format_version": 1,
        "server_ephemeral_public_key": eph_pub,
        "hkdf_salt": HKDF_SALT,
        "hkdf_context_version": HKDF_CONTEXT_VERSION,
        "nonce": NONCE,
        "authentication_tag": tag,
        "canonical_aad": canonical_aad,
        "aad_digest": aad_digest,
        "root_key_version": ROOT_KEY_VERSION,
        "derivation_version": DERIVATION_VERSION,
        "recipient_certificate_digest": recipient_fp,
        "operation_id": OPERATION_ID,
    })

    env_dgst = envelope_digest(ciphertext, params)
    kcv = hashlib.sha256(BUSINESS_KEY).digest()[:3]
    pinput = proof_input(env_dgst, kcv)

    vector = {
        "_comment": "非生产 golden vector；由 gen_keyprov_ecdh_es_v1_vector.py 生成",
        "inputs": {
            "device_private_key": DEVICE_PRIV.hex(),
            "device_public_key": device_pub.hex(),
            "server_ephemeral_private_key": EPH_PRIV.hex(),
            "hkdf_salt": HKDF_SALT.hex(),
            "nonce": NONCE.hex(),
            "business_key": BUSINESS_KEY.hex(),
            "recipient_certificate_digest": recipient_fp.hex(),
            "request_id": REQUEST_ID,
            "business_domain": BUSINESS_DOMAIN,
            "purpose": PURPOSE_NAME,
            "key_id": KEY_ID,
            "business_key_version": BUSINESS_KEY_VERSION,
            "root_key_version": ROOT_KEY_VERSION,
            "derivation_version": DERIVATION_VERSION,
            "operation_id": OPERATION_ID,
            "hkdf_context_version": HKDF_CONTEXT_VERSION,
            "wrapping_suite": "ECDH_ES_P256_HKDF_SHA256_AES256GCM",
            "key_algorithm": "AES-256",
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
            "parameters": params.hex(),
            "envelope_digest": env_dgst.hex(),
            "key_check_value": kcv.hex(),
            "proof_input": pinput.hex(),
        },
    }

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "keyprov_ecdh_es_v1_vector.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(vector, f, indent=2, sort_keys=True)
        f.write("\n")
    print("wrote", out_path)


if __name__ == "__main__":
    main()
