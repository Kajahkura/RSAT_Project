"""Standard bundle primitives supplied by PyCryptodome, with no custom cryptography."""

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Protocol.DH import import_x25519_public_key, key_agreement
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import eddsa


def generate_key(curve):
    return ECC.generate(curve=curve)


def private_pem(key):
    return key.export_key(format="PEM", use_pkcs8=True).encode("ascii")


def public_pem(key):
    return key.public_key().export_key(format="PEM").encode("ascii")


def load_key(data, curve, private=False):
    key = ECC.import_key(data)
    if key.curve != curve or key.has_private() != private:
        kind = "private" if private else "public"
        raise ValueError(f"Expected {curve} {kind} key")
    return key


def sign(key, message):
    return eddsa.new(key, "rfc8032").sign(message)


def verify(key, signature, message):
    eddsa.new(key, "rfc8032").verify(message, signature)


def public_raw(key):
    return key.public_key().export_key(format="raw")


def import_recipient(data):
    return import_x25519_public_key(data)


def derive(private, public, salt):
    if len(salt) != 32:
        raise ValueError("Expected 32-byte bundle salt")
    return key_agreement(
        static_priv=private,
        static_pub=public,
        kdf=lambda secret: HKDF(secret, 32, salt, SHA256, context=b"RSAT evidence bundle v1"),
    )


def encrypt(key, nonce, content, aad):
    if len(nonce) != 12:
        raise ValueError("Expected 12-byte bundle nonce")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(content)
    return ciphertext + tag


def decrypt(key, nonce, content, aad):
    if len(nonce) != 12 or len(content) < 16:
        raise ValueError("Invalid encrypted bundle nonce or authentication tag")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    return cipher.decrypt_and_verify(content[:-16], content[-16:])
