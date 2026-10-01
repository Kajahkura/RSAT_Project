"""Published primitive vectors and interoperability with the former bundle backend."""

import base64
import json
import zipfile

import pytest
from Cryptodome.Protocol.DH import import_x25519_private_key
from Cryptodome.PublicKey import ECC

from rsat import _crypto as c
from rsat.bundle import create_bundle, decrypt_bundle, encrypt_bundle, generate_keys
from rsat.model import canonical


def test_rfc8032_ed25519_empty_message():
    # RFC 8032 section 7.1, TEST 1.
    key = ECC.construct(
        curve="Ed25519",
        seed=bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
    )
    expected = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
        "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    assert c.public_raw(key).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert c.sign(key, b"") == expected
    c.verify(key.public_key(), expected, b"")
    with pytest.raises(ValueError):
        c.verify(key.public_key(), expected, b"changed")


def test_rfc7748_x25519_exchange():
    # RFC 7748 section 6.1, Alice/Bob exchange; compare RSAT KDF output too.
    alice = import_x25519_private_key(
        bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    )
    bob = c.import_recipient(
        bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    )
    from Cryptodome.Protocol.DH import key_agreement
    from Cryptodome.Protocol.KDF import HKDF
    from Cryptodome.Hash import SHA256

    expected = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    assert bytes(key_agreement(static_priv=alice, static_pub=bob, kdf=lambda secret: secret)) == expected
    assert c.derive(alice, bob, bytes(32)) == HKDF(
        expected, 32, bytes(32), SHA256, context=b"RSAT evidence bundle v1"
    )


def test_nist_aes256_gcm_vector():
    # NIST GCM example, 256-bit zero key, 96-bit zero IV, 128-bit zero plaintext.
    expected = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
    assert c.encrypt(bytes(32), bytes(12), bytes(16), b"") == expected
    assert c.decrypt(bytes(32), bytes(12), expected, b"") == bytes(16)


@pytest.mark.parametrize("curve", ["Ed25519", "Curve25519"])
def test_key_type_and_private_public_boundaries(curve):
    key = c.generate_key(curve)
    with pytest.raises(ValueError, match="Expected"):
        c.load_key(c.private_pem(key), curve)
    with pytest.raises(ValueError, match="Expected"):
        c.load_key(c.public_pem(key), curve, private=True)
    with pytest.raises(ValueError, match="Expected"):
        c.load_key(c.public_pem(key), "Curve25519" if curve == "Ed25519" else "Ed25519")


@pytest.mark.parametrize("public", [bytes(32), b"\x01" + bytes(31)])
def test_low_order_recipient_rejected(public):
    with pytest.raises(ValueError):
        c.derive(c.generate_key("Curve25519"), c.import_recipient(public), bytes(32))


@pytest.mark.parametrize("length", [0, 8, 16])
def test_nonstandard_nonce_rejected(length):
    with pytest.raises(ValueError, match="nonce"):
        c.encrypt(bytes(32), bytes(length), b"data", b"")
    with pytest.raises(ValueError, match="nonce"):
        c.decrypt(bytes(32), bytes(length), bytes(16), b"")


def test_former_backend_interoperability(tmp_path):
    pytest.importorskip("cryptography")  # Upstream no longer supports Intel macOS.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    keys = generate_keys(tmp_path / "keys")
    bundle = create_bundle({"audit.json": b"evidence"}, tmp_path / "audit.zip", keys / "signing.key.pem")
    with zipfile.ZipFile(bundle) as archive:
        public = serialization.load_pem_public_key(archive.read("signer.pub.pem"))
        assert isinstance(public, ed25519.Ed25519PublicKey)
        public.verify(archive.read("manifest.sig"), archive.read("manifest.json"))
    old_signer = ed25519.Ed25519PrivateKey.generate()
    imported = c.load_key(
        old_signer.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
        "Ed25519",
        private=True,
    )
    assert c.sign(imported, b"interop") == old_signer.sign(b"interop")

    encrypted = encrypt_bundle(bundle, tmp_path / "audit.enc", keys / "recipient.pub.pem")
    data = json.loads(encrypted.read_bytes())
    header = {k: v for k, v in data.items() if k != "ciphertext"}

    def decode(name):
        return base64.b64decode(data[name])

    old_private = serialization.load_pem_private_key((keys / "recipient.key.pem").read_bytes(), None)
    shared = old_private.exchange(x25519.X25519PublicKey.from_public_bytes(decode("ephemeral")))
    derived = HKDF(hashes.SHA256(), 32, decode("salt"), b"RSAT evidence bundle v1").derive(shared)
    assert (
        AESGCM(derived).decrypt(decode("nonce"), decode("ciphertext"), canonical(header))
        == bundle.read_bytes()
    )

    # A former-backend key and encrypted envelope must be accepted by the new backend.
    recipient = x25519.X25519PrivateKey.generate()
    ephemeral = x25519.X25519PrivateKey.generate()
    private_path = tmp_path / "old.key.pem"
    private_path.write_bytes(
        recipient.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    header["ephemeral"] = base64.b64encode(
        ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    derived = HKDF(hashes.SHA256(), 32, decode("salt"), b"RSAT evidence bundle v1").derive(
        ephemeral.exchange(recipient.public_key())
    )
    old_envelope = tmp_path / "old.enc"
    old_envelope.write_bytes(
        canonical(
            {
                **header,
                "ciphertext": base64.b64encode(
                    AESGCM(derived).encrypt(decode("nonce"), b"old evidence", canonical(header))
                ).decode(),
            }
        )
    )
    assert decrypt_bundle(old_envelope, tmp_path / "old.zip", private_path).read_bytes() == b"old evidence"
