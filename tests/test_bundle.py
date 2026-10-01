import json
import zipfile
import pytest

from rsat.bundle import create_bundle, decrypt_bundle, encrypt_bundle, generate_keys, verify_bundle


@pytest.fixture
def keys(tmp_path):
    return generate_keys(tmp_path / "keys")


def test_unsigned_integrity(tmp_path):
    bundle = create_bundle({"audit.json": b'{"test":true}'}, tmp_path / "audit.zip")
    result = verify_bundle(bundle)
    assert result["integrity_verified"] and not result["trusted_signer_verified"]


def test_trusted_signature_and_wrong_key(tmp_path, keys):
    bundle = create_bundle({"audit.json": b"{}"}, tmp_path / "audit.zip", keys / "signing.key.pem")
    assert verify_bundle(bundle, keys / "signing.pub.pem")["trusted_signer_verified"]
    assert not verify_bundle(bundle)["trusted_signer_verified"]
    other = generate_keys(tmp_path / "other")
    with pytest.raises(ValueError, match="Signature"):
        verify_bundle(bundle, other / "signing.pub.pem")


def test_unsigned_cannot_satisfy_trusted_verification(tmp_path, keys):
    bundle = create_bundle({"audit.json": b"{}"}, tmp_path / "audit.zip")
    with pytest.raises(ValueError, match="unsigned"):
        verify_bundle(bundle, keys / "signing.pub.pem")


def test_tampering_detected(tmp_path):
    bundle = create_bundle({"audit.json": b"{}"}, tmp_path / "audit.zip")
    with zipfile.ZipFile(bundle) as src:
        manifest = src.read("manifest.json")
    with zipfile.ZipFile(tmp_path / "tampered.zip", "w") as dst:
        dst.writestr("manifest.json", manifest)
        dst.writestr("audit.json", b"changed")
    with pytest.raises(ValueError, match="integrity"):
        verify_bundle(tmp_path / "tampered.zip")


@pytest.mark.parametrize("name", ["../escape", "dir/file", "dir\\file", ".hidden"])
def test_path_traversal_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        create_bundle({name: b"{}"}, tmp_path / "audit.zip")


def test_unmanifested_file_rejected(tmp_path):
    bundle = create_bundle({"audit.json": b"{}"}, tmp_path / "audit.zip")
    with zipfile.ZipFile(bundle, "a") as archive:
        archive.writestr("unlisted.txt", "test")
    with pytest.raises(ValueError, match="Unmanifested"):
        verify_bundle(bundle)


def test_encryption_roundtrip_and_wrong_recipient(tmp_path, keys):
    bundle = create_bundle(
        {"audit.json": b"private endpoint data"}, tmp_path / "audit.zip", keys / "signing.key.pem"
    )
    envelope = encrypt_bundle(bundle, tmp_path / "audit.enc", keys / "recipient.pub.pem")
    assert b"private endpoint data" not in envelope.read_bytes()
    restored = decrypt_bundle(envelope, tmp_path / "restored.zip", keys / "recipient.key.pem")
    assert restored.read_bytes() == bundle.read_bytes()
    assert verify_bundle(restored, keys / "signing.pub.pem")["trusted_signer_verified"]
    other = generate_keys(tmp_path / "other")
    with pytest.raises(ValueError, match="authentication"):
        decrypt_bundle(envelope, tmp_path / "wrong.zip", other / "recipient.key.pem")


def test_encryption_header_tampering_rejected(tmp_path, keys):
    source = tmp_path / "source"
    source.write_bytes(b"secret")
    envelope = encrypt_bundle(source, tmp_path / "source.enc", keys / "recipient.pub.pem")
    data = json.loads(envelope.read_bytes())
    data["extra"] = "tampered header"
    envelope.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="authentication"):
        decrypt_bundle(envelope, tmp_path / "out", keys / "recipient.key.pem")


def test_existing_output_not_overwritten(tmp_path):
    path = tmp_path / "audit.zip"
    path.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        create_bundle({"audit.json": b"{}"}, path)
    assert path.read_bytes() == b"existing"
