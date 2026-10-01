"""Signed manifests and recipient encryption using standard cryptographic primitives."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import zipfile

from .model import canonical
from .storage import write_new

MAX_BUNDLE = 50_000_000


def crypto():
    try:
        from . import _crypto
    except ImportError as exc:
        raise ValueError("Cryptography support requires: pip install 'rsat-audit[crypto]'") from exc
    return _crypto


def generate_keys(directory):
    c = crypto()
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, curve in (("signing", "Ed25519"), ("recipient", "Curve25519")):
        key = c.generate_key(curve)
        write_new(directory / f"{name}.key.pem", c.private_pem(key))
        write_new(directory / f"{name}.pub.pem", c.public_pem(key), 0o644)
    return directory


def create_bundle(entries, path, signing_key=None):
    if not entries or any("/" in n or "\\" in n or n.startswith(".") for n in entries):
        raise ValueError("Bundle entries must be plain filenames")
    if sum(len(v) for v in entries.values()) > MAX_BUNDLE:
        raise ValueError("Bundle exceeds size limit")
    manifest = {
        "schema_version": "1.0",
        "hash_algorithm": "sha256",
        "files": {n: hashlib.sha256(v).hexdigest() for n, v in entries.items()},
    }
    manifest_bytes = canonical(manifest)
    extra = {"manifest.json": manifest_bytes}
    if signing_key:
        c = crypto()
        key = c.load_key(Path(signing_key).read_bytes(), "Ed25519", private=True)
        extra["manifest.sig"] = c.sign(key, manifest_bytes)
        extra["signer.pub.pem"] = c.public_pem(key)
    if set(entries) & set(extra):
        raise ValueError("Reserved bundle entry name")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in {**entries, **extra}.items():
            archive.writestr(name, content)
    return write_new(path, output.getvalue())


def verify_bundle(path, trusted_key=None):
    """An embedded key is descriptive; trust requires a separately pinned public key."""
    if Path(path).stat().st_size > MAX_BUNDLE:
        raise ValueError("Bundle exceeds size limit")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > 100 or sum(x.file_size for x in infos) > MAX_BUNDLE:
            raise ValueError("Unsafe bundle size")
        names = [i.filename for i in infos]
        if len(names) != len(set(names)) or any("/" in n or "\\" in n or n.startswith(".") for n in names):
            raise ValueError("Duplicate or unsafe bundle names")
        if "manifest.json" not in names:
            raise ValueError("Manifest missing")
        manifest_bytes = archive.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        if manifest.get("schema_version") != "1.0" or manifest.get("hash_algorithm") != "sha256":
            raise ValueError("Unsupported manifest")
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise ValueError("Invalid manifest files")
        allowed = set(files) | {"manifest.json", "manifest.sig", "signer.pub.pem"}
        if set(names) - allowed:
            raise ValueError("Unmanifested files")
        for name, digest in files.items():
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError("Bundle integrity verification failed")
        signed = "manifest.sig" in names
        if trusted_key and not signed:
            raise ValueError("A trusted signature was requested but the bundle is unsigned")
        if signed:
            c = crypto()
            if "signer.pub.pem" not in names:
                raise ValueError("Signer key missing")
            key_bytes = Path(trusted_key).read_bytes() if trusted_key else archive.read("signer.pub.pem")
            key = c.load_key(key_bytes, "Ed25519")
            try:
                c.verify(key, archive.read("manifest.sig"), manifest_bytes)
            except Exception as exc:
                raise ValueError("Signature verification failed") from exc
        return {
            "integrity_verified": True,
            "signed": signed,
            "trusted_signer_verified": bool(signed and trusted_key),
            "files": list(files),
        }


def encrypt_bundle(source, destination, recipient_key):
    c = crypto()
    content = Path(source).read_bytes()
    if len(content) > MAX_BUNDLE:
        raise ValueError("Bundle exceeds size limit")
    public = c.load_key(Path(recipient_key).read_bytes(), "Curve25519")
    ephemeral = c.generate_key("Curve25519")
    header = {
        "schema_version": "1.0",
        "algorithm": "X25519-HKDF-SHA256-AES256GCM",
        "ephemeral": base64.b64encode(c.public_raw(ephemeral)).decode(),
        "salt": base64.b64encode(os.urandom(32)).decode(),
        "nonce": base64.b64encode(os.urandom(12)).decode(),
    }
    aad = canonical(header)
    key = c.derive(ephemeral, public, base64.b64decode(header["salt"]))
    envelope = {
        **header,
        "ciphertext": base64.b64encode(
            c.encrypt(key, base64.b64decode(header["nonce"]), content, aad)
        ).decode(),
    }
    return write_new(destination, canonical(envelope))


def decrypt_bundle(source, destination, private_key):
    c = crypto()
    if Path(source).stat().st_size > MAX_BUNDLE * 2:
        raise ValueError("Encrypted bundle exceeds size limit")
    envelope = json.loads(Path(source).read_bytes())
    if envelope.get("schema_version") != "1.0" or envelope.get("algorithm") != "X25519-HKDF-SHA256-AES256GCM":
        raise ValueError("Unsupported encrypted bundle")
    private = c.load_key(Path(private_key).read_bytes(), "Curve25519", private=True)
    header = {k: v for k, v in envelope.items() if k != "ciphertext"}
    public = c.import_recipient(base64.b64decode(header["ephemeral"], validate=True))
    key = c.derive(private, public, base64.b64decode(header["salt"], validate=True))
    try:
        content = c.decrypt(
            key,
            base64.b64decode(header["nonce"], validate=True),
            base64.b64decode(envelope["ciphertext"], validate=True),
            canonical(header),
        )
    except Exception as exc:
        raise ValueError("Bundle decryption/authentication failed") from exc
    if len(content) > MAX_BUNDLE:
        raise ValueError("Decrypted bundle exceeds size limit")
    return write_new(destination, content)
