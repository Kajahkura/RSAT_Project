"""Tamper-evident local history with device-key identity and explicit retention."""

import hashlib
from pathlib import Path
import sqlite3
from contextlib import contextmanager

from .bundle import crypto, generate_keys
from .model import canonical, utcnow, validate_audit
from .storage import read_json, write_new


def device_init(directory):
    directory = generate_keys(directory)
    public = (directory / "signing.pub.pem").read_bytes()
    identity = {
        "schema_version": "1.0",
        "device_id": hashlib.sha256(public).hexdigest(),
        "created_at": utcnow(),
        "signing_public_key_sha256": hashlib.sha256(public).hexdigest(),
        "limitations": "Device key identity; not TPM attestation or hostname identity.",
    }
    write_new(directory / "device.json", canonical(identity))
    return identity


def signed_snapshot(audit, keys, sequence, previous_hash=""):
    validate_audit(audit)
    if type(sequence) is not int or sequence < 1 or sequence > 2**53 or not isinstance(previous_hash, str):
        raise ValueError("Invalid snapshot sequence/hash")
    public = (Path(keys) / "signing.pub.pem").read_bytes()
    key = crypto().load_key((Path(keys) / "signing.key.pem").read_bytes(), "Ed25519", private=True)
    payload = {
        "schema_version": "1.0",
        "device_id": hashlib.sha256(public).hexdigest(),
        "sequence": sequence,
        "previous_hash": previous_hash,
        "created_at": utcnow(),
        "audit_sha256": hashlib.sha256(canonical(audit)).hexdigest(),
        "audit": audit,
    }
    import base64

    return {
        "payload": payload,
        "signature": base64.b64encode(crypto().sign(key, canonical(payload))).decode(),
        "public_key": public.decode("ascii"),
    }


def verify_snapshot(snapshot, pinned_public_key):
    import base64

    if not isinstance(snapshot, dict) or set(snapshot) != {"payload", "signature", "public_key"}:
        raise ValueError("Invalid signed snapshot")
    public = pinned_public_key.encode() if isinstance(pinned_public_key, str) else pinned_public_key
    if snapshot["public_key"].encode() != public:
        raise ValueError("Snapshot signer does not match pinned device key")
    payload = snapshot["payload"]
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0":
        raise ValueError("Unsupported snapshot")
    validate_audit(payload.get("audit"))
    if payload.get("device_id") != hashlib.sha256(public).hexdigest():
        raise ValueError("Invalid device identity")
    if type(payload.get("sequence")) is not int or not 1 <= payload["sequence"] <= 2**53:
        raise ValueError("Invalid snapshot sequence")
    if payload.get("audit_sha256") != hashlib.sha256(canonical(payload["audit"])).hexdigest():
        raise ValueError("Snapshot audit hash mismatch")
    try:
        crypto().verify(
            crypto().load_key(public, "Ed25519"),
            base64.b64decode(snapshot["signature"], validate=True),
            canonical(payload),
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Snapshot signature verification failed") from exc
    return payload


@contextmanager
def database(path):
    path = Path(path)
    if not path.exists():
        write_new(path, b"")
    connection = sqlite3.connect(path, timeout=10)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute(
        "CREATE TABLE IF NOT EXISTS snapshots (device TEXT, sequence INTEGER, digest TEXT, payload TEXT, created TEXT, PRIMARY KEY(device, sequence))"
    )
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def append_snapshot(path, snapshot, pinned_public_key):
    payload = verify_snapshot(snapshot, pinned_public_key)
    digest = hashlib.sha256(canonical(snapshot)).hexdigest()
    with database(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT sequence, digest FROM snapshots WHERE device=? ORDER BY sequence DESC LIMIT 1",
            (payload["device_id"],),
        ).fetchone()
        expected_sequence, expected_previous = (row[0] + 1, row[1]) if row else (1, "")
        if payload["sequence"] != expected_sequence or payload["previous_hash"] != expected_previous:
            raise ValueError("Replay, gap or history-chain mismatch")
        connection.execute(
            "INSERT INTO snapshots VALUES (?,?,?,?,?)",
            (payload["device_id"], payload["sequence"], digest, canonical(snapshot).decode(), utcnow()),
        )
    return {"device_id": payload["device_id"], "sequence": payload["sequence"], "snapshot_sha256": digest}


def history_status(path, device_id):
    with database(path) as connection:
        rows = connection.execute(
            "SELECT sequence,digest,created FROM snapshots WHERE device=? ORDER BY sequence", (device_id,)
        ).fetchall()
    return {
        "device_id": device_id,
        "snapshots": [{"sequence": r[0], "sha256": r[1], "received_at": r[2]} for r in rows],
    }


def snapshot_from_file(audit_path, keys, store):
    audit = read_json(audit_path)
    device_id = read_json(Path(keys) / "device.json")["device_id"]
    status = history_status(store, device_id)["snapshots"]
    sequence, previous = (status[-1]["sequence"] + 1, status[-1]["sha256"]) if status else (1, "")
    snapshot = signed_snapshot(audit, keys, sequence, previous)
    append_snapshot(store, snapshot, (Path(keys) / "signing.pub.pem").read_bytes())
    return snapshot


def prune_history(path, device_id, keep_last):
    if type(keep_last) is not int or keep_last < 1:
        raise ValueError("Retention must keep at least the current chain anchor")
    with database(path) as connection:
        rows = connection.execute(
            "SELECT sequence FROM snapshots WHERE device=? ORDER BY sequence DESC", (device_id,)
        ).fetchall()
        if len(rows) > keep_last:
            connection.execute(
                "DELETE FROM snapshots WHERE device=? AND sequence<?", (device_id, rows[keep_last - 1][0])
            )
    return history_status(path, device_id)
