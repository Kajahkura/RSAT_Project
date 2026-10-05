"""Optional self-hosted workspace: hashed scoped tokens and challenge-bound device enrollment."""

import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager

from .bundle import crypto
from .history import verify_snapshot
from .model import canonical
from .storage import write_new

SCOPES = {"enroll", "upload", "read", "revoke"}


@contextmanager
def database(path):
    path = Path(path)
    if not path.exists():
        write_new(path, b"")
    connection = sqlite3.connect(path, timeout=10)
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript("""
      CREATE TABLE IF NOT EXISTS tokens (digest TEXT PRIMARY KEY, tenant TEXT, scopes TEXT, expires REAL);
      CREATE TABLE IF NOT EXISTS challenges (nonce TEXT PRIMARY KEY, tenant TEXT, public TEXT, expires REAL, used INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS devices (tenant TEXT, device TEXT, public TEXT, revoked INTEGER DEFAULT 0, sequence INTEGER DEFAULT 0, digest TEXT DEFAULT '', PRIMARY KEY(tenant,device));
      CREATE TABLE IF NOT EXISTS uploads (tenant TEXT, device TEXT, sequence INTEGER, snapshot TEXT, PRIMARY KEY(tenant,device,sequence));
    """)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def issue_token(path, tenant, scopes, lifetime=3600):
    if not isinstance(tenant, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", tenant):
        raise ValueError("Invalid tenant identifier")
    if not isinstance(scopes, list) or not scopes or set(scopes) - SCOPES or not 60 <= lifetime <= 86400:
        raise ValueError("Invalid token scopes/lifetime")
    token = secrets.token_urlsafe(32)
    with database(path) as db:
        db.execute(
            "INSERT INTO tokens VALUES (?,?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), tenant, json.dumps(scopes), time.time() + lifetime),
        )
    return {"token": token, "tenant": tenant, "scopes": scopes, "expires_in": lifetime}


def authorize(db, token, scope):
    if not isinstance(token, str) or len(token) > 256:
        raise ValueError("Invalid access token")
    row = db.execute(
        "SELECT tenant,scopes,expires FROM tokens WHERE digest=?",
        (hashlib.sha256(token.encode()).hexdigest(),),
    ).fetchone()
    if not row or row[2] <= time.time() or scope not in json.loads(row[1]):
        raise ValueError("Expired token or insufficient scope")
    return row[0]


def operation(path, token, action, data):
    scopes = {
        "challenge": "enroll",
        "enroll": "enroll",
        "upload": "upload",
        "history": "read",
        "revoke": "revoke",
    }
    if action not in scopes or not isinstance(data, dict):
        raise ValueError("Unknown workspace capability")
    with database(path) as db:
        db.execute("BEGIN IMMEDIATE")
        tenant = authorize(db, token, scopes[action])
        if action == "challenge":
            public = data.get("public_key")
            if not isinstance(public, str) or len(public) > 1000:
                raise ValueError("Invalid enrollment key")
            crypto().load_key(public.encode(), "Ed25519")
            challenge = {
                "purpose": "rsat-device-enrollment-v1",
                "tenant": tenant,
                "nonce": secrets.token_urlsafe(32),
                "device_id": hashlib.sha256(public.encode()).hexdigest(),
                "expires_at": int(time.time()) + 300,
            }
            db.execute(
                "INSERT INTO challenges(nonce,tenant,public,expires) VALUES (?,?,?,?)",
                (challenge["nonce"], tenant, public, challenge["expires_at"]),
            )
            return challenge
        if action == "enroll":
            challenge = data.get("challenge")
            if not isinstance(challenge, dict) or set(challenge) != {
                "purpose",
                "tenant",
                "nonce",
                "device_id",
                "expires_at",
            }:
                raise ValueError("Invalid enrollment challenge")
            row = db.execute(
                "SELECT public,expires,used FROM challenges WHERE nonce=? AND tenant=?",
                (challenge["nonce"], tenant),
            ).fetchone()
            if not row or row[2] or row[1] <= time.time():
                raise ValueError("Expired, replayed or foreign enrollment")
            expected = {
                "purpose": "rsat-device-enrollment-v1",
                "tenant": tenant,
                "nonce": challenge["nonce"],
                "device_id": hashlib.sha256(row[0].encode()).hexdigest(),
                "expires_at": int(row[1]),
            }
            if challenge != expected:
                raise ValueError("Enrollment challenge binding mismatch")
            crypto().verify(
                crypto().load_key(row[0].encode(), "Ed25519"),
                base64.b64decode(data["signature"], validate=True),
                canonical(challenge),
            )
            if db.execute(
                "SELECT 1 FROM devices WHERE tenant=? AND device=?", (tenant, expected["device_id"])
            ).fetchone():
                raise ValueError("Device already enrolled; revoked identities require a new key")
            db.execute(
                "INSERT INTO devices(tenant,device,public) VALUES (?,?,?)",
                (tenant, expected["device_id"], row[0]),
            )
            db.execute("UPDATE challenges SET used=1 WHERE nonce=?", (challenge["nonce"],))
            return {"device_id": expected["device_id"], "enrolled": True}
        device = data.get("device_id")
        row = db.execute(
            "SELECT public,revoked,sequence,digest FROM devices WHERE tenant=? AND device=?", (tenant, device)
        ).fetchone()
        if not row or row[1]:
            raise ValueError("Device unavailable in this tenant")
        if action == "upload":
            snapshot = data.get("snapshot")
            payload = verify_snapshot(snapshot, row[0])
            if (
                payload["device_id"] != device
                or payload["sequence"] != row[2] + 1
                or not hmac.compare_digest(payload["previous_hash"], row[3])
            ):
                raise ValueError("Replay, sequence gap or device-chain mismatch")
            digest = hashlib.sha256(canonical(snapshot)).hexdigest()
            db.execute(
                "INSERT INTO uploads VALUES (?,?,?,?)",
                (tenant, device, payload["sequence"], canonical(snapshot).decode()),
            )
            db.execute(
                "UPDATE devices SET sequence=?,digest=? WHERE tenant=? AND device=?",
                (payload["sequence"], digest, tenant, device),
            )
            return {"sequence": payload["sequence"], "sha256": digest}
        if action == "revoke":
            db.execute("UPDATE devices SET revoked=1 WHERE tenant=? AND device=?", (tenant, device))
            return {"revoked": True}
        return {
            "device_id": device,
            "sequence": row[2],
            "sha256": row[3],
            "snapshots": [
                json.loads(r[0])
                for r in db.execute(
                    "SELECT snapshot FROM uploads WHERE tenant=? AND device=? ORDER BY sequence DESC LIMIT 100",
                    (tenant, device),
                )
            ],
        }


def enrollment_proof(challenge, private_key):
    key = crypto().load_key(Path(private_key).read_bytes(), "Ed25519", private=True)
    return {
        "challenge": challenge,
        "signature": base64.b64encode(crypto().sign(key, canonical(challenge))).decode(),
    }
