"""Launch the packaged application, including its native crypto modules."""

import json
from pathlib import Path
import subprocess
import tempfile


def main():
    binaries = list(Path("dist").glob("RSAT_*"))
    assert len(binaries) == 1, binaries
    binary = str(binaries[0].resolve())
    with tempfile.TemporaryDirectory(prefix="rsat-binary-") as folder:
        root = Path(folder)

        def run(*args):
            return subprocess.run(
                [binary, *map(str, args)], cwd=root, check=True, capture_output=True, text=True, timeout=120
            ).stdout

        assert "RSAT 2." in run("--version")
        run("keygen", "keys")
        run(
            "audit",
            "--deadline",
            "30",
            "--command-timeout",
            "3",
            "--output",
            "audit-output",
            "--bundle",
            "--signing-key",
            "keys/signing.key.pem",
            "--recipient-key",
            "keys/recipient.pub.pem",
        )
        output = next((root / "audit-output").iterdir())
        audit = json.loads((output / "audit.json").read_bytes())
        assert audit["observations"] and audit["findings"]
        signed = output / "evidence.rsat.zip"
        verification = json.loads(run("verify", signed, "--trusted-key", "keys/signing.pub.pem"))
        assert verification["trusted_signer_verified"]
        run(
            "decrypt",
            output / "evidence.rsat.enc",
            "--output",
            "restored.zip",
            "--key",
            "keys/recipient.key.pem",
        )
        assert (root / "restored.zip").read_bytes() == signed.read_bytes()
        run("keygen", "wrong-keys")
        wrong = subprocess.run(
            [binary, "verify", str(signed), "--trusted-key", "wrong-keys/signing.pub.pem"],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert wrong.returncode != 0, "Packaged verifier accepted an untrusted signer"
    print(f"Standalone audit, signing, encryption, decryption and wrong-key smoke passed: {binaries[0].name}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        message = str(exc).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error::{type(exc).__name__}: {message}", flush=True)
        raise
