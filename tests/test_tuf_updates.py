from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
from rsat.updates import fetch_update


def test_tuf_rejects_tampered_and_expired_targets(tmp_path):
    pytest.importorskip("tuf")
    from tuf.api.metadata import Metadata, Root, Targets, Snapshot, Timestamp, MetaFile, TargetFile
    from securesystemslib.signer import CryptoSigner
    from tuf.ngclient.fetcher import FetcherInterface
    from tuf.ngclient import Updater
    from tuf.api.exceptions import RepositoryError
    from unittest.mock import patch

    expires = datetime.now(timezone.utc) + timedelta(days=1)
    signers = {role: CryptoSigner.generate_ed25519() for role in ["root", "targets", "snapshot", "timestamp"]}
    root = Root(expires=expires, consistent_snapshot=False)
    for role, signer in signers.items():
        root.add_key(signer.public_key, role)
    rootmd = Metadata(root)
    rootmd.sign(signers["root"])
    pinned = tmp_path / "root.json"
    pinned.write_bytes(rootmd.to_bytes())
    target = b"verified synthetic collector"
    targets = Metadata(
        Targets(expires=expires, targets={"collector": TargetFile.from_data("collector", target)})
    )
    targets.sign(signers["targets"])
    snapshot = Metadata(
        Snapshot(
            expires=expires, meta={"targets.json": MetaFile.from_data(1, targets.to_bytes(), ["sha256"])}
        )
    )
    snapshot.sign(signers["snapshot"])
    timestamp = Metadata(
        Timestamp(expires=expires, snapshot_meta=MetaFile.from_data(1, snapshot.to_bytes(), ["sha256"]))
    )
    timestamp.sign(signers["timestamp"])
    files = {
        "timestamp.json": timestamp.to_bytes(),
        "snapshot.json": snapshot.to_bytes(),
        "targets.json": targets.to_bytes(),
        "collector": target,
    }

    class Fetcher(FetcherInterface):
        def _fetch(self, url):
            from tuf.api.exceptions import DownloadHTTPError

            name = url.rsplit("/", 1)[-1]
            if name not in files:
                raise DownloadHTTPError("missing", 404)
            yield files[name]

    def updater(*args, **kwargs):
        return Updater(*args, fetcher=Fetcher(), bootstrap=None)

    with patch("tuf.ngclient.Updater", side_effect=updater):
        result = fetch_update(
            pinned,
            "https://example.org/meta/",
            "https://example.org/targets/",
            "collector",
            tmp_path / "cache",
        )
        assert Path(result["verified_target"]).read_bytes() == target and not result["installed"]
        from tuf.api.exceptions import BadVersionNumberError

        newer = Metadata(
            Timestamp(
                version=2,
                expires=expires,
                snapshot_meta=MetaFile.from_data(1, snapshot.to_bytes(), ["sha256"]),
            )
        )
        newer.sign(signers["timestamp"])
        files["timestamp.json"] = newer.to_bytes()
        fetch_update(
            pinned,
            "https://example.org/meta/",
            "https://example.org/targets/",
            "collector",
            tmp_path / "cache",
        )
        files["timestamp.json"] = timestamp.to_bytes()
        with pytest.raises(BadVersionNumberError):
            fetch_update(
                pinned,
                "https://example.org/meta/",
                "https://example.org/targets/",
                "collector",
                tmp_path / "cache",
            )
        files["collector"] = b"tampered"
        with pytest.raises(Exception):
            fetch_update(
                pinned,
                "https://example.org/meta/",
                "https://example.org/targets/",
                "collector",
                tmp_path / "other-cache",
            )
        files["collector"] = target
        expired = Metadata(
            Timestamp(
                expires=datetime.now(timezone.utc) - timedelta(days=1),
                snapshot_meta=MetaFile.from_data(1, snapshot.to_bytes(), ["sha256"]),
            )
        )
        expired.sign(signers["timestamp"])
        files["timestamp.json"] = expired.to_bytes()
        with pytest.raises(RepositoryError):
            fetch_update(
                pinned,
                "https://example.org/meta/",
                "https://example.org/targets/",
                "collector",
                tmp_path / "expired-cache",
            )


@pytest.mark.parametrize("target", ["../escape", "/root/collector", "script;evil"])
def test_update_paths_are_constrained(tmp_path, target):
    with pytest.raises(ValueError):
        fetch_update(
            tmp_path / "root.json",
            "https://example.org/meta/",
            "https://example.org/targets/",
            target,
            tmp_path / "cache",
        )
