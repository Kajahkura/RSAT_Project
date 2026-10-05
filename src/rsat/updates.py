"""Optional maintained TUF client: pinned root, persistent rollback state, verified download."""

from pathlib import Path
import re
from urllib.parse import urlsplit


def fetch_update(root, metadata_url, target_url, target, directory):
    for value in (metadata_url, target_url):
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Update repositories require HTTPS without credentials")
    if not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", target):
        raise ValueError("Require a plain target filename")
    try:
        from tuf.ngclient import Updater
    except ImportError as exc:
        raise ValueError("Install rsat-audit[updates] for maintained TUF verification") from exc
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = directory / "metadata"
    downloads = directory / "targets"
    metadata.mkdir(mode=0o700, exist_ok=True)
    downloads.mkdir(mode=0o700, exist_ok=True)
    if not (metadata / "root.json").exists():
        from .storage import write_new

        write_new(metadata / "root.json", Path(root).read_bytes())
    updater = Updater(str(metadata), metadata_url, str(downloads), target_url, bootstrap=None)
    updater.refresh()
    info = updater.get_targetinfo(target)
    if info is None:
        raise ValueError("Target absent from verified repository")
    cached = updater.find_cached_target(info)
    path = cached or updater.download_target(info)
    return {
        "verified_target": str(path),
        "trust": "TUF repository rooted in independently pinned initial root",
        "installed": False,
    }
