"""Detect collection boundaries without treating guest evidence as host evidence."""

import os
from pathlib import Path
import platform


def environment_context(system=None, release=None, environ=None, container_marker=None):
    system = system or platform.system()
    release = release if release is not None else platform.release()
    environ = os.environ if environ is None else environ
    if container_marker is None:
        container_marker = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists()
    wsl = system == "Linux" and ("microsoft" in release.lower() or bool(environ.get("WSL_INTEROP")))
    kind = "wsl" if wsl else "container" if system == "Linux" and container_marker else "native"
    return {
        "kind": kind,
        "system": system,
        "host_controls_assessed": kind == "native",
        "scope": "WSL guest only; Windows host controls require a native Windows assessment"
        if wsl
        else "Container namespace only; host controls require a separate host assessment"
        if kind == "container"
        else "Local operating system; no external reachability verified",
        "limitations": "Environment detection is contextual metadata, not hardware attestation.",
    }
