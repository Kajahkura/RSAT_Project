"""Optional existing-SSH transport and explicit second-host reachability probes."""

from datetime import datetime, timezone
import ipaddress
from pathlib import Path
import re
import shlex
import socket
import base64

from .model import validate_audit
from .runner import CommandRunner, parse_json


def remote_audit(target, binary="rsat", port=22, identity=None, runner=None):
    # Only run an already installed/verified RSAT command. No credentials or binaries are uploaded.
    if not re.fullmatch(r"[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+", target) or target.startswith("-"):
        raise ValueError("SSH target must be user@host without shell syntax")
    if not 1 <= port <= 65535:
        raise ValueError("Invalid SSH port")
    if not re.fullmatch(r"[A-Za-z0-9_./ -]+", binary) or binary.startswith("-"):
        raise ValueError("Invalid remote executable path")
    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-p",
        str(port),
    ]
    if identity:
        argv += ["-i", str(Path(identity).resolve(strict=True))]
    argv += [target, shlex.quote(binary) + " audit --stdout --deadline 45"]
    runner = runner or CommandRunner(timeout=55, deadline=60)
    return validate_audit(parse_json(runner.run(argv, timeout=55)))


def winrm_audit(host, binary, runner=None):
    """Windows-only HTTPS WinRM using the current authenticated identity; no stored passwords."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", host):
        raise ValueError("Invalid WinRM hostname")
    if not binary or "\0" in binary or len(binary) > 1024:
        raise ValueError("Invalid remote RSAT executable")
    encoded = base64.b64encode(binary.encode("utf-8")).decode("ascii")
    script = (
        "$binary=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));"
        "$options=New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 55000;"
        "Invoke-Command -ComputerName '" + host + "' -UseSSL -SessionOption $options "
        "-ScriptBlock {param($p) & $p audit --stdout --deadline 45} -ArgumentList $binary"
    )
    runner = runner or CommandRunner(timeout=60, deadline=65)
    return validate_audit(parse_json(runner.powershell(script)))


def probe(host, ports, timeout=1.0):
    if not 0 < timeout <= 10 or len(ports) > 100:
        raise ValueError("Probe requires at most 100 ports and a timeout in (0,10]")
    # Resolve once to fix the probe's destination and record all resolved addresses.
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    seen = set()
    results = []
    for family, socktype, protocol, _, sockaddr in addresses:
        address = sockaddr[0]
        if address in seen:
            continue
        seen.add(address)
        ipaddress.ip_address(address.split("%")[0])
        for port in ports:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError("Invalid probe port")
            destination = (address, port, *sockaddr[2:]) if family == socket.AF_INET6 else (address, port)
            with socket.socket(family, socktype, protocol) as connection:
                connection.settimeout(timeout)
                try:
                    code = connection.connect_ex(destination)
                    reachable = code == 0
                    error = None if reachable else f"connect result {code}"
                except OSError as exc:
                    reachable, error = False, type(exc).__name__
            results.append(
                {
                    "host": host,
                    "address": address,
                    "port": port,
                    "reachable": reachable,
                    "error": error,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                    "probe_host": socket.gethostname(),
                    "protocol": "tcp",
                    "scope": "Reachability from this probe host only; no vulnerability test performed",
                }
            )
    return results
