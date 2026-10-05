"""Original AI-tool controls using explicit config metadata, never credential values."""

from dataclasses import asdict
import hashlib
import ipaddress
from pathlib import Path
import urllib.parse

from .model import Finding, Observation
from .storage import read_json

MODEL_PORTS = {
    11434: "Ollama",
    8000: "Model/API service (unconfirmed)",
    1234: "LM Studio",
    8080: "Model/API service (unconfirmed)",
}


def public_listener(address):
    try:
        return not ipaddress.ip_address(str(address).split("%")[0]).is_loopback
    except ValueError:
        return False


def collect_ai_metadata(configs, listeners):
    """Parse only caller-selected MCP configs and retain reviewed structural fields."""
    services = []
    for listener in listeners if isinstance(listeners, list) else []:
        if not isinstance(listener, dict):
            continue
        port = listener.get("port")
        process = str(listener.get("process", "")).lower()
        if port in MODEL_PORTS and (
            port in {11434, 1234} or any(name in process for name in ["ollama", "vllm", "llama", "lm studio"])
        ):
            services.append(
                {
                    "port": port,
                    "address": listener.get("address"),
                    "product": MODEL_PORTS[port],
                    "non_loopback": public_listener(listener.get("address")),
                    "authentication": "not assessed",
                    "external_reachability": "not verified",
                }
            )
    observations = [asdict(Observation("ai.services", services, source="network.listeners metadata"))]
    for index, path in enumerate(configs):
        path = Path(path)
        try:
            data = read_json(path, limit=1_000_000)
            servers = data.get("mcpServers", data.get("servers"))
            if not isinstance(servers, dict) or len(servers) > 100:
                raise ValueError("Expected at most 100 MCP server entries")
            metadata = []
            for name, config in servers.items():
                if not isinstance(config, dict) or not isinstance(name, str):
                    raise ValueError("Invalid MCP configuration")
                url = config.get("url", "")
                parsed = urllib.parse.urlparse(url) if isinstance(url, str) else urllib.parse.urlparse("")
                environment = config.get("env", {})
                permissions = config.get("permissions", {})
                if not isinstance(environment, dict) or not isinstance(permissions, dict):
                    raise ValueError("Invalid MCP permissions/environment")
                if any(not isinstance(k, str) for k in environment):
                    raise ValueError("Invalid environment key")
                scopes = permissions.get("filesystem", [])
                if not isinstance(scopes, list) or any(not isinstance(x, str) for x in scopes):
                    raise ValueError("Invalid filesystem scope declaration")
                # Neither arguments, endpoint queries, credential values, nor raw names enter evidence.
                metadata.append(
                    {
                        "server_id": hashlib.sha256(name.encode()).hexdigest()[:16],
                        "transport": config.get("type")
                        if config.get("type") in {"stdio", "sse", "http"}
                        else "unknown",
                        "url_scheme": parsed.scheme,
                        "url_host_present": bool(parsed.hostname),
                        "url_has_credentials": bool(parsed.username or parsed.password),
                        "credential_environment_count": sum(
                            any(t in k.upper() for t in ["TOKEN", "KEY", "SECRET", "PASSWORD"])
                            for k in environment
                        ),
                        "filesystem_scope_count": len(scopes),
                        "broad_filesystem_scope": any(
                            x in {"/", "*", "**", "~", "C:\\", "C:/"} for x in scopes
                        ),
                        "write_declared": permissions.get("write") is True,
                        "provenance_sha256_present": isinstance(config.get("sha256"), str)
                        and len(config["sha256"]) == 64
                        and all(c in "0123456789abcdef" for c in config["sha256"]),
                        "permissions_declared": bool(permissions),
                        "disabled": config.get("disabled") is True,
                    }
                )
            observations.append(
                asdict(Observation(f"ai.mcp.{index}", metadata, source="explicit MCP configuration metadata"))
            )
        except (OSError, ValueError, TypeError, AttributeError):
            observations.append(
                asdict(
                    Observation(
                        f"ai.mcp.{index}",
                        state="UNKNOWN",
                        reason="MCP config unavailable or invalid",
                        source="explicit MCP configuration",
                    )
                )
            )
    return observations


def evaluate_ai(observations):
    facts = {o["id"]: o for o in observations}
    findings = []

    def add(ident, title, status, severity, ids, details, remediation):
        findings.append(asdict(Finding(ident, title, status, severity, ids, details, remediation, "1.0.0")))

    services = facts.get("ai.services", {}).get("value", [])
    add(
        "RSAT-AI-001",
        "Model-serving listeners remain on loopback",
        "FAIL" if any(x.get("non_loopback") for x in services) else "PASS" if services else "UNKNOWN",
        "high",
        ["ai.services"],
        "A non-loopback AI listener requires access-boundary review; authentication and external reachability are not established."
        if any(x.get("non_loopback") for x in services)
        else "No non-loopback model listener observed in the collected listener inventory."
        if services
        else "No identified model listener; service identity or collection coverage may be incomplete.",
        "Bind local model services to loopback or apply reviewed authenticated network access and independently verify reachability.",
    )
    configs = [o for o in observations if o["id"].startswith("ai.mcp.")]
    entries = [entry for o in configs if o["state"] == "OK" for entry in o["value"] if not entry["disabled"]]
    checks = [
        (
            "002",
            "MCP remote transport uses HTTPS without embedded credentials",
            lambda x: x["url_has_credentials"] or (x["url_host_present"] and x["url_scheme"] != "https"),
            "high",
            "Use authenticated HTTPS and OS-backed credential references; remove credentials from URLs.",
        ),
        (
            "003",
            "MCP filesystem write scopes are constrained",
            lambda x: x["broad_filesystem_scope"] and x["write_declared"],
            "high",
            "Replace root/global write scopes with the smallest required directories and permissions.",
        ),
        (
            "004",
            "MCP plugin provenance is declared",
            lambda x: not x["provenance_sha256_present"],
            "medium",
            "Record and independently verify pinned plugin artifact provenance. A hash declaration alone does not verify trust.",
        ),
        (
            "005",
            "MCP permissions are explicitly declared",
            lambda x: not x["permissions_declared"],
            "medium",
            "Document and enforce least-privilege tool, filesystem and outbound capabilities in the actual runtime.",
        ),
    ]
    for suffix, title, failed, severity, remediation in checks:
        state = (
            "UNKNOWN"
            if not entries or any(o["state"] != "OK" for o in configs)
            else "FAIL"
            if any(failed(x) for x in entries)
            else "UNKNOWN"
            if suffix == "003" and any(not x["permissions_declared"] for x in entries)
            else "PASS"
        )
        add(
            "RSAT-AI-" + suffix,
            title,
            state,
            severity,
            [o["id"] for o in configs],
            "Assessment of explicitly supplied configuration declarations; runtime enforcement and plugin trust require independent verification.",
            remediation,
        )
    return findings
