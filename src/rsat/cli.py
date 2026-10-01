"""Explicit command-line workflows; audit collection never applies fixes."""

import argparse
import json
from pathlib import Path
import sys

from . import __version__
from .analysis import analyze, diff_audits
from .bundle import create_bundle, decrypt_bundle, encrypt_bundle, generate_keys, verify_bundle
from .collectors import Collector, osquery_observations
from .exports import local_summary, oscal
from .intelligence import load_pack, match_inventory, query_osv, refresh_enrichment
from .model import Observation, canonical, new_audit, utcnow, validate_audit
from .policy import apply_exceptions, coverage, evaluate, load_policy
from .remediation import apply_action, plan, rollback
from .report import dashboard, render
from .runner import CommandRunner
from .storage import read_json, write_new
from .transport import probe, remote_audit, winrm_audit


def parser():
    p = argparse.ArgumentParser(prog="rsat", description="Portable, evidence-based endpoint auditing")
    p.add_argument("--version", action="version", version=f"RSAT {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    a = sub.add_parser("audit", help="Read-only local endpoint assessment")
    a.add_argument("--output", type=Path, default=Path("audit-output"))
    a.add_argument("--stdout", action="store_true", help="Emit JSON only; do not write output")
    a.add_argument("--policy", type=Path)
    a.add_argument("--policy-bundle", type=Path, help="Verify a signed policy bundle before using --policy")
    a.add_argument("--policy-key", type=Path, help="Pinned publisher public key")
    a.add_argument("--exceptions", type=Path)
    a.add_argument("--inventory", action="store_true")
    a.add_argument("--update-search", action="store_true", help="Opt into bounded live vendor update search")
    a.add_argument("--deadline", type=float, default=60)
    a.add_argument("--command-timeout", type=float, default=10)
    a.add_argument("--asset-salt-file", type=Path, help="Engagement secret for pseudonymous asset matching")
    a.add_argument("--include-hostname", action="store_true")
    a.add_argument("--intel-pack", type=Path)
    a.add_argument("--intel-bundle", type=Path, help="Signed bundle containing the chosen intelligence pack")
    a.add_argument("--intel-key", type=Path, help="Pinned intelligence publisher public key")
    a.add_argument("--enrichment", type=Path, help="Import separately refreshed KEV/EPSS metadata")
    a.add_argument("--online-osv", action="store_true", help="Send inventory package metadata to OSV")
    a.add_argument("--reachability", type=Path, help="Import a separate-host probe JSON file")
    a.add_argument("--osquery", type=Path, help="Explicit trusted osqueryi binary")
    a.add_argument("--signing-key", type=Path)
    a.add_argument("--recipient-key", type=Path, help="Encrypt bundle; requires --bundle")
    a.add_argument("--bundle", action="store_true")
    a.add_argument("--oscal", action="store_true")
    a.add_argument("--fail-on-findings", action="store_true")
    r = sub.add_parser("report", help="Render saved audit JSON")
    r.add_argument("audit", type=Path)
    r.add_argument("--output", type=Path, required=True)
    d = sub.add_parser("diff", help="Compare audits of the same asset")
    d.add_argument("before", type=Path)
    d.add_argument("after", type=Path)
    d.add_argument("--output", type=Path)
    v = sub.add_parser("verify", help="Verify evidence or policy bundle integrity/signature")
    v.add_argument("bundle", type=Path)
    v.add_argument("--trusted-key", type=Path)
    k = sub.add_parser("keygen", help="Generate Ed25519 signing and X25519 recipient keys")
    k.add_argument("directory", type=Path)
    for name in ("encrypt", "decrypt"):
        c = sub.add_parser(name, help=f"{name.capitalize()} an evidence bundle")
        c.add_argument("source", type=Path)
        c.add_argument("--output", type=Path, required=True)
        c.add_argument("--key", type=Path, required=True)
    b = sub.add_parser("bundle", help="Package an audit or a declarative policy")
    b.add_argument("source", type=Path)
    b.add_argument("--policy", action="store_true")
    b.add_argument("--intelligence", action="store_true")
    b.add_argument("--output", type=Path, required=True)
    b.add_argument("--signing-key", type=Path)
    i = sub.add_parser("intel-refresh", help="Download KEV/EPSS metadata for specified CVEs")
    i.add_argument("cves", nargs="+")
    i.add_argument("--output", type=Path, required=True)
    w = sub.add_parser("workspace", help="Generate a local HTML overview of imported audits")
    w.add_argument("audits", type=Path, nargs="+")
    w.add_argument("--output", type=Path, required=True)
    s = sub.add_parser("serve", help="Serve one generated HTML report on loopback")
    s.add_argument("report", type=Path)
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--duration", type=float, default=300)
    t = sub.add_parser("remote", help="Audit through existing SSH access; RSAT must exist on target")
    t.add_argument("target")
    t.add_argument("--binary", default="rsat")
    t.add_argument("--port", type=int, default=22)
    t.add_argument("--identity", type=Path)
    t.add_argument("--output", type=Path, required=True)
    t = sub.add_parser(
        "winrm", help="HTTPS WinRM using current Windows credentials; RSAT must exist on target"
    )
    t.add_argument("host")
    t.add_argument("--binary", required=True)
    t.add_argument("--output", type=Path, required=True)
    n = sub.add_parser("probe", help="Explicit TCP reachability probe from this host")
    n.add_argument("host")
    n.add_argument("--ports", type=int, nargs="+", required=True)
    n.add_argument("--timeout", type=float, default=1)
    n.add_argument("--output", type=Path, required=True)
    f = sub.add_parser("plan", help="Generate remediation instructions and allowlisted actions")
    f.add_argument("audit", type=Path)
    f.add_argument("--output", type=Path, required=True)
    f = sub.add_parser("apply", help="Dry-run or explicitly execute an allowlisted remediation")
    f.add_argument("plan", type=Path)
    f.add_argument("action")
    f.add_argument("--backup", type=Path, required=True)
    f.add_argument("--execute", action="store_true")
    f.add_argument("--recovery-access", action="store_true")
    f = sub.add_parser("rollback", help="Dry-run or restore a saved allowlisted setting")
    f.add_argument("backup", type=Path)
    f.add_argument("--execute", action="store_true")
    f.add_argument("--recovery-access", action="store_true")
    g = sub.add_parser("summary", help="Generate optional cited client prose using a local model")
    g.add_argument("audit", type=Path)
    g.add_argument("--model", required=True)
    g.add_argument("--endpoint", default="http://127.0.0.1:11434/api/generate")
    g.add_argument("--output", type=Path, required=True)
    o = sub.add_parser("oscal", help="Export an OSCAL assessment plan/results pair")
    o.add_argument("audit", type=Path)
    o.add_argument("--output", type=Path, required=True)
    return p


def load_audit(path):
    return validate_audit(read_json(path))


def emit(data, output=None):
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    if output:
        write_new(output, text)
    else:
        print(text, end="")


def run_audit(args):
    if not 0 < args.deadline <= 600 or not 0 < args.command_timeout <= args.deadline:
        raise ValueError("Require 0 < command-timeout <= deadline <= 600 seconds")
    if args.stdout and (args.bundle or args.signing_key or args.recipient_key or args.oscal):
        raise ValueError("Bundle/signing/encryption/OSCAL output cannot be combined with --stdout")
    if args.recipient_key and not args.bundle:
        raise ValueError("--recipient-key requires --bundle")
    if bool(args.policy_bundle) != bool(args.policy_key) or (args.policy_bundle and not args.policy):
        raise ValueError("Signed policy use requires --policy, --policy-bundle, and --policy-key together")
    if bool(args.intel_bundle) != bool(args.intel_key) or (args.intel_bundle and not args.intel_pack):
        raise ValueError(
            "Signed intelligence use requires --intel-pack, --intel-bundle, and --intel-key together"
        )
    if args.intel_bundle:
        verification = verify_bundle(args.intel_bundle, args.intel_key)
        import zipfile

        with zipfile.ZipFile(args.intel_bundle) as archive:
            if (
                "intelligence.json" not in verification["files"]
                or archive.read("intelligence.json") != args.intel_pack.read_bytes()
            ):
                raise ValueError("Intelligence pack does not match the pinned signed bundle")
    if args.policy_bundle:
        verification = verify_bundle(args.policy_bundle, args.policy_key)
        import zipfile

        with zipfile.ZipFile(args.policy_bundle) as archive:
            if (
                "policy.json" not in verification["files"]
                or archive.read("policy.json") != args.policy.read_bytes()
            ):
                raise ValueError("Policy does not match trusted signed bundle")
    policy = load_policy(args.policy)
    salt = args.asset_salt_file.read_text().strip() if args.asset_salt_file else ""
    if args.asset_salt_file and len(salt) < 16:
        raise ValueError("Engagement salt must contain at least 16 characters")
    audit = new_audit(salt, args.include_hostname)
    audit["policy"] = {
        "id": policy.get("id", "custom"),
        "version": policy["version"],
        "trust": "pinned signed bundle"
        if args.policy_bundle
        else "local custom"
        if args.policy
        else "bundled original rules",
    }
    runner = CommandRunner(args.command_timeout, args.deadline)
    audit["observations"] = Collector(
        runner,
        inventory=args.inventory or bool(args.intel_pack) or args.online_osv,
        update_search=args.update_search,
    ).collect()
    if args.osquery:
        audit["observations"].extend(osquery_observations(args.osquery, runner))
    if args.reachability:
        from dataclasses import asdict

        values = read_json(args.reachability)
        if not isinstance(values, list) or any(
            not isinstance(x, dict)
            or not isinstance(x.get("port"), int)
            or not isinstance(x.get("reachable"), bool)
            for x in values
        ):
            raise ValueError("Invalid probe evidence")
        audit["observations"].append(
            asdict(Observation("network.reachability", values, source="imported explicit probe"))
        )
    inventory = next(
        (o["value"] for o in audit["observations"] if o["id"] == "software.inventory" and o["state"] == "OK"),
        [],
    )
    if not isinstance(inventory, list):
        inventory = [inventory]
    if args.intel_pack:
        pack, metadata = load_pack(args.intel_pack)
        metadata["publisher_verified"] = bool(args.intel_bundle)
        audit["intelligence"] = metadata
        audit["vulnerabilities"] = match_inventory(inventory, pack)
    if args.enrichment:
        from .intelligence import enrich

        audit["vulnerabilities"], audit["enrichment"] = enrich(
            audit["vulnerabilities"], read_json(args.enrichment)
        )
    if args.online_osv:
        vulnerabilities, skipped = query_osv(inventory, budget=min(30, runner.remaining))
        audit["vulnerabilities"].extend(vulnerabilities)
        audit["online_osv"] = {
            "queried_at": utcnow(),
            "skipped_packages": skipped,
            "data_shared": "package names, versions and ecosystems",
        }
    audit["findings"] = evaluate(policy, audit["observations"], audit["platform"])
    if args.exceptions:
        apply_exceptions(audit["findings"], read_json(args.exceptions))
    audit["coverage"] = coverage(audit["findings"])
    audit["risks"] = analyze(audit)
    audit["finished_at"] = utcnow()
    validate_audit(audit)
    if args.stdout:
        emit(audit)
    else:
        directory = args.output / audit["audit_id"]
        directory.mkdir(mode=0o700, parents=True, exist_ok=False)
        entries = {
            "audit.json": canonical(audit),
            "report.html": render(audit).encode("utf-8"),
            "remediation-plan.json": canonical(plan(audit)),
        }
        if args.oscal:
            assessment_plan, results = oscal(audit)
            entries.update(
                {
                    "assessment-plan.json": canonical(assessment_plan),
                    "assessment-results.json": canonical(results),
                }
            )
        for name, content in entries.items():
            write_new(directory / name, content)
        if args.bundle or args.signing_key:
            path = create_bundle(entries, directory / "evidence.rsat.zip", args.signing_key)
            if args.recipient_key:
                encrypt_bundle(path, directory / "evidence.rsat.enc", args.recipient_key)
        print(
            f"Audit saved: {directory.resolve()}\nAssessed {audit['coverage']['assessed']}/{audit['coverage']['applicable']} applicable controls; "
            f"{audit['coverage']['FAIL']} failed; {audit['coverage']['UNKNOWN'] + audit['coverage']['ERROR']} unknown/errors"
        )
    return 2 if args.fail_on_findings and any(f["status"] == "FAIL" for f in audit["findings"]) else 0


def serve(path, port, duration):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import time

    if not 1 <= port <= 65535 or not 0 < duration <= 3600:
        raise ValueError("Invalid server port/duration")
    content = Path(path).read_bytes()
    if len(content) > 20_000_000:
        raise ValueError("Report exceeds size limit")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path not in {"/", "/index.html"}:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, format, *args):
            return

    with HTTPServer(("127.0.0.1", port), Handler) as server:
        server.timeout = 0.5
        print(f"Local report: http://127.0.0.1:{port}/ (available for {duration:g}s)", flush=True)
        until = time.monotonic() + duration
        while time.monotonic() < until:
            server.handle_request()


def main(argv=None):
    args = parser().parse_args(argv if argv is not None else (sys.argv[1:] or ["audit"]))
    try:
        if args.command == "audit":
            return run_audit(args)
        if args.command == "report":
            write_new(args.output, render(load_audit(args.audit)))
        elif args.command == "diff":
            emit(diff_audits(load_audit(args.before), load_audit(args.after)), args.output)
        elif args.command == "verify":
            emit(verify_bundle(args.bundle, args.trusted_key))
        elif args.command == "keygen":
            print(generate_keys(args.directory))
        elif args.command == "encrypt":
            encrypt_bundle(args.source, args.output, args.key)
        elif args.command == "decrypt":
            decrypt_bundle(args.source, args.output, args.key)
        elif args.command == "bundle":
            if args.policy and args.intelligence:
                raise ValueError("Choose one bundle type")
            data = (
                load_pack(args.source)[0]
                if args.intelligence
                else load_policy(args.source)
                if args.policy
                else load_audit(args.source)
            )
            name = (
                "intelligence.json" if args.intelligence else "policy.json" if args.policy else "audit.json"
            )
            entries = {
                name: args.source.read_bytes() if args.policy or args.intelligence else canonical(data)
            }
            if not args.policy and not args.intelligence:
                entries["report.html"] = render(data).encode()
            create_bundle(entries, args.output, args.signing_key)
        elif args.command == "intel-refresh":
            emit(refresh_enrichment(args.cves), args.output)
        elif args.command == "workspace":
            write_new(args.output, dashboard([load_audit(p) for p in args.audits]))
        elif args.command == "serve":
            serve(args.report, args.port, args.duration)
        elif args.command == "remote":
            emit(remote_audit(args.target, args.binary, args.port, args.identity), args.output)
        elif args.command == "winrm":
            emit(winrm_audit(args.host, args.binary), args.output)
        elif args.command == "probe":
            emit(probe(args.host, args.ports, args.timeout), args.output)
        elif args.command == "plan":
            emit(plan(load_audit(args.audit)), args.output)
        elif args.command == "apply":
            emit(
                apply_action(
                    read_json(args.plan),
                    args.action,
                    args.backup,
                    args.execute,
                    recovery_access=args.recovery_access,
                )
            )
        elif args.command == "rollback":
            emit(rollback(args.backup, args.execute, recovery_access=args.recovery_access))
        elif args.command == "summary":
            emit(local_summary(load_audit(args.audit), args.endpoint, args.model), args.output)
        elif args.command == "oscal":
            args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
            assessment_plan, results = oscal(load_audit(args.audit))
            emit(assessment_plan, args.output / "assessment-plan.json")
            emit(results, args.output / "assessment-results.json")
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"RSAT: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("RSAT: interrupted", file=sys.stderr)
        return 130
