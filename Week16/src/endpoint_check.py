#!/usr/bin/env python3
"""
endpoint_check.py — verify CCDC Inject SVRA12T (Endpoint Protection).

Reads a JSON config describing which services, ports, log files, and
signature files to check, then runs all of them and reports pass/fail.
Auto-detects manager vs agent role from the JSON config name, but can be
overridden with --config.

Usage:
    python3 endpoint_check.py                        # auto-pick config
    python3 endpoint_check.py --config myconfig.json
    python3 endpoint_check.py --output results.json  # save results as JSON

Linux only. Stdlib only. Run as root for full coverage.
"""

import argparse
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def run(cmd, timeout=10):
    """Run a shell command, return (stdout, returncode). Never raises."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return proc.stdout, proc.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return "", -1


def detect_role():
    """Look at installed unit files to guess if this is a manager or agent."""
    out, _ = run(["systemctl", "list-unit-files", "--no-pager", "--no-legend"])
    if "wazuh-manager" in out:
        return "manager"
    if "wazuh-agent" in out:
        return "agent"
    return "unknown"


def auto_config_path(role):
    """Pick the bundled config for the detected role."""
    base = Path(__file__).parent / "sample_data"
    candidates = {
        "manager": base / "config_manager.json",
        "agent": base / "config_agent.json",
        "unknown": base / "config_agent.json",  # fall back to agent
    }
    return candidates.get(role)


# ---------------------------------------------------------------------------
# Individual check types. Each takes a dict from the JSON config plus any
# extra runtime info, and returns (status, detail).
# ---------------------------------------------------------------------------
def check_service(spec):
    """Spec: {"service": "wazuh-agent"}"""
    name = spec["service"]
    out, _ = run(["systemctl", "is-active", name])
    state = out.strip()
    if state == "active":
        return "pass", f"{name} is active"
    return "fail", f"{name} is '{state or 'unknown'}'"


def check_port(spec):
    """Spec: {"port": 3310, "protocol": "tcp"} — check it's listening."""
    port = spec["port"]
    proto = spec.get("protocol", "tcp")
    flag = "-ltnp" if proto == "tcp" else "-tulnp"
    out, _ = run(f"ss {flag} 2>/dev/null | grep ':{port} '")
    if out.strip():
        return "pass", f"{proto} port {port} is listening"
    return "fail", f"{proto} port {port} is not listening"


def check_log_pattern(spec):
    """Spec: {"path": "/var/ossec/logs/ossec.log", "must_contain": "Connected to the server"}"""
    log = Path(spec["path"])
    if not log.is_file():
        return "fail", f"log file {spec['path']} not found"
    out, _ = run(["tail", "-n", "200", str(log)])
    if spec["must_contain"] in out:
        return "pass", f"found expected pattern in log"
    if "warn_if_contains" in spec and spec["warn_if_contains"] in out:
        return "warn", f"found warning pattern (not yet at expected state)"
    return "fail", f"expected pattern not found in last 200 log lines"


def check_signature_freshness(spec):
    """Spec: {"paths": ["/var/lib/clamav/daily.cvd", ...], "max_age_days": 7}"""
    max_age = spec.get("max_age_days", 7)
    for path in spec["paths"]:
        p = Path(path)
        if p.is_file():
            age_days = (time.time() - p.stat().st_mtime) / 86400
            if age_days <= max_age:
                return "pass", f"signatures updated {age_days:.1f} days ago"
            return "warn", f"signatures are {age_days:.1f} days old (max {max_age})"
    return "fail", "no signature database found at any expected path"


def check_scheduled_task(spec):
    """Spec: {"timer_pattern": "clam", "cron_pattern": "clamscan|clamdscan"}"""
    timer = spec.get("timer_pattern", "")
    if timer:
        out, _ = run(f"systemctl list-timers --all --no-pager 2>/dev/null | grep -i {timer}")
        if out.strip():
            return "pass", f"systemd timer matching '{timer}' found"
    cron = spec.get("cron_pattern", "")
    if cron:
        out, _ = run(f"grep -rl -i '{cron}' /etc/cron.* /var/spool/cron 2>/dev/null")
        if out.strip():
            return "pass", f"cron entry matching '{cron}' found"
    return "fail", "no scheduled task found (no timer or cron entry)"


# Set of valid check type names. Kept as a constant so config validation
# (in tests and elsewhere) can verify a config doesn't reference unknown types.
CHECK_TYPES = {
    "service", "port", "log_pattern",
    "signature_freshness", "scheduled_task",
}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_checks(config):
    """Walk every check in the config; return a list of result dicts."""
    import endpoint_check as ec_self  # for late binding so tests can patch
    type_to_fn = {
        "service": "check_service",
        "port": "check_port",
        "log_pattern": "check_log_pattern",
        "signature_freshness": "check_signature_freshness",
        "scheduled_task": "check_scheduled_task",
    }
    results = []
    for check in config["checks"]:
        check_type = check["type"]
        fn_name = type_to_fn.get(check_type)
        if fn_name is None:
            results.append({
                "name": check.get("name", "?"),
                "type": check_type,
                "status": "fail",
                "detail": f"unknown check type: {check_type}",
            })
            continue
        runner = getattr(ec_self, fn_name)
        try:
            status, detail = runner(check)
        except Exception as e:
            status, detail = "fail", f"check raised: {type(e).__name__}: {e}"
        results.append({
            "name": check.get("name", check_type),
            "type": check_type,
            "status": status,
            "detail": detail,
        })
    return results


def build_report(config, results):
    """Build the JSON output report — used by --output."""
    counts = {"pass": 0, "warn": 0, "fail": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {
        "host": socket.gethostname(),
        "config": config.get("name", "unknown"),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": counts,
        "checks": results,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description="Verify SVRA12T endpoint protection inject.")
    p.add_argument("--config", help="Path to JSON config (auto-detected by default)")
    p.add_argument("--output", help="Write results as JSON to this file")
    args = p.parse_args()

    if args.config:
        config_path = Path(args.config)
    else:
        role = detect_role()
        config_path = auto_config_path(role)
        if config_path is None or not config_path.is_file():
            print(f"error: could not auto-locate config for role '{role}'", file=sys.stderr)
            print(f"       try --config sample_data/config_agent.json", file=sys.stderr)
            return 2

    if not config_path.is_file():
        print(f"error: config file not found: {config_path}", file=sys.stderr)
        return 2

    with config_path.open() as f:
        config = json.load(f)

    print(f"\nEndpoint protection check  (host: {socket.gethostname()})")
    print(f"Config: {config_path.name}  ({config.get('name', 'unnamed')})\n")

    results = run_checks(config)
    icons = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}
    for r in results:
        print(f"  {icons[r['status']]} {r['name']:<28} {r['detail']}")

    counts = {"pass": 0, "warn": 0, "fail": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"\nSummary: {counts['pass']} pass, {counts['warn']} warn, {counts['fail']} fail")

    if args.output:
        report = build_report(config, results)
        Path(args.output).write_text(json.dumps(report, indent=2))
        print(f"Wrote JSON results to {args.output}")

    return 0 if counts["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())