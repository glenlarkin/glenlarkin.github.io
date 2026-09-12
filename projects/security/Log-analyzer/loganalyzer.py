#!/usr/bin/env python3
"""Log anomaly detector: parses auth/syslog/firewall logs and flags suspicious events."""

import re
import csv
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

# --- Detection thresholds ---
BRUTE_FORCE_THRESHOLD = 5       # failed logins within window
BRUTE_FORCE_WINDOW_SEC = 60
OFF_HOURS = range(0, 6)         # midnight–6am considered off-hours

# --- Regex patterns ---
PATTERNS = {
    # SSH failed login: auth.log / syslog
    "ssh_fail": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
    ),
    # SSH accepted login
    "ssh_success": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)"
    ),
    # sudo / privilege escalation
    "sudo": re.compile(
        r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+).*sudo.*USER=(?P<user>\S+).*COMMAND=(?P<cmd>.+)"
    ),
    # Generic syslog timestamp fallback
    "syslog_ts": re.compile(r"^(\w+\s+\d+\s+\d+:\d+:\d+)"),
}


def parse_syslog_time(month: str, day: str, time_str: str) -> datetime:
    year = datetime.now().year
    try:
        return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return datetime.now()


def parse_log(path: str) -> list[dict]:
    events = []
    with open(path, errors="replace") as f:
        for line in f:
            for etype, pat in PATTERNS.items():
                m = pat.search(line)
                if m:
                    d = m.groupdict()
                    ts = parse_syslog_time(d.get("month", "Jan"), d.get("day", "1"), d.get("time", "00:00:00"))
                    events.append({
                        "type": etype,
                        "timestamp": ts,
                        "ip": d.get("ip", ""),
                        "user": d.get("user", ""),
                        "cmd": d.get("cmd", ""),
                        "raw": line.strip(),
                    })
                    break
    return events


def detect_anomalies(events: list[dict]) -> list[dict]:
    findings = []

    # Group failed logins by IP
    fails_by_ip: dict[str, list[datetime]] = defaultdict(list)
    seen_ips: set[str] = set()
    success_ips: set[str] = set()

    for e in events:
        if e["type"] == "ssh_success":
            success_ips.add(e["ip"])

    for e in events:
        if e["type"] == "ssh_fail":
            fails_by_ip[e["ip"]].append(e["timestamp"])

        if e["type"] == "ssh_success":
            # Off-hours login
            if e["timestamp"].hour in OFF_HOURS:
                findings.append({
                    "severity": "MEDIUM",
                    "rule": "Off-Hours Login",
                    "timestamp": e["timestamp"].isoformat(),
                    "ip": e["ip"],
                    "user": e["user"],
                    "detail": f"Successful login at {e['timestamp'].strftime('%H:%M')}",
                })

        if e["type"] == "sudo":
            findings.append({
                "severity": "HIGH",
                "rule": "Privilege Escalation",
                "timestamp": e["timestamp"].isoformat(),
                "ip": "",
                "user": e["user"],
                "detail": f"sudo command: {e['cmd'][:80]}",
            })

    # Brute force: N failures within window
    for ip, times in fails_by_ip.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times[i:] if (t - times[i]).total_seconds() <= BRUTE_FORCE_WINDOW_SEC]
            if len(window) >= BRUTE_FORCE_THRESHOLD:
                findings.append({
                    "severity": "CRITICAL",
                    "rule": "Brute Force Attempt",
                    "timestamp": times[i].isoformat(),
                    "ip": ip,
                    "user": "",
                    "detail": f"{len(window)} failed logins in {BRUTE_FORCE_WINDOW_SEC}s",
                })
                break  # one finding per IP

    return sorted(findings, key=lambda x: x["severity"])


def write_report(findings: list[dict], output: str):
    with open(output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["severity", "rule", "timestamp", "ip", "user", "detail"])
        writer.writeheader()
        writer.writerows(findings)


def print_summary(findings: list[dict]):
    counts = defaultdict(int)
    for f in findings:
        counts[f["severity"]] += 1
    print("\n=== ANOMALY SUMMARY ===")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev]:
            print(f"  {sev}: {counts[sev]}")
    print(f"  TOTAL: {len(findings)}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Log anomaly detector — flags suspicious auth events")
    parser.add_argument("logs", nargs="+", help="Log files to analyze (auth.log, syslog, etc.)")
    parser.add_argument("-o", "--output", help="Output CSV (default: anomalies_<timestamp>.csv)")
    args = parser.parse_args()

    output = args.output or f"anomalies_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    all_events = []
    for path in args.logs:
        print(f"Parsing {path}...")
        all_events.extend(parse_log(path))

    print(f"Parsed {len(all_events)} events. Running detection...")
    findings = detect_anomalies(all_events)

    write_report(findings, output)
    print_summary(findings)
    print(f"\nReport saved → {output}")


if __name__ == "__main__":
    main()
