#!/usr/bin/env python3
"""Network scanner: discovers hosts and open ports, outputs CSV."""

import csv
import socket
import sys
import ipaddress
import concurrent.futures
from datetime import datetime

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 27017]


def resolve_hostname(host: str) -> str:
    try:
        return socket.gethostbyaddr(host)[0]
    except socket.herror:
        return ""


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def scan_host(host: str, ports: list[int]) -> dict | None:
    open_ports = [p for p in ports if scan_port(host, p)]
    if not open_ports:
        return None
    return {
        "ip": host,
        "hostname": resolve_hostname(host),
        "open_ports": ",".join(map(str, open_ports)),
    }


def expand_targets(targets: list[str]) -> list[str]:
    hosts = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            hosts.extend(str(ip) for ip in net.hosts())
        except ValueError:
            hosts.append(t)
    return hosts


def scan(targets: list[str], ports: list[int], workers: int = 50) -> list[dict]:
    hosts = expand_targets(targets)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_host, h, ports): h for h in hosts}
        for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
            print(f"\r[{i}/{len(hosts)}] scanning...", end="", flush=True)
            result = f.result()
            if result:
                results.append(result)
    print()
    return results


def write_csv(results: list[dict], output: str):
    with open(output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "hostname", "open_ports"])
        writer.writeheader()
        writer.writerows(results)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Network scanner — outputs CSV of hosts and open ports")
    parser.add_argument("targets", nargs="+", help="IPs, hostnames, or CIDR ranges (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", help="Comma-separated ports (default: common ports)")
    parser.add_argument("-o", "--output", help="Output CSV file (default: scan_<timestamp>.csv)")
    parser.add_argument("-w", "--workers", type=int, default=50, help="Concurrent threads (default: 50)")
    args = parser.parse_args()

    ports = list(map(int, args.ports.split(","))) if args.ports else DEFAULT_PORTS
    output = args.output or f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    print(f"Scanning {args.targets} on {len(ports)} ports...")
    results = scan(args.targets, ports, args.workers)
    write_csv(results, output)
    print(f"Found {len(results)} host(s) with open ports → {output}")


if __name__ == "__main__":
    main()
