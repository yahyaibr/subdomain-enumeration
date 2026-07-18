#!/usr/bin/env python3
"""
Subdomain enumeration tool — queries multiple public passive-DNS / certificate-
transparency sources concurrently and merges the results.

Sources: crt.sh, AlienVault OTX, VirusTotal, SecurityTrails, ThreatCrowd,
BufferOver.

Usage:
    python subdomain_tool.py example.com
    python subdomain_tool.py example.com -o results.txt
    python subdomain_tool.py example.com --timeout 15 --workers 6

API keys (optional ):
    export OTX_API_KEY="..."
    export VT_API_KEY="..."
    export SECURITYTRAILS_API_KEY="..."

"""

import argparse
import concurrent.futures
import json
import os
import sys
from typing import Iterable

import requests

DEFAULT_TIMEOUT = 10
BANNER = r"""
╔════════════════════════════════════════╗
║                                        ║
║     WELCOME TO THE SUBDOMAIN TOOL      ║
║                                        ║
║     CREATED BY: Yahyaibr               ║
║     CYBER SECURITY STUDENT & RESEARCHER║
║                                        ║
║           LET'S GET STARTED!           ║
║                                        ║
╚════════════════════════════════════════╝
"""


def _get_json(url: str, headers: dict | None = None, timeout: int = DEFAULT_TIMEOUT):
    """GET a URL and return parsed JSON, or None on any failure."""
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f"    [!] request failed for {url.split('/')[2]}: {e}", file=sys.stderr)
    except json.JSONDecodeError:
        print(f"    [!] bad JSON from {url.split('/')[2]}", file=sys.stderr)
    return None


def source_crtsh(domain: str, timeout: int) -> set[str]:
    data = _get_json(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=timeout)
    found = set()
    if isinstance(data, list):
        for item in data:
            for value in item.get("name_value", "").split("\n"):
                value = value.strip().lower().lstrip("*.")
                if value:
                    found.add(value)
    return found


def source_otx(domain: str, timeout: int) -> set[str]:
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        return set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    data = _get_json(url, headers={"X-OTX-API-KEY": api_key}, timeout=timeout)
    found = set()
    if data:
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname", "").strip().lower()
            if hostname:
                found.add(hostname)
    return found


def source_virustotal(domain: str, timeout: int) -> set[str]:
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return set()
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    data = _get_json(url, headers={"x-apikey": api_key}, timeout=timeout)
    found = set()
    if data:
        for item in data.get("data", []):
            sub = item.get("id", "").strip().lower()
            if sub:
                found.add(sub)
    return found


def source_securitytrails(domain: str, timeout: int) -> set[str]:
    api_key = os.environ.get("SECURITYTRAILS_API_KEY")
    if not api_key:
        return set()
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    data = _get_json(url, headers={"APIKEY": api_key}, timeout=timeout)
    found = set()
    if data:
        for sub in data.get("subdomains", []):
            found.add(f"{sub}.{domain}".lower())
    return found


def source_threatcrowd(domain: str, timeout: int) -> set[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    data = _get_json(url, timeout=timeout)
    found = set()
    if data and data.get("response_code") == "1":
        for sub in data.get("subdomains", []):
            found.add(sub.strip().lower())
    return found


def source_bufferover(domain: str, timeout: int) -> set[str]:
    url = f"https://tls.bufferover.run/dns?q=.{domain}"
    data = _get_json(url, timeout=timeout)
    found = set()
    if data:
        for entry in data.get("Results", []) or []:
            # entries look like "ip,sub.domain.com"
            sub = entry.split(",")[-1].strip().lower()
            if sub.endswith(domain):
                found.add(sub)
    return found


SOURCES = {
    "crt.sh": source_crtsh,
    "OTX": source_otx,
    "VirusTotal": source_virustotal,
    "SecurityTrails": source_securitytrails,
    "ThreatCrowd": source_threatcrowd,
    "BufferOver": source_bufferover,
}


def enumerate_subdomains(domain: str, timeout: int, workers: int) -> set[str]:
    all_subs: set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_name = {
            pool.submit(fn, domain, timeout): name for name, fn in SOURCES.items()
        }
        for future in concurrent.futures.as_completed(future_to_name):
            name = future_to_name[future]
            try:
                results = future.result()
            except Exception as e:
                print(f"    [!] {name} crashed: {e}", file=sys.stderr)
                continue
            print(f"    [+] {name}: {len(results)} result(s)")
            all_subs |= results
    return all_subs


def main():
    parser = argparse.ArgumentParser(description="Multi-source subdomain enumeration tool")
    parser.add_argument("domain", nargs="?", help="Target domain, e.g. example.com")
    parser.add_argument("-o", "--output", help="Write results to this file")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds")
    parser.add_argument("--workers", type=int, default=6, help="Number of concurrent source queries")
    args = parser.parse_args()

    print(BANNER)
    domain = args.domain or input("Please enter a domain: ").strip()
    if not domain:
        print("No domain provided, exiting.")
        sys.exit(1)

    print(f"[+] Checking subdomain activity for {domain} ...")
    subdomains = enumerate_subdomains(domain, args.timeout, args.workers)

    print(f"\n[+] Subdomains found: {len(subdomains)}")
    for sub in sorted(subdomains):
        print(" └─", sub)

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(sorted(subdomains)) + "\n")
        print(f"\n[+] Results written to {args.output}")


if __name__ == "__main__":
    main()
