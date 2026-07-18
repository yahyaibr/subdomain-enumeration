# Subdomain Tool

A command-line OSINT utility that discovers subdomains for a given domain by
querying multiple public passive-DNS and certificate-transparency sources in
parallel, then merges and deduplicates the results.

## Sources used

| Source | API key required? |
|---|---|
| [crt.sh](https://crt.sh) (certificate transparency logs) | No |
| [AlienVault OTX](https://otx.alienvault.com) (passive DNS) | Yes — `OTX_API_KEY` |
| [VirusTotal](https://www.virustotal.com) (subdomains) | Yes — `VT_API_KEY` |
| [SecurityTrails](https://securitytrails.com) (subdomains) | Yes — `SECURITYTRAILS_API_KEY` |
| [ThreatCrowd](https://threatcrowd.org) | No |
| [BufferOver](https://tls.bufferover.run) (TLS/DNS) | No |

Sources that need a key are skipped automatically if that key isn't set —
the tool still runs fine with just crt.sh, ThreatCrowd, and BufferOver.

## Requirements

- Python 3.9+
- `requests`

Install the dependency:

```bash
pip install requests
```

## Setup

Get free API keys from whichever paid sources you want to use, then export
them as environment variables (never hardcode keys in the script):

```bash
export OTX_API_KEY="your_otx_key"
export VT_API_KEY="your_virustotal_key"
export SECURITYTRAILS_API_KEY="your_securitytrails_key"
```

## Usage

Interactive mode (prompts for a domain):

```bash
python subdomain_tool.py
```

Direct mode:

```bash
python subdomain_tool.py example.com
```

Save results to a file:

```bash
python subdomain_tool.py example.com -o results.txt
```

Tune request timeout and concurrency:

```bash
python subdomain_tool.py example.com --timeout 15 --workers 6
```

### CLI options

| Flag | Description | Default |
|---|---|---|
| `domain` | Target domain (positional, optional — prompted if omitted) | — |
| `-o`, `--output` | File to write the sorted subdomain list to | none (prints only) |
| `--timeout` | Per-request timeout in seconds | `10` |
| `--workers` | Number of sources queried concurrently | `6` |

## How it works

1. Each source module (`source_crtsh`, `source_otx`, etc.) sends one HTTP
   request and normalizes its response into a set of lowercase hostnames.
2. All six sources are dispatched concurrently with a
   `ThreadPoolExecutor`, so a slow or unresponsive API doesn't block the
   others.
3. Each source is wrapped in its own error handling — a failed request,
   timeout, missing key, or malformed JSON response from one source is
   logged to stderr and simply excluded, rather than crashing the run.
4. Results from every source are merged into a single deduplicated set and
   printed sorted, optionally also written to a file.

## Notes

- This tool only queries third-party public data sources — it does not scan
  or send traffic to the target domain itself.
- Free tiers of VirusTotal, SecurityTrails, and OTX are rate-limited; heavy
  use may return errors, which the tool will report but not crash on.
- Use responsibly and only against domains you're authorized to assess.
