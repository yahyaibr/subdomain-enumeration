## Subdomain Enumeration Tool – Description

This tool is a **subdomain enumeration and reconnaissance script** written in Python. It is designed to collect and aggregate subdomains of a given domain from multiple public threat-intelligence and OSINT sources. The main goal is to help **security researchers, penetration testers, and students** identify exposed or forgotten subdomains that may increase an organization’s attack surface.

### What the tool does

* Prompts the user to enter a target domain
* Queries several well-known security and intelligence platforms
* Collects subdomains from each source
* Normalizes and deduplicates results
* Outputs a clean, sorted list of discovered subdomains

### Data sources used

The tool gathers subdomains from multiple independent sources to improve coverage and accuracy:

* **crt.sh** – Extracts subdomains from Certificate Transparency logs
* **AlienVault OTX** – Uses passive DNS records
* **VirusTotal** – Fetches known subdomains from VirusTotal intelligence
* **SecurityTrails** – Retrieves historical and current subdomain data
* **TLS BufferOver** – Uses DNS and TLS scan data
* **ThreatCrowd** – Pulls subdomains from threat intelligence reports

### Key features

* Aggregates results from **multiple APIs** in one run
* Removes duplicates using Python sets
* Handles network/API errors gracefully
* Outputs results in a simple, readable format
* Easy to extend with additional sources

### Use cases

* Attack surface mapping
* Bug bounty reconnaissance
* OSINT investigations
* Academic cybersecurity research
* Learning how threat-intelligence APIs work

### Requirements

* Python 3
* `requests` library
* API keys for some services (VirusTotal, OTX, SecurityTrails, BufferOver)

### Important note

This tool is intended for **ethical and legal security testing only**. Always ensure you have proper authorization before scanning or collecting information about a domain.
