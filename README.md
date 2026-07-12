# KEV Analyzer

A CLI tool that fetches and analyzes the [CISA Known Exploited Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog — the list of vulnerabilities with evidence of active exploitation in the wild. Useful as an input to vulnerability management prioritization.

## What it does

- Downloads the latest KEV catalog from CISA and caches it locally
- Shows statistics: total entries, ransomware-linked count, top vendors, per-year breakdown
- Filters by ransomware campaign use, recency, or search term
- Matches the catalog against your own asset inventory
- Outputs human-readable text or JSON

## Installation

Requires [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/marinsec/kev-analyzer.git
cd kev-analyzer
uv tool install .
```

This installs a global `kev-analyzer` command. To update after pulling new changes, run `uv tool install . --force`.

## SOC Use Cases
- Prioritize vulnerability patching based on active exploitation
- Enrich incident investigations with KEV threat intelligence
- Cross-reference detected exploits during alert triage
- Feed KEV data into SIEM detection rules
- Track ransomware-associated vulnerabilities for threat hunting

## Example Output

```sh
$ kev-analyzer

=== CISA KEV Catalog === Total entries: 1,247 Ransomware-linked: 189 (15.2%) Top vendors: Microsoft, Adobe, Cisco, Fortinet, Apple

Recent additions (last 14 days): 7

CVE-2024-XXXXX (Fortinet) - RCE
CVE-2024-XXXXX (Microsoft) - Elevation of Privilege ...
```

## MITRE ATT&CK Relevance

KEV vulnerabilities are frequently mapped to:
- T1190 (Exploit Public-Facing Application)
- T1210 (Exploitation of Remote Services)
- T1068 (Exploitation for Privilege Escalation)

## Usage

```sh
kev-analyzer                        # overview statistics
kev-analyzer --ransomware           # only ransomware-linked entries
kev-analyzer --recent 14            # added in the last 14 days
kev-analyzer --search fortinet      # filter by vendor/product/name
kev-analyzer --inventory inventory.txt               # match your asset list
kev-analyzer --inventory inventory.txt --ransomware  # combine filters
kev-analyzer --json                 # JSON output
kev-analyzer --update               # refresh data from CISA
```

The catalog is cached in a `kev.json` file in the current directory after the first run. Subsequent runs read from that cache (fast, offline); use `--update` to pull the latest data from CISA.

## Asset inventory

Copy `inventory.example.txt` to `inventory.txt` and list your vendors/products (one per line). `inventory.txt` is gitignored so your environment is not exposed.

## Project structure

- `fetch.py` — downloads and caches the catalog
- `parse.py` — extracts the relevant fields from the raw JSON
- `analyze.py` — counting, filtering, search, inventory matching
- `main.py` — CLI entry point

## Data source

[CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), public domain.
