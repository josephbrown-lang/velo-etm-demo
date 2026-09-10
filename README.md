# VeloCloud ETM Demo

A web-based tool for demonstrating VeloCloud Edge Threat Management (ETM) capabilities. It runs security test modules against a VeloCloud edge and displays real-time results showing which traffic is blocked, allowed, or inconclusive.

## Test Modules

| Module | Description |
|---|---|
| Web/URL Filter | Tests URL category filtering (social media, gambling, streaming, etc.) |
| IDPS | Sends known threat signatures (CobaltStrike, Log4j, cryptominers, etc.) |
| URL Reputation | Tests known malicious and phishing URLs |
| IP Reputation | Tests TCP connections to known bad IPs (Tor exits, botnets, C2) |
| GEO/IP Filter | Tests geographic-based URL filtering by country |
| DNS Filter | Tests DNS resolution of known malware and phishing domains |
| App Filter | Tests application-layer DPI across HTTP, HTTPS, DNS, SMTP, IMAP, and streaming |
| Dynamic Blocklist | Fetches external threat feeds (URLhaus, OpenPhish) and tests each entry |

## Requirements

- Python 3.5.2+
- A network path through a VeloCloud edge with ETM policies configured

## Setup

```bash
pip install -r requirements.txt
```

## Usage

Start the server:

```bash
python3 server.py
```

Open http://localhost:8080 in a browser.

From the sidebar, select a test module, choose which targets to test, and click **Run Test**. Use **Run All Tests** at the top of the sidebar to execute all modules sequentially.

Results stream into the terminal pane in real time. The stats bar at the bottom tracks blocked, allowed, and inconclusive counts.

### Adding Custom Targets

Each module supports custom targets. Type a URL, domain, or IP into the input field at the bottom of the expanded module card and click **+ Add**.

### Running Tests from the CLI

Individual test scripts can also be run directly:

```bash
python3 tests/web_filter.py --no-verify
python3 tests/idps.py --no-verify --target cobalt-c2 --target log4j
```

Options:
- `--no-verify` — disable SSL certificate verification
- `--timeout N` — request timeout in seconds (default: 5)
- `--target KEY` — run specific targets only (repeatable; omit to run all)
