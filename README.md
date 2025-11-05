# KAPLAN - Defensive Acquisition Pipeline

KAPLAN is a multithreaded, identity-rotating, resilient file fetcher built for covert reconnaissance and data exfiltration.

## Key Features

| Feature | Description |
|---|---|
| **Multiple Network Support** | Download files over Tor, I2P, or the clearnet. |
| **Automatic Tor Circuit Rotation** | Each file download originates from a fresh exit node, preventing correlation between requests. |
| **Parallelized Downloads (Threaded)** | Speed meets stealth—download dozens of files concurrently without sacrificing anonymity. |
| **Resilient Retry Logic** | Handles timeouts, transient errors, and flaky onion/i2p services with configurable retries. |
| **OPSEC-Aware Logging** | All activity is timestamped, structured, and saved locally—no external telemetry. |
| **Filename Extraction & Conflict Avoidance** | Automatically parses `Content-Disposition`, falls back to URL-derived names, and prevents overwrites. |
| **Connectivity Validation** | Before anything runs, KAPLAN verifies your traffic is actually routed through Tor (via `check.torproject.org`). |
| **Installer/Wrapper Script** | The `run.sh` script automatically creates a virtual environment and installs dependencies. |

## How It Works

### 1. **Setup & Validation**
- The `run.sh` script creates a Python virtual environment and installs the required dependencies.
- When using Tor, it starts by checking if Tor is properly routing traffic.
- If not, it warns you—because there’s nothing worse than thinking you’re anonymous when you’re not.

### 2. **Input Handling**
- Reads URLs from a simple `urls.txt` file:
  ```txt
  https://example.com/confidential.pdf
  http://example.com/creds.xlsx
  http://identiguy.i2p/
  ```
- Ignores comments (`#`) and invalid lines.

### 3. **Download Execution**
For **each URL**:
- **Rotates Tor identity** (if using Tor) by requesting a new circuit via `NEWNYM`.
- Fetches the file via `requests` over the configured network (Tor, I2P, or clearnet).
- Saves with **smart naming** to avoid collisions.
- Logs success/failure with full context.

### 4. **Execution Modes**
- **`parallel`** (default): Uses `ThreadPoolExecutor` for speed.
- **`sequential`**: Slower, but useful for resource-limited or highly sensitive ops.

## Quick Start

### Prerequisites
- Python 3.7+
- `python3-venv` package.
- For Tor support: Tor running with **ControlPort 9051** and **SOCKS5 at 9050** (default in most configs).
- For I2P support: An I2P router running and configured with an HTTP proxy (usually at `http://127.0.0.1:4444`).
- For `tpm2-pytss` support: `libtss2-dev` package.

### Usage
1. Create `urls.txt` with your target files:
   ```txt
   https://example.com/some-report.pdf
   https://example.com/config.bak
   http://identiguy.i2p/
   ```
2. Run the installer/wrapper script:
   ```bash
   # For Tor downloads (default)
   ./run.sh

   # For I2P downloads
   NETWORK=i2p I2P_PROXY=http://127.0.0.1:4444 ./run.sh

   # For clearnet downloads
   NETWORK=clearnet ./run.sh
   ```
3. Check `quarantine/` and `logs/` for results.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `URLS_FILE` | Path to the file containing URLs to download. | `urls.txt` |
| `MODE` | `parallel` or `sequential`. | `parallel` |
| `NETWORK` | `tor`, `i2p`, or `clearnet`. | `tor` |
| `TOR_PROXY` | Tor SOCKS proxy port. | `9050` |
| `TOR_CTL` | Tor control port. | `9051` |
| `TOR_PASS` | Tor control port password. | `None` |
| `I2P_PROXY` | I2P HTTP proxy URL. | `None` |
| `OUT_DIR` | Output directory for downloaded files. | `artifacts` |
| `QUAR_DIR` | Quarantine directory for downloaded files before they are moved to `OUT_DIR`. | `quarantine` |
| `LOG_DIR` | Directory for log files. | `logs` |
| `AUDIT_LOG` | Path to the audit log file (JSONL format). | `logs/audit.jsonl` |
| `MAX_WORKERS` | Maximum number of download threads in parallel mode. | `3` |
| `PER_HOST_CAP` | Maximum number of concurrent downloads per host. | `2` |
| `MAX_RETRIES` | Maximum number of retries for a failed download. | `3` |
| `RETRY_BASE_DELAY` | Base delay in seconds for retries. | `3.0` |
| `MAX_FILE_MB` | Maximum file size in megabytes. | `1024` |
| `ALLOW_DOMAINS` | Comma-separated list of allowed domains. | `None` |
| `DENY_TLDS` | Comma-separated list of denied TLDs. | `None` |
| `ENFORCE_MIME` | Enforce MIME type matching between `Content-Type` header and file content. | `1` |
| `YARA_DIR` | Directory containing YARA rules. | `yara_rules` |

---

**License**: MIT.