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
- `python3-venv` package
- For Tor support: Tor running with **ControlPort 9051** and **SOCKS5 at 9050** (default in most configs)
- For I2P support: An I2P router running and configured with an HTTP proxy (usually at `http://127.0.0.1:4444`)
- For `tpm2-pytss` support: `libtss2-dev` package
- Optional: `dialog` or `whiptail` for TUI configuration menu

### How to Run

There are two main entry points in this project:

#### **Option 1: Using `run.sh` (Recommended)**
The `run.sh` script is a wrapper that:
- Creates and activates a Python virtual environment
- Installs all dependencies
- Provides a TUI (Text User Interface) for easy configuration
- Runs the main `kaplan.py` script

**Usage:**
```bash
# Interactive mode with TUI configuration menu
./run.sh

# Or set environment variables directly
NETWORK=tor MODE=parallel ./run.sh

# For I2P with multiple proxies (rotation)
NETWORK=i2p I2P_PROXIES="http://127.0.0.1:4444,http://127.0.0.1:4445" ./run.sh
```

#### **Option 2: Running `kaplan.py` directly**
You can also run the Python script directly if you've already set up your environment:

```bash
# First time setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the script
python kaplan.py

# Or with environment variables
NETWORK=i2p HEADLESS=1 python kaplan.py
```

**Note:** `kaplan.py` uses the advanced implementation from `src/tor_blue_downloader.py` which includes all features like encryption, signing, cover traffic, etc.

### Usage Examples

1. **Create `urls.txt` with your target files:**
   ```txt
   https://example.com/some-report.pdf
   https://example.com/config.bak
   http://identiguy.i2p/
   http://anothersite.i2p/files/data.zip
   ```

2. **Run with different configurations:**

   ```bash
   # Tor downloads with TUI (default)
   ./run.sh

   # I2P downloads with single proxy
   NETWORK=i2p I2P_HTTP_PROXY=http://127.0.0.1:4444 ./run.sh

   # I2P with multiple proxies for rotation (recommended for better anonymity)
   NETWORK=i2p I2P_PROXIES="http://127.0.0.1:4444,http://127.0.0.1:4445,http://127.0.0.1:4446" ./run.sh

   # Headless mode (no TUI, batch mode)
   HEADLESS=1 NETWORK=tor MODE=parallel ./run.sh

   # Clearnet downloads
   NETWORK=direct ./run.sh
   ```

3. **Check results:**
   - Downloaded files: `quarantine/` directory
   - Logs: `logs/` directory
   - Audit trail: `logs/audit.jsonl`

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `URLS_FILE` | Path to the file containing URLs to download. | `urls.txt` |
| `MODE` | `parallel` or `sequential`. | `parallel` |
| `NETWORK` | `tor`, `i2p`, or `direct` (clearnet). | `tor` |
| `TOR_PROXY` | Tor SOCKS proxy port. | `9050` |
| `TOR_CTL` | Tor control port. | `9051` |
| `TOR_PASS` | Tor control port password. | `None` |
| `I2P_HTTP_PROXY` | I2P HTTP proxy URL (single proxy). | `http://127.0.0.1:4444` |
| `I2P_SOCKS_PROXY` | I2P SOCKS proxy URL (alternative to HTTP). | `socks5h://127.0.0.1:4447` |
| `I2P_PROXIES` | **Comma-separated list of I2P proxies for rotation** (recommended for anonymity). | `None` |
| `OUT_DIR` | Output directory for downloaded files. | `artifacts` |
| `QUAR_DIR` | Quarantine directory for downloaded files before they are moved to `OUT_DIR`. | `quarantine` |
| `LOG_DIR` | Directory for log files. | `logs` |
| `AUDIT_LOG` | Path to the audit log file (JSONL format). | `logs/audit.jsonl` |
| `MAX_WORKERS` | Maximum number of download threads in parallel mode. | `3` |
| `PER_HOST_CAP` | Maximum number of concurrent downloads per host (auto-reduced for I2P). | `2` |
| `MAX_RETRIES` | Maximum number of retries for a failed download (auto-increased for I2P). | `3` |
| `RETRY_BASE_DELAY` | Base delay in seconds for retries (auto-increased for I2P). | `3.0` |
| `MAX_FILE_MB` | Maximum file size in megabytes. | `1024` |
| `ALLOW_DOMAINS` | Comma-separated list of allowed domains. | `None` |
| `DENY_TLDS` | Comma-separated list of denied TLDs. | `None` |
| `ENFORCE_MIME` | Enforce MIME type matching between `Content-Type` header and file content. | `1` |
| `YARA_DIR` | Directory containing YARA rules. | `yara_rules` |
| `HEADLESS` | Run in headless/batch mode without TUI. | `0` |
| `TRANSPORT` | Same as `NETWORK` (alternative variable name). | `tor` |

## I2P-Specific Features & Optimizations

When using I2P as the transport network, KAPLAN automatically applies several optimizations:

### **Automatic I2P Rotation**
- Similar to Tor's NEWNYM, KAPLAN supports I2P tunnel/session rotation for enhanced anonymity
- Configure multiple I2P HTTP proxies using `I2P_PROXIES` for automatic rotation
- Example: `I2P_PROXIES="http://127.0.0.1:4444,http://127.0.0.1:4445,http://127.0.0.1:4446"`
- Each proxy can point to a different I2P tunnel with separate destination keys

### **I2P-Optimized Download Algorithm**
The downloader automatically detects `.i2p` domains and applies the following optimizations:

1. **Extended Timeouts**
   - HEAD requests: 60s (vs 30s for Tor/clearnet)
   - GET requests: 180s (vs 90s for Tor/clearnet)
   - I2P tunnels are slower and more variable in latency

2. **Reduced Concurrency**
   - Per-host connection limit is halved for `.i2p` domains
   - Prevents overwhelming slow I2P tunnels
   - Example: If `PER_HOST_CAP=2`, I2P sites use 1 concurrent connection

3. **Increased Retry Attempts**
   - Automatic +2 extra retries for I2P downloads
   - I2P network is less reliable than Tor due to peer-based routing

4. **Longer Retry Delays**
   - Base delay multiplied by 1.5x for I2P
   - Allows time for tunnel recovery/rebuilding

5. **Aggressive Identity Rotation**
   - 70% chance of rotating on retry (vs 50% for Tor)
   - Forces new tunnel path for better anonymity and reliability

### **Setting Up Multiple I2P Proxies for Rotation**

To maximize anonymity and reliability with I2P, configure multiple tunnels:

1. **Edit your I2P router's tunnel configuration** (`~/.i2p/i2ptunnel.config` or via the I2P console)
2. **Create multiple HTTP proxy tunnels** on different ports (e.g., 4444, 4445, 4446)
3. **Each tunnel should use a different destination key** for true identity separation
4. **Set the environment variable:**
   ```bash
   export I2P_PROXIES="http://127.0.0.1:4444,http://127.0.0.1:4445,http://127.0.0.1:4446"
   ```
5. **Run KAPLAN:**
   ```bash
   NETWORK=i2p ./run.sh
   ```

### **Manual I2P Rotation (Interactive Mode)**

When using the interactive TUI mode, you can manually force I2P rotation:

```
(tbd) renew
```

This will rotate to the next I2P proxy in your configured list or clear the current session to force a new tunnel.

---