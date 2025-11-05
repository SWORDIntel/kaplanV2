# KAPLAN — Stealthy Bulk Fetching Over Tor for Red Team Ops

> **A multithreaded, identity-rotating, resilient file fetcher built for covert red team reconnaissance and data exfiltration over Tor.**  
> 🔥 Written with OPSEC in mind • By [toxy4ny](https://github.com/toxy4ny) • For Hackers Who Like To Stay Unseen

---

## 🕵️‍♂️ Why This Tool Exists

When you're operating in hostile environments—whether during internal pentests, adversary simulations, or covert intel gathering—you can't afford to leave traces. Every HTTP request is a potential fingerprint. Every static IP is a liability.

Enter **KAPLAN** (`tdd`): a Python utility engineered for red teams who need to **download sensitive documents, dumps, configs, or artifacts**—**anonymously**, **resiliently**, and **without revealing their true origin**.

Unlike generic downloaders, `tdd`:
- Routes **all traffic over Tor** using SOCKS5.
- **Rotates Tor circuits** before *every* download to avoid linkability.
- Handles **failures gracefully** with exponential retry logic.
- Supports **parallelized bulk fetching** without breaking operational security.
- Leaves **zero forensic residue** beyond Tor traffic.

> ⚠️ **Note**: This tool is for authorized security research and legitimate red team engagements only. Misuse is illegal.

---

## 🧰 Key Features

| Feature | Red Team Value |
|--------|----------------|
| **Automatic Tor Circuit Rotation** | Each file download originates from a **fresh exit node**, preventing correlation between requests. |
| **Parallelized Downloads (Threaded)** | Speed meets stealth—download **dozens of files concurrently** without sacrificing anonymity. |
| **Resilient Retry Logic** | Handles timeouts, transient errors, and flaky onion services with **configurable retries**. |
| **OPSEC-Aware Logging** | All activity is **timestamped**, **structured**, and **saved locally**—no external telemetry. |
| **Filename Extraction & Conflict Avoidance** | Automatically parses `Content-Disposition`, falls back to URL-derived names, and prevents overwrites. |
| **Tor Connectivity Validation** | Before anything runs, `tdd` **verifies** your traffic is actually routed through Tor (via `check.torproject.org`). |

---

## 🛠️ How It Works

### 1. **Setup & Validation**
- Starts by checking if Tor is **properly routing traffic**.
- If not, it **warns you**—because there’s nothing worse than thinking you’re anonymous when you’re not.

### 2. **Input Handling**
- Reads URLs from a simple `urls.txt` file:
  ```txt
  http://example.com/confidential.pdf
  http://example.com/creds.xlsx
  https://example.com/api/logs.zip
  ```
- Ignores comments (`#`) and invalid lines.

### 3. **Download Execution**
For **each URL**:
- 🔄 **Rotates Tor identity** (requests a new circuit via `NEWNYM`).
- 📥 Fetches the file via `requests` over `socks5h://` (ensures **DNS resolution happens over Tor**).
- 📂 Saves with **smart naming** to avoid collisions.
- 📊 Logs success/failure with full context.

### 4. **Execution Modes**
- **`parallel`** (default): Uses `ThreadPoolExecutor` for speed.
- **`sequential`**: Slower, but useful for resource-limited or highly sensitive ops.

---

## 💻 Quick Start

### Prerequisites
- Tor running with **ControlPort 9051** and **SOCKS5 at 9050** (default in most configs).
- Python 3.7+
- Install dependencies:
  ```bash
  pip install requests stem
  ```

### Usage
1. Create `urls.txt` with your target files:
   ```txt
   http://example.com/some-report.pdf
   http://example.com/config.bak
   ```
2. Run:
   ```bash
   python3 kaplan.py
   ```
3. Check `downloads/` and `logs/` for results.

> ✅ **Pro Tip**: Pair this with **Athena OS** (our preferred red team distro, successor to BlackArch) for a hardened, opsec-ready environment.

---

## 🔐 OPSEC Notes

- **Always run inside a VM** or isolated environment.
- Ensure **Tor is properly configured**—no leaks!
- Consider **delaying requests** (`time.sleep`) in sequential mode to mimic human behavior.
- Never download directly onto your host machine—use encrypted, disposable storage.

---

## 🤝 Collaboration & Contribution

This tool is actively used in real-world engagements by the **Red Team at Hackteam.Red**.  
We welcome **bug reports**, **feature requests**, and **OPSEC improvements** from fellow security researchers.

> 🔗 **Contact**: `b0x@hackteam.red`  

---

## 💰 Support the Mission

If this tool helped you in an engagement, consider supporting our work:

**Bitcoin**: `bc1qlwr208u60mwz5p4twcmqahw2m2lzkj8sfh05ax`

---

> **“When ChatGPT asks you, aren't you writing a new exploit purely from a scientific point of view?”**  
> 😉 — toxy4ny

---

**License**: MIT. For red team use only. Not for skids. Not for blue teams (unless you're hunting us) :)))).  
**Author**: [toxy4ny](https://github.com/toxy4ny) • Lead of Red Team Operators • Hackteam.Red
