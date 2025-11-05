#!/usr/bin/env python3
# tor_blue_downloader.py — Blue-team hardened Tor downloader with provenance, quarantine, and optional AV/YARA.
# License: MIT
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import shutil
import signal
import stat
import sys
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, unquote

import requests
from stem import Signal
from stem.control import Controller

# --- Optional deps (auto-detected) -------------------------------------------
with suppress(Exception):
    import magic  # python-magic
with suppress(Exception):
    import yara  # yara-python

# --- Utilities ---------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _rand_jitter(min_s: float, max_s: float) -> float:
    return random.uniform(min_s, max_s)

def _is_root() -> bool:
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def _safe_umask():
    # Files: 640, Dirs: 750
    os.umask(0o027)

def _sanitize_filename(name: str, max_len: int = 150) -> str:
    # Normalize Unicode, strip path separators, collapse whitespace, keep safe charset
    name = unicodedata.normalize("NFKC", name)
    name = name.replace("\\", "_").replace("/", "_").replace("..", "_")
    name = re.sub(r"[\r\n\t]+", "_", name)
    name = re.sub(r"[^\w\-.()+=@ ]", "_", name, flags=re.UNICODE)
    name = re.sub(r"\s+", " ", name).strip()
    return (name[:max_len] or "file")

def _atomic_write(src_tmp: Path, dst_path: Path) -> None:
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src_tmp, dst_path)
    os.sync()

def _hashes_for_file(path: Path, chunk: int = 1 << 20) -> Dict[str, str]:
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h_md5.update(b)
            h_sha1.update(b)
            h_sha256.update(b)
    return {
        "md5": h_md5.hexdigest(),
        "sha1": h_sha1.hexdigest(),
        "sha256": h_sha256.hexdigest(),
    }

# --- Data classes ------------------------------------------------------------

@dataclass
class ScanVerdicts:
    clamav: Optional[str] = None
    yara_matches: Optional[List[str]] = None
    mime_magic: Optional[str] = None
    content_type_header: Optional[str] = None

@dataclass
class Provenance:
    url: str
    requested_at: str
    completed_at: Optional[str]
    tor_exit_ip: Optional[str]
    http_status: Optional[int]
    http_headers: Dict[str, str]
    filename: str
    saved_as: str
    size_bytes: Optional[int]
    hashes: Dict[str, str]
    policy_blocked: bool
    degraded_mode: bool
    error: Optional[str]
    scans: ScanVerdicts
    notes: Optional[str] = None

# --- Main class --------------------------------------------------------------

class TorBlueDownloader:
    def __init__(
        self,
        tor_proxy_port: int = 9050,
        tor_control_port: int = 9051,
        tor_password: Optional[str] = None,
        i2p_proxy: Optional[str] = None,
        out_dir: str = "artifacts",
        quarantine_dir: str = "quarantine",
        log_dir: str = "logs",
        audit_jsonl: str = "logs/audit.jsonl",
        max_workers: int = 3,
        per_host_cap: int = 2,
        max_retries: int = 3,
        retry_base_delay: float = 3.0,
        max_file_mb: int = 1024,  # safety cap
        allow_domains: Optional[List[str]] = None,  # exact hostnames
        deny_tlds: Optional[List[str]] = None,      # e.g., ["zip","mov"]
        enforce_mime_match: bool = True,
        yara_rules_dir: Optional[str] = "yara_rules",
    ):
        if _is_root():
            print("[!] Refusing to run as root. Use an unprivileged account.", file=sys.stderr)
            sys.exit(1)

        _safe_umask()

        self.out_dir = Path(out_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.log_dir = Path(log_dir)
        self.audit_jsonl = Path(audit_jsonl)
        for p in (self.out_dir, self.quarantine_dir, self.log_dir, self.audit_jsonl.parent):
            p.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.per_host_cap = max(1, per_host_cap)
        self.max_retries = max_retries
        self.retry_base_delay = retry_base_delay
        self.max_file_bytes = max_file_mb * 1024 * 1024
        self.allow_domains = set(allow_domains or [])
        self.deny_tlds = set(deny_tlds or [])
        self.enforce_mime_match = enforce_mime_match
        self.yara_rules_dir = Path(yara_rules_dir) if yara_rules_dir else None

        self.tor_control_port = tor_control_port
        self.tor_password = tor_password
        self.i2p_proxy = i2p_proxy
        self.proxies = {
            "http": f"socks5h://127.0.0.1:{tor_proxy_port}",
            "https": f"socks5h://127.0.0.1:{tor_proxy_port}",
        }
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
        }
        self.tor_lock = Lock()
        self.host_counters: Dict[str, int] = {}
        self._init_logging()
        self._load_yara()

    # --- Logging / YARA ------------------------------------------------------

    def _init_logging(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        logfile = self.log_dir / f"download_{ts}.log"
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.FileHandler(logfile, encoding="utf-8"), logging.StreamHandler()],
        )
        self.log = logging.getLogger("TorBlueDownloader")
        self.log.info(f"Log file: {logfile}")

    def _load_yara(self):
        self.yara_rules = None
        if "yara" in sys.modules and self.yara_rules_dir and self.yara_rules_dir.exists():
            try:
                # Compile all .yar/.yara in directory
                rule_files = {
                    p.stem: str(p)
                    for p in self.yara_rules_dir.glob("**/*.yar*")
                }
                if rule_files:
                    self.yara_rules = yara.compile(filepaths=rule_files)
                    self.log.info(f"Loaded YARA rules: {len(rule_files)}")
            except Exception as e:
                self.log.warning(f"YARA load failed: {e}")

    # --- Tor controls --------------------------------------------------------

    def renew_tor_identity(self) -> bool:
        with self.tor_lock:
            try:
                with Controller.from_port(port=self.tor_control_port) as c:
                    # Prefer cookie auth if available; fall back to password if provided
                    try:
                        c.authenticate()
                    except Exception:
                        if self.tor_password:
                            c.authenticate(password=self.tor_password)
                        else:
                            raise
                    c.signal(Signal.NEWNYM)
                    self.log.info("Tor NEWNYM signaled")
                time.sleep(_rand_jitter(3.0, 7.0))  # jitter to allow circuit build
                return True
            except Exception as e:
                self.log.warning(f"Tor NEWNYM failed: {e}")
                return False

    def tor_exit_ip(self) -> Optional[str]:
        try:
            r = requests.get("https://check.torproject.org/api/ip", proxies=self.proxies, timeout=15)
            js = r.json()
            if js.get("IsTor"):
                return js.get("IP")
            return None
        except Exception:
            return None

    # --- Policy gates --------------------------------------------------------

    def _host_allowed(self, host: str) -> bool:
        if self.allow_domains and host not in self.allow_domains:
            return False
        if self.deny_tlds:
            m = re.search(r"\.([A-Za-z0-9]+)$", host)
            if m and m.group(1).lower() in self.deny_tlds:
                return False
        return True

    # --- Download core -------------------------------------------------------

    def _next_filename(self, url: str, resp: requests.Response, custom: Optional[str]) -> str:
        if custom:
            return _sanitize_filename(custom)
        cd = resp.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            m = re.findall(r'filename\*?=(?:UTF-8\'\')?("?)([^";\n]+)\1', cd)
            if m:
                return _sanitize_filename(unquote(m[0][1]))
        parsed = urlparse(url)
        base = _sanitize_filename(unquote(os.path.basename(parsed.path))) or "file"
        return base

    def _mime_from_magic(self, path: Path) -> Optional[str]:
        if "magic" in sys.modules:
            try:
                return magic.from_file(str(path), mime=True)  # type: ignore[attr-defined]
            except Exception:
                return None
        return None

    def _clamav_scan(self, path: Path) -> Optional[str]:
        # Try clamd (fast), then clamscan as fallback
        try:
            import socket  # local import
            import struct
            with socket.create_connection(("127.0.0.1", 3310), timeout=5) as s:
                s.sendall(b"zINSTREAM\0")
                with path.open("rb") as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        s.sendall(struct.pack("!I", len(chunk)) + chunk)
                s.sendall(struct.pack("!I", 0))
                resp = s.recv(4096).decode("utf-8", "replace")
                return resp.strip()
        except Exception:
            pass
        with suppress(Exception):
            import subprocess
            r = subprocess.run(["clamscan", "--no-summary", str(path)], capture_output=True, text=True, timeout=300)
            return r.stdout.strip() or r.stderr.strip()
        return None

    def _yara_scan(self, path: Path) -> Optional[List[str]]:
        if self.yara_rules:
            try:
                m = self.yara_rules.match(str(path))
                if m:
                    return [str(mm.rule) for mm in m]
            except Exception as e:
                self.log.warning(f"YARA scan error: {e}")
        return None

    def _gpg_verify(self, path: Path) -> Optional[str]:
        # If adjacent .asc exists, try to verify (requires gpg)
        asc = path.with_suffix(path.suffix + ".asc")
        if not asc.exists():
            return None
        with suppress(Exception):
            import subprocess
            r = subprocess.run(["gpg", "--verify", str(asc), str(path)],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                return "GPG signature: VALID"
            return f"GPG signature: INVALID ({r.stderr.strip() or r.stdout.strip()})"
        return None

    def _write_sidecar_and_audit(self, prov: Provenance, sidecar_path: Path):
        sidecar_path.write_text(json.dumps(asdict(prov), indent=2, ensure_ascii=False), encoding="utf-8")
        with self.audit_jsonl.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(prov), ensure_ascii=False) + "\n")

    def download_with_retry(self, url: str, custom_filename: Optional[str] = None, network: str = 'tor') -> Tuple[bool, Optional[Path], Optional[str]]:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if not self._host_allowed(host):
            msg = f"Policy block: host {host} not allowed by domain/TLD policy"
            self.log.warning(msg)
            return False, None, msg

        # Per-host concurrency limiter (soft)
        self.host_counters.setdefault(host, 0)
        if self.host_counters[host] >= self.per_host_cap:
            self.log.info(f"Per-host cap reached for {host}; waiting")
            time.sleep(_rand_jitter(0.5, 1.5))

        for attempt in range(1, self.max_retries + 1):
            self.host_counters[host] += 1
            try:
                ok, p, err = self._download_once(url, custom_filename, network)
                if ok:
                    return True, p, None
                raise RuntimeError(err or "unknown error")
            except Exception as e:
                msg = f"Attempt {attempt}/{self.max_retries} failed: {e}"
                self.log.warning(msg)
                if attempt < self.max_retries:
                    delay = self.retry_base_delay * (2 ** (attempt - 1)) + _rand_jitter(0.5, 1.5)
                    # Hygiene: occasional NEWNYM between retries
                    if attempt == 1 or random.random() < 0.5:
                        self.renew_tor_identity()
                    time.sleep(delay)
                else:
                    return False, None, str(e)
            finally:
                self.host_counters[host] = max(0, self.host_counters[host] - 1)

        return False, None, "exhausted"

    def _download_once(self, url: str, custom_filename: Optional[str], network: str) -> Tuple[bool, Optional[Path], Optional[str]]:
        self.log.info(f"Download start: {url} (network: {network})")
        degraded = False
        exit_ip = None

        proxies = None
        if network == 'tor':
            proxies = self.proxies
            exit_ip = self.tor_exit_ip()
            if not exit_ip:
                self.log.warning("Tor check failed; proceeding in degraded mode")
                degraded = True
        elif network == 'i2p':
            if not self.i2p_proxy:
                return False, None, "I2P proxy not configured"
            proxies = {
                'http': self.i2p_proxy,
                'https': self.i2p_proxy,
            }

        s = requests.Session()
        s.headers.update(self.headers)
        if proxies:
            s.proxies.update(proxies)

        # HEAD for size/ETag if possible
        size_limit_ok = True
        content_length = None
        try:
            h = s.head(url, timeout=30, allow_redirects=True)
            if h.ok and h.headers.get("Content-Length"):
                content_length = int(h.headers["Content-Length"])
                if content_length > self.max_file_bytes:
                    return False, None, f"Size {content_length} exceeds cap {self.max_file_bytes}"
        except Exception:
            # Not fatal
            degraded = True

        r = s.get(url, timeout=90, stream=True, allow_redirects=True)
        r.raise_for_status()

        filename = self._next_filename(url, r, custom_filename)
        # Ensure unique
        target = self.quarantine_dir / filename
        base, ext = target.stem, target.suffix
        i = 1
        while target.exists():
            target = self.quarantine_dir / f"{base}_{i}{ext}"
            i += 1

        tmp_dir = self.quarantine_dir / ".tmp"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = tmp_dir / (target.name + ".part")

        total = 0
        with tmp_file.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if not chunk:
                    continue
                f.write(chunk)
                total += len(chunk)
                if total > self.max_file_bytes:
                    f.flush(); os.fsync(f.fileno())
                    tmp_file.unlink(missing_ok=True)
                    return False, None, f"Exceeded size cap {self.max_file_bytes} bytes"

        # Seal file and set perms
        _atomic_write(tmp_file, target)
        os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)  # 640

        # Hashes
        hashes = _hashes_for_file(target)

        # Scans & type checks
        ct_header = r.headers.get("Content-Type")
        mime_magic = self._mime_from_magic(target)
        clam = self._clamav_scan(target)
        yara_hits = self._yara_scan(target)

        scans = ScanVerdicts(
            clamav=clam,
            yara_matches=yara_hits,
            mime_magic=mime_magic,
            content_type_header=ct_header,
        )

        # Policy: MIME mismatch
        policy_blocked = False
        if self.enforce_mime_match and ct_header and mime_magic:
            c_top = ct_header.split(";")[0].strip().lower()
            if not (c_top == mime_magic or c_top.split("/")[0] == mime_magic.split("/")[0]):
                policy_blocked = True
                self.log.warning(f"MIME mismatch header={c_top} magic={mime_magic} -> flagged")

        # Provenance sidecar
        prov = Provenance(
            url=url,
            requested_at=_now_iso(),
            completed_at=_now_iso(),
            tor_exit_ip=exit_ip,
            http_status=r.status_code,
            http_headers={k: v for k, v in r.headers.items()},
            filename=filename,
            saved_as=str(target),
            size_bytes=total,
            hashes=hashes,
            policy_blocked=policy_blocked,
            degraded_mode=degraded,
            error=None,
            scans=scans,
            notes=self._gpg_verify(target),
        )
        sidecar = target.with_suffix(target.suffix + ".json")
        self._write_sidecar_and_audit(prov, sidecar)

        # Done
        self.log.info(f"Saved: {target} ({total} bytes) sha256={hashes['sha256']}")
        if policy_blocked:
            self.log.warning("Artifact flagged by policy (MIME mismatch)")
        return True, target, None

    # --- Public batch methods -----------------------------------------------

    def load_urls(self, file: str = "urls.txt") -> List[str]:
        urls: List[str] = []
        try:
            with open(file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith(("http://", "https://")):
                        urls.append(line)
        except Exception as e:
            self.log.error(f"Failed to read URL file: {e}")
        self.log.info(f"Loaded {len(urls)} URLs")
        return urls

    def download_all_sequential(self, urls: List[str], network: str = 'tor') -> None:
        total = len(urls); ok = 0; fail = 0
        for i, u in enumerate(urls, 1):
            self.log.info(f"[{i}/{total}] {u}")
            success, _, err = self.download_with_retry(u, network=network)
            if success: ok += 1
            else:
                fail += 1
                self.log.error(f"Failed: {u} — {err}")
            if i < total:
                time.sleep(_rand_jitter(1.0, 2.0))
        self._stats(total, ok, fail)

    def download_all_parallel(self, urls: List[str], network: str = 'tor') -> None:
        total = len(urls); ok = 0; fail = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            fut2url = {ex.submit(self.download_with_retry, u, network=network): u for u in urls}
            for i, fut in enumerate(as_completed(fut2url), 1):
                u = fut2url[fut]
                try:
                    success, _, err = fut.result()
                    if success:
                        ok += 1
                        self.log.info(f"[{i}/{total}] ✓ {u}")
                    else:
                        fail += 1
                        self.log.error(f"[{i}/{total}] ✗ {u} — {err}")
                except Exception as e:
                    fail += 1
                    self.log.error(f"[{i}/{total}] exception {u}: {e}")
        self._stats(total, ok, fail)

    def _stats(self, total: int, ok: int, fail: int):
        self.log.info("=" * 60)
        self.log.info("Acquisition complete")
        self.log.info(f"Success: {ok}/{total}  Fail: {fail}/{total}")
        self.log.info(f"Quarantine: {self.quarantine_dir.resolve()}")
        self.log.info(f"Audit JSONL: {self.audit_jsonl.resolve()}")
        self.log.info("=" * 60)


# --- CLI ---------------------------------------------------------------------

def main():
    banner = r"""
.___  ___.   ______    _______  __         _______..______      ___       __   __
|   \/   |  /  __  \  |   ____||  |       /       ||   _  \    /   \     |  | |  |
|  \  /  | |  |  |  | |  |__   |  |      |   (----`|  |_)  |  /  ^  \    |  | |  |
|  |\/|  | |  |  |  | |   __|  |  |       \   \    |   ___/  /  /_\  \   |  | |  |
|  |  |  | |  `--'  | |  |____ |  `----.---)   |   |  |     /  _____  \  |  | |  |
|__|  |__|  \______/  |_______||_______|_______/    |__|    /__/     \__\ |__| |__|
  Tor Blue Downloader v2.0 — Defensive Acquisition Pipeline
"""
    print(banner)

    URLS_FILE = os.environ.get("URLS_FILE", "urls.txt")
    MODE = os.environ.get("MODE", "parallel")  # parallel|sequential
    NETWORK = os.environ.get("NETWORK", "tor") # tor|i2p|clearnet

    d = TorBlueDownloader(
        tor_proxy_port=int(os.environ.get("TOR_PROXY", "9050")),
        tor_control_port=int(os.environ.get("TOR_CTL", "9051")),
        tor_password=os.environ.get("TOR_PASS") or None,
        i2p_proxy=os.environ.get("I2P_PROXY") or None,
        out_dir=os.environ.get("OUT_DIR", "artifacts"),
        quarantine_dir=os.environ.get("QUAR_DIR", "quarantine"),
        log_dir=os.environ.get("LOG_DIR", "logs"),
        audit_jsonl=os.environ.get("AUDIT_LOG", "logs/audit.jsonl"),
        max_workers=int(os.environ.get("MAX_WORKERS", "3")),
        per_host_cap=int(os.environ.get("PER_HOST_CAP", "2")),
        max_retries=int(os.environ.get("MAX_RETRIES", "3")),
        retry_base_delay=float(os.environ.get("RETRY_BASE_DELAY", "3.0")),
        max_file_mb=int(os.environ.get("MAX_FILE_MB", "1024")),
        allow_domains=(os.environ.get("ALLOW_DOMAINS") or "").split(",") if os.environ.get("ALLOW_DOMAINS") else None,
        deny_tlds=(os.environ.get("DENY_TLDS") or "").split(",") if os.environ.get("DENY_TLDS") else None,
        enforce_mime_match=os.environ.get("ENFORCE_MIME", "1") != "0",
        yara_rules_dir=os.environ.get("YARA_DIR", "yara_rules"),
    )

    if NETWORK == 'tor':
        print("[*] Checking Tor…")
        # Soft-check is inside download, but we do an early ping
        if not d.tor_exit_ip():
            print("[!] Could not confirm Tor exit IP; continuing (degraded).")

    urls = d.load_urls(URLS_FILE)
    if not urls:
        print(f"[!] No URLs found in {URLS_FILE}")
        sys.exit(2)

    t0 = time.time()
    try:
        if MODE == "parallel":
            d.download_all_parallel(urls, network=NETWORK)
        else:
            d.download_all_sequential(urls, network=NETWORK)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    finally:
        print(f"[*] Elapsed: {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()
