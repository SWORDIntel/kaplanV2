#!/usr/bin/env python3
# tor_blue_downloader.py — Interactive blue-team acquisition over Tor/I2P with sealing, attestations, cover-traffic,
# egress safeguards, REST server (optional), and stealth hardening.
# License: MIT
from __future__ import annotations

import cmd
import hashlib
import json
import logging
import os
import random
import re
import stat
import subprocess
import sys
import threading
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlsplit, urlunsplit, unquote

import requests
from stem import Signal
from stem.control import Controller

with suppress(Exception):
    import magic
with suppress(Exception):
    import yara
with suppress(Exception):
    import curl_cffi.requests as cffi_requests
with suppress(Exception):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
with suppress(Exception):
    from tpm2_pytss import ESYS_TR, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPMT_PUBLIC, TPM2_ALG, TPM2B_AUTH, TPMT_SYM_DEF_OBJECT, TPM2B_DATA, TSS2_Exception, ESAPI
with suppress(Exception):
    import fastapi, uvicorn
with suppress(Exception):
    import flask

def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()

def _rand_jitter(min_s: float, max_s: float) -> float:
    import random
    return random.uniform(min_s, max_s)

def _is_root() -> bool:
    import os
    return os.geteuid() == 0 if hasattr(os, "geteuid") else False

def _safe_umask():
    import os
    os.umask(0o027)

def _sanitize_filename(name: str, max_len: int = 150) -> str:
    import unicodedata, re
    name = unicodedata.normalize("NFKC", name)
    name = name.replace("\\", "_").replace("/", "_").replace("..", "_")
    name = re.sub(r"[\\r\\n\\t]+", "_", name)
    name = re.sub(r"[^\\w\\-.()+=@ ]", "_", name, flags=re.UNICODE)
    name = re.sub(r"\\s+", " ", name).strip()
    return (name[:max_len] or "file")

def _hashes_for_file(path: Path, chunk: int = 1 << 20) -> Dict[str, str]:
    import hashlib
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
    return {"md5": h_md5.hexdigest(), "sha1": h_sha1.hexdigest(), "sha256": h_sha256.hexdigest()}

def _atomic_write(src_tmp: Path, dst_path: Path) -> None:
    import os
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src_tmp, dst_path)

def _guess_scheme_and_normalize(u: str) -> str:
    import re
    from urllib.parse import urlsplit, urlunsplit
    u = u.strip()
    if not u:
        return u
    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', u):
        return u
    guess = u if u.startswith("//") else "//" + u
    parts = urlsplit(guess, allow_fragments=True)
    host = parts.netloc
    path = parts.path or "/"
    query = parts.query
    frag  = parts.fragment
    port = None
    if ":" in host:
        h, p = host.rsplit(":", 1)
        if p.isdigit():
            port = int(p); host = h
    if host.endswith(".i2p"):
        scheme = "http" if port in (None, 80) else ("https" if port == 443 else "http")
    elif host.endswith(".onion"):
        scheme = "https" if port == 443 else "http"
    else:
        scheme = "https" if (port in (None, 443)) else ("http" if port == 80 else "https")
    netloc = host if port is None else f"{host}:{port}"
    return urlunsplit((scheme, netloc, path, query, frag))

from dataclasses import dataclass
from typing import Optional, List, Dict

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
    transport: Optional[str] = None
    tls_fingerprint_mode: Optional[str] = None
    headers_used: Optional[Dict[str, str]] = None
    is_cover: Optional[bool] = None
    enc_enabled: Optional[bool] = None
    enc_alg: Optional[str] = None
    enc_nonce_b64: Optional[str] = None
    enc_wrapped_key: Optional[str] = None
    enc_wrap_method: Optional[str] = None
    manifest_path: Optional[str] = None
    signature_path: Optional[str] = None

from enum import Enum
class Transport(str, Enum):
    TOR = "tor"
    I2P = "i2p"
    DIRECT = "direct"
    CUSTOM = "custom"

_HEADER_UA_POOL = [
    ("win", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
    ("linux", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"),
    ("mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15"),
]
_ACCEPT_LANGUAGE_POOL = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en-GB;q=0.8,en;q=0.7"]
_ACCEPT_ENCODING_POOL = ["gzip, deflate, br", "gzip, deflate", "br, gzip, deflate"]

def _rotated_headers(base: Dict[str, str], level: int, persona: Optional[str]) -> Dict[str, str]:
    import random
    h = dict(base)
    if level >= 1:
        ualist = [ua for p, ua in _HEADER_UA_POOL if not persona or p == persona]
        if not ualist:
            ualist = [ua for _, ua in _HEADER_UA_POOL]
        h["User-Agent"] = random.choice(ualist)
        h["Accept-Language"] = random.choice(_ACCEPT_LANGUAGE_POOL)
    if level >= 2:
        h["Accept-Encoding"] = random.choice(_ACCEPT_ENCODING_POOL)
        h["Connection"] = "close" if random.random() < 0.6 else "keep-alive"
    if level >= 3:
        h.setdefault("Sec-Fetch-Site", "none")
        h.setdefault("Sec-Fetch-Mode", "navigate")
        h.setdefault("Sec-Fetch-Dest", "document")
    return h

class TokenBucket:
    def __init__(self, rate_per_sec: float, burst: float):
        import time
        self.rate = max(0.0, rate_per_sec)
        self.capacity = max(burst, rate_per_sec)
        self.tokens = self.capacity
        self.ts = time.monotonic()
        self.lock = Lock()
    def take(self, cost: float = 1.0):
        import time
        with self.lock:
            now = time.monotonic()
            delta = now - self.ts
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            while self.tokens < cost:
                wait = (cost - self.tokens) / self.rate if self.rate > 0 else 0.5
                time.sleep(min(0.5, max(0.01, wait)))
                now2 = time.monotonic()
                delta2 = now2 - self.ts
                self.ts = now2
                self.tokens = min(self.capacity, self.tokens + delta2 * self.rate)
            self.tokens -= cost

class TransportManager:
    def __init__(
        self,
        transport: Transport,
        tor_socks_port: int = 9050,
        i2p_http_proxy: str = "http://127.0.0.1:4444",
        i2p_socks_proxy: str = "socks5h://127.0.0.1:4447",
        custom_http_proxy: Optional[str] = None,
        custom_socks_proxy: Optional[str] = None,
        base_headers: Optional[Dict[str, str]] = None,
        obfuscation_level: int = 1,
        tls_client_mode: str = "auto",
        isolate_sessions: bool = True,
        disable_keepalive: bool = False,
        persona: Optional[str] = None,
    ):
        self.transport = transport
        self.tor_socks_port = tor_socks_port
        self.i2p_http_proxy = i2p_http_proxy
        self.i2p_socks_proxy = i2p_socks_proxy
        self.custom_http_proxy = custom_http_proxy
        self.custom_socks_proxy = custom_socks_proxy
        self.base_headers = base_headers or {}
        self.level = max(0, min(3, obfuscation_level))
        self.tls_client_mode = tls_client_mode
        self.isolate_sessions = isolate_sessions
        self.disable_keepalive = disable_keepalive
        self.persona = persona
        self._sticky_session = None

    def _mk_proxies(self) -> Dict[str, str]:
        if self.transport == Transport.TOR:
            sp = f"socks5h://127.0.0.1:{self.tor_socks_port}"
            return {"http": sp, "https": sp}
        if self.transport == Transport.I2P:
            return {"http": self.i2p_http_proxy, "https": self.i2p_http_proxy}
        if self.transport == Transport.CUSTOM:
            proxies = {}
            if self.custom_http_proxy:
                proxies["http"] = self.custom_http_proxy
                proxies["https"] = self.custom_http_proxy
            if self.custom_socks_proxy:
                proxies["http"] = self.custom_socks_proxy
                proxies["https"] = self.custom_socks_proxy
            return proxies
        return {}

    def _new_requests_impl(self):
        if self.tls_client_mode == "chrome" and "cffi_requests" in globals():
            return cffi_requests.Session()
        return requests.Session()

    def session(self):
        if not self.isolate_sessions:
            if self._sticky_session is None:
                self._sticky_session = self._build_session()
            return self._sticky_session
        return self._build_session()

    def _build_session(self):
        s = self._new_requests_impl()
        s.headers.update(_rotated_headers(self.base_headers, self.level, self.persona))
        proxies = self._mk_proxies()
        if proxies:
            s.proxies.update(proxies)
        if self.disable_keepalive:
            s.headers["Connection"] = "close"
        return s

class CoverTrafficManager:
    def __init__(self, transport_mgr: TransportManager, log: logging.Logger):
        self.tm = transport_mgr
        self.log = log
        self.enable = os.environ.get("COVER_ENABLE", "0") == "1"
        self.domains = [d.strip() for d in (os.environ.get("COVER_DOMAINS","").split(",") if os.environ.get("COVER_DOMAINS") else [])]
        self.min_iv = int(os.environ.get("COVER_MIN_INTERVAL","12"))
        self.max_iv = int(os.environ.get("COVER_MAX_INTERVAL","45"))
        self.methods = [m.strip().upper() for m in os.environ.get("COVER_METHODS","GET,HEAD").split(",")]
        self.paths = [p.strip() for p in os.environ.get("COVER_PATHS","/").split(",")]
        self._stop = threading.Event()
        self._thr = None

    def _loop(self):
        self.log.info("CoverTraffic: loop started (enable=%s)", self.enable)
        while not self._stop.is_set():
            if not self.enable or not self.domains:
                time.sleep(1.0); continue
            try:
                import random
                dom = random.choice(self.domains)
                path = random.choice(self.paths) or "/"
                meth = random.choice(self.methods)
                url = f"https://{dom}{path if path.startswith('/') else '/' + path}"
                s = self.tm.session()
                hdrs = dict(s.headers)
                self.log.info(f"CoverTraffic: method={meth} url={url} cover=true tls_client={getattr(self.tm,'tls_client_mode','auto')} ua={hdrs.get('User-Agent')}")
                if meth == "HEAD":
                    s.head(url, timeout=15, allow_redirects=True)
                else:
                    s.get(url, timeout=20, allow_redirects=True, stream=False)
            except Exception as e:
                self.log.debug(f"CoverTraffic: error: {e}")
            time.sleep(_rand_jitter(self.min_iv, self.max_iv))

    def start(self):
        if self._thr is None:
            self._stop.clear()
            self._thr = threading.Thread(target=self._loop, name="cover-traffic", daemon=True)
            self._thr.start()

    def stop(self):
        if self._thr:
            self._stop.set()
            self._thr.join(timeout=3)
            self._thr = None

    def set_enabled(self, enabled: bool):
        self.enable = enabled

class XDPEgressManager:
    def __init__(self, log: logging.Logger):
        self.log = log
        self.enabled = os.environ.get("XDP_ATTACH","0") == "1"
        self.iface = os.environ.get("XDP_IFACE","eth0")
        self.mode = os.environ.get("XDP_ATTACH_MODE","tc").lower()
        self.obj = os.environ.get("XDP_OBJECT") or ""
        self.sec = os.environ.get("XDP_SECTION","classifier")
        self.attached = False

    def _run(self, args: List[str]) -> Tuple[int,str,str]:
        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=10)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except Exception as e:
            return 127, "", str(e)

    def attach(self):
        if not self.enabled or self.attached:
            return
        if not self.obj or not Path(self.obj).exists():
            self.log.warning("XDP/tc: object missing; skip"); return
        if self.mode == "tc":
            rc, out, err = self._run(["tc","qdisc","add","dev", self.iface,"clsact"])
            if rc != 0 and "File exists" not in err:
                self.log.warning(f"tc clsact add failed: {err or out}")
            rc, out, err = self._run(["tc","filter","add","dev", self.iface,"egress","bpf","da","obj", self.obj,"sec", self.sec])
            if rc == 0:
                self.attached = True
                self.log.info("tc egress BPF attached: iface=%s obj=%s sec=%s", self.iface, self.obj, self.sec)
            else:
                self.log.warning(f"tc egress attach failed: {err or out}")
        else:
            rc, out, err = self._run(["ip","link","set","dev", self.iface,"xdpgeneric","obj", self.obj,"sec", self.sec])
            if rc == 0:
                self.attached = True
                self.log.info("XDP (generic) attached: iface=%s obj=%s sec=%s", self.iface, self.obj, self.sec)
            else:
                self.log.warning(f"XDP attach failed: {err or out}")

    def detach(self):
        if not self.attached:
            return
        if self.mode == "tc":
            rc, out, err = self._run(["tc","filter","del","dev", self.iface,"egress"])
            if rc != 0 and "No such file or directory" not in err:
                self.log.warning(f"tc egress detach warn: {err or out}")
        else:
            rc, out, err = self._run(["ip","link","set","dev", self.iface,"xdpgeneric","off"])
            if rc != 0:
                self.log.warning(f"XDP detach warn: {err or out}")
        self.attached = False
        self.log.info("Egress hook detached")

class KeyWrapMethod(str, Enum):
    NONE = "none"
    PASS = "pass"
    RSA = "rsa"
    TPM_SEAL = "tpm_seal"

class SealingManager:
    def __init__(self, log: logging.Logger):
        self.log = log
        self.enable = os.environ.get("ENC_ENABLE","0") == "1"
        self.wrap = KeyWrapMethod(os.environ.get("ENC_WRAP","pass").lower())
        self.passphrase = os.environ.get("ENC_PASS") or None
        self.rsa_pub_pem = os.environ.get("ENC_PUBKEY_PEM") or None
        self.alg = "AES-256-GCM"
        self.worm = os.environ.get("WORM","0") == "1"
        self.sign_enable = os.environ.get("SIGN_ENABLE","0") == "1"
        self.sign_key_pem = os.environ.get("SIGN_KEY_PEM") or None
        self.sign_alg = os.environ.get("SIGN_ALG","ed25519").lower()
        self.enc_dir = os.environ.get("ENC_DIR", "sealed")
        Path(self.enc_dir).mkdir(parents=True, exist_ok=True)

    def _derive_kek(self, passphrase: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
        return kdf.derive(passphrase.encode("utf-8"))

    def wrap_key(self, dek: bytes) -> Tuple[str, str]:
        if not self.enable:
            return (KeyWrapMethod.NONE.value, "")
        try:
            if self.wrap == KeyWrapMethod.PASS:
                import os
                salt = os.urandom(16)
                kek = self._derive_kek(self.passphrase or "changeme", salt)
                nonce = os.urandom(12)
                aes = AESGCM(kek)
                ct = aes.encrypt(nonce, dek, b"wrap")
                return ("pass", (salt + nonce + ct).hex())
            elif self.wrap == KeyWrapMethod.RSA and self.rsa_pub_pem and 'serialization' in globals():
                pub = serialization.load_pem_public_key(Path(self.rsa_pub_pem).read_bytes())
                ct = pub.encrypt(dek, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                return ("rsa", ct.hex())
            elif self.wrap == KeyWrapMethod.TPM_SEAL and "ESAPI" in globals():
                try:
                    esys = ESAPI()
                    sens = TPM2B_SENSITIVE_CREATE()
                    sens.sensitive.data = dek
                    pub = TPM2B_PUBLIC()
                    pub.publicArea.type = TPM2_ALG.KEYEDHASH
                    pub.publicArea.nameAlg = TPM2_ALG.SHA256
                    pub.publicArea.objectAttributes = (1<<10) | (1<<4) | (1<<5)
                    pub.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG.NULL
                    outPriv, outPub = esys.Create(ESYS_TR.RH_OWNER, TPM2B_AUTH(), sens, pub, TPM2B_DATA(), TPMT_SYM_DEF_OBJECT(TPM2_ALG.NULL,0,TPM2_ALG.NULL))
                    blob = outPriv.buffer + outPub.buffer
                    return ("tpm_seal", blob.hex())
                except Exception as e:
                    self.log.warning(f"TPM seal failed, fallback to PASS: {e}")
                    self.wrap = KeyWrapMethod.PASS
                    return self.wrap_key(dek)
            else:
                return ("none", "")
        except Exception as e:
            self.log.warning(f"Key wrap error, disabling encryption: {e}")
            self.enable = False
            return ("none","")

    def encrypt_file(self, src: Path) -> Tuple[Optional[Path], Optional[str], Optional[str]]:
        if not self.enable or "AESGCM" not in globals():
            return None, None, None
        try:
            import os
            dek = os.urandom(32)
            nonce = os.urandom(12)
            data = src.read_bytes()
            aes = AESGCM(dek)
            ct = aes.encrypt(nonce, data, b"file")
            enc_path = Path(self.enc_dir) / (src.name + ".enc")
            enc_path.write_bytes(ct)
            wrap_method, wrapped = self.wrap_key(dek)
            if self.worm:
                self._make_immutable(enc_path)
            return enc_path, nonce.hex(), (wrapped or "")
        except Exception as e:
            self.log.warning(f"Encryption failed (soft-continue): {e}")
            return None, None, None

    def _make_immutable(self, path: Path):
        with suppress(Exception):
            import sys, os, subprocess, stat
            if sys.platform.startswith("linux"):
                subprocess.run(["chattr"," +i", str(path)], check=False)
            else:
                os.chmod(path, stat.S_IREAD)

    def merkle_and_sign(self, files: List[Path]) -> Tuple[Optional[Path], Optional[Path]]:
        try:
            import hashlib, time, json
            leaves = []
            for p in files:
                h = hashlib.sha256(p.read_bytes()).hexdigest()
                leaves.append({"path": str(p), "sha256": h})
            root = hashlib.sha256(("".join(l["sha256"] for l in leaves)).encode()).hexdigest()
            manifest = {"created": _now_iso(), "root_sha256": root, "leaves": leaves, "alg": "SHA-256"}
            man_path = Path(self.enc_dir) / f"manifest_{int(time.time())}.json"
            man_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            sig_path = None
            if self.sign_enable and 'serialization' in globals():
                key_data = Path(self.sign_key_pem).read_bytes() if self.sign_key_pem else None
                if self.sign_alg == "ed25519" and key_data:
                    if b"BEGIN" in key_data:
                        sk = serialization.load_pem_private_key(key_data, password=None)
                    else:
                        sk = ed25519.Ed25519PrivateKey.from_private_bytes(key_data)
                    sig = sk.sign(json.dumps(manifest, sort_keys=True).encode())
                    sig_path = man_path.with_suffix(".sig"); sig_path.write_bytes(sig)
                elif self.sign_alg == "rsa" and key_data:
                    sk = serialization.load_pem_private_key(key_data, password=None)
                    sig = sk.sign(json.dumps(manifest, sort_keys=True).encode(),
                                  padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                                  hashes.SHA256())
                    sig_path = man_path.with_suffix(".sig"); sig_path.write_bytes(sig)
            if self.worm:
                self._make_immutable(man_path); 
                if sig_path: self._make_immutable(sig_path)
            return man_path, sig_path
        except Exception as e:
            self.log.warning(f"Manifest/sign failed: {e}")
            return None, None

class TorBlueDownloader:
    def __init__(
        self,
        tor_proxy_port: int = 9050,
        tor_control_port: int = 9051,
        tor_password: Optional[str] = None,
        out_dir: str = "artifacts",
        quarantine_dir: str = "quarantine",
        log_dir: str = "logs",
        audit_jsonl: str = "logs/audit.jsonl",
        max_workers: int = 3,
        per_host_cap: int = 2,
        max_retries: int = 3,
        retry_base_delay: float = 3.0,
        max_file_mb: int = 1024,
        allow_domains: Optional[List[str]] = None,
        deny_tlds: Optional[List[str]] = None,
        enforce_mime_match: bool = True,
        yara_rules_dir: Optional[str] = "yara_rules",
    ):
        if _is_root():
            print("[!] Refusing to run as root. Use an unprivileged account.", file=sys.stderr)
            sys.exit(1)

        _safe_umask()
        self.out_dir = Path(out_dir); self.out_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir = Path(quarantine_dir); self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir = Path(log_dir); self.log_dir.mkdir(parents=True, exist_ok=True)
        self.audit_jsonl = Path(audit_jsonl); self.audit_jsonl.parent.mkdir(parents=True, exist_ok=True)

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

        self.headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"}
        self.tor_lock = Lock()
        self.host_counters: Dict[str, int] = {}
        self.egress_bytes: Dict[str, int] = {}
        self.egress_flows: Dict[str, int] = {}
        self.per_host_rate = float(os.environ.get("PER_HOST_RPS","0.0"))
        self.per_host_bps  = float(os.environ.get("PER_HOST_BPS","0.0"))
        self.buckets_req: Dict[str, TokenBucket] = {}
        self.buckets_bps: Dict[str, TokenBucket] = {}

        self._init_logging()
        self._load_yara()

        self.transport = Transport(os.environ.get("TRANSPORT", "tor").lower())
        self.obfuscation_level = int(os.environ.get("OBFUSCATION_LEVEL", "1"))
        self.isolate_sessions = os.environ.get("ISOLATE_SESSIONS", "1") != "0"
        self.disable_keepalive = os.environ.get("DISABLE_KEEPALIVE", "0") == "1"
        self.tls_client_mode = os.environ.get("TLS_CLIENT", "auto")
        self.custom_http_proxy = os.environ.get("HTTP_PROXY") or None
        self.custom_socks_proxy = os.environ.get("SOCKS_PROXY") or None
        self.persona = os.environ.get("PERSONA") or None

        self.transport_mgr = TransportManager(
            transport=self.transport,
            tor_socks_port=tor_proxy_port,
            i2p_http_proxy=os.environ.get("I2P_HTTP_PROXY", "http://127.0.0.1:4444"),
            i2p_socks_proxy=os.environ.get("I2P_SOCKS_PROXY", "socks5h://127.0.0.1:4447"),
            custom_http_proxy=self.custom_http_proxy,
            custom_socks_proxy=self.custom_socks_proxy,
            base_headers=self.headers,
            obfuscation_level=self.obfuscation_level,
            tls_client_mode=self.tls_client_mode,
            isolate_sessions=self.isolate_sessions,
            disable_keepalive=self.disable_keepalive,
            persona=self.persona,
        )

        self.cover_mgr = CoverTrafficManager(self.transport_mgr, self.log)
        self.xdp_mgr = XDPEgressManager(self.log)
        self.seal_mgr = SealingManager(self.log)

    def _init_logging(self):
        from datetime import datetime
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
                rule_files = {p.stem: str(p) for p in self.yara_rules_dir.glob("**/*.yar*")}
                if rule_files:
                    self.yara_rules = yara.compile(filepaths=rule_files)
                    self.log.info(f"Loaded YARA rules: {len(rule_files)}")
            except Exception as e:
                self.log.warning(f"YARA load failed: {e}")

    def renew_tor_identity(self) -> bool:
        if self.transport != Transport.TOR:
            self.log.info("NEWNYM skipped (transport != tor)")
            return False
        with self.tor_lock:
            try:
                with Controller.from_port(port=self.tor_control_port) as c:
                    try:
                        c.authenticate()
                    except Exception:
                        if self.tor_password:
                            c.authenticate(password=self.tor_password)
                        else:
                            raise
                    c.signal(Signal.NEWNYM)
                    self.log.info("Tor NEWNYM signaled")
                time.sleep(_rand_jitter(3.0, 7.0))
                return True
            except Exception as e:
                self.log.warning(f"Tor NEWNYM failed: {e}")
                return False

    def tor_exit_ip(self) -> Optional[str]:
        if self.transport != Transport.TOR:
            return None
        try:
            sp = f"socks5h://127.0.0.1:{os.environ.get('TOR_PROXY','9050')}"
            r = requests.get("https://check.torproject.org/api/ip", proxies={"http": sp, "https": sp}, timeout=15)
            js = r.json()
            return js.get("IP") if js.get("IsTor") else None
        except Exception:
            return None

    def _host_allowed(self, host: str) -> bool:
        if self.allow_domains and host not in self.allow_domains:
            return False
        if self.deny_tlds:
            m = re.search(r"\.([A-Za-z0-9]+)$", host)
            if m and m.group(1).lower() in self.deny_tlds:
                return False
        if self.transport == Transport.I2P and not host.endswith(".i2p"):
            self.log.warning("Non-.i2p host over I2P transport; review policy")
        return True

    def _bucket_for(self, host: str):
        if self.per_host_rate > 0 and host not in self.buckets_req:
            self.buckets_req[host] = TokenBucket(self.per_host_rate, self.per_host_rate)
        if self.per_host_bps > 0 and host not in self.buckets_bps:
            self.buckets_bps[host] = TokenBucket(self.per_host_bps, self.per_host_bps)

    def _egress_count(self, host: str, bytes_n: int):
        self.egress_bytes[host] = self.egress_bytes.get(host, 0) + bytes_n

    def _next_filename(self, url: str, resp: requests.Response, custom: Optional[str]) -> str:
        if custom:
            return _sanitize_filename(custom)
        cd = resp.headers.get("Content-Disposition", "")
        if "filename=" in cd:
            m = re.findall(r'filename\*?=(?:UTF-8\'\')?("?)([^\";\\n]+)\\1', cd)
            if m:
                return _sanitize_filename(unquote(m[0][1]))
        parsed = urlparse(url)
        base = _sanitize_filename(unquote(os.path.basename(parsed.path))) or "file"
        return base

    def _mime_from_magic(self, path: Path) -> Optional[str]:
        if "magic" in sys.modules:
            try:
                return magic.from_file(str(path), mime=True)
            except Exception:
                return None
        return None

    def _clamav_scan(self, path: Path) -> Optional[str]:
        try:
            import socket, struct
            with socket.create_connection(("127.0.0.1", 3310), timeout=5) as s:
                s.sendall(b"zINSTREAM\\0")
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
        asc = path.with_suffix(path.suffix + ".asc")
        if not asc.exists():
            return None
        with suppress(Exception):
            r = subprocess.run(["gpg", "--verify", str(asc), str(path)],
                               capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                return "GPG signature: VALID"
            return f"GPG signature: INVALID ({r.stderr.strip() or r.stdout.strip()})"
        return None

    def _write_sidecar_and_audit(self, prov: Provenance, sidecar_path: Path):
        sidecar_path.write_text(json.dumps(asdict(prov), indent=2, ensure_ascii=False), encoding="utf-8")
        with self.audit_jsonl.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(prov), ensure_ascii=False) + "\\n")

    def download_with_retry(self, url: str, custom_filename: Optional[str] = None) -> Tuple[bool, Optional[Path], Optional[str]]:
        url = _guess_scheme_and_normalize(url)
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        if not self._host_allowed(host):
            msg = f"Policy block: host {host} not allowed by domain/TLD policy"
            self.log.warning(msg)
            return False, None, msg

        self._bucket_for(host)

        self.host_counters.setdefault(host, 0)
        if self.host_counters[host] >= self.per_host_cap:
            self.log.info(f"Per-host cap reached for {host}; waiting")
            time.sleep(_rand_jitter(0.5, 1.5))

        for attempt in range(1, self.max_retries + 1):
            self.host_counters[host] += 1
            try:
                if host in self.buckets_req:
                    self.buckets_req[host].take(1.0)
                ok, p, err = self._download_once(url, custom_filename, host)
                if ok:
                    self.egress_flows[host] = self.egress_flows.get(host, 0) + 1
                    return True, p, None
                raise RuntimeError(err or "unknown error")
            except Exception as e:
                msg = f"Attempt {attempt}/{self.max_retries} failed: {e}"
                self.log.warning(msg)
                if attempt < self.max_retries:
                    delay = self.retry_base_delay * (2 ** (attempt - 1)) + _rand_jitter(0.5, 1.5)
                    if self.transport == Transport.TOR and (attempt == 1 or random.random() < 0.5):
                        self.renew_tor_identity()
                    time.sleep(delay)
                else:
                    return False, None, str(e)
            finally:
                self.host_counters[host] = max(0, self.host_counters[host] - 1)
        return False, None, "exhausted"

    def _download_once(self, url: str, custom_filename: Optional[str], host: str) -> Tuple[bool, Optional[Path], Optional[str]]:
        self.log.info(f"Download start: {url}")
        degraded = False
        exit_ip = self.tor_exit_ip() if self.transport == Transport.TOR else None
        if self.transport == Transport.TOR and not exit_ip:
            self.log.warning("Tor check failed; proceeding in degraded mode")
            degraded = True

        s = self.transport_mgr.session()

        content_length = None
        try:
            h = s.head(url, timeout=30, allow_redirects=True)
            if getattr(h, "ok", False) and h.headers.get("Content-Length"):
                content_length = int(h.headers["Content-Length"])
                if content_length > self.max_file_bytes:
                    return False, None, f"Size {content_length} exceeds cap {self.max_file_bytes}"
        except Exception:
            degraded = True

        r = s.get(url, timeout=90, stream=True, allow_redirects=True)
        r.raise_for_status()

        filename = self._next_filename(url, r, custom_filename)
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
                bytes_n = len(chunk)
                total += bytes_n
                if host in self.buckets_bps:
                    self.buckets_bps[host].take(bytes_n)
                if total > self.max_file_bytes:
                    f.flush(); os.fsync(f.fileno())
                    tmp_file.unlink(missing_ok=True)
                    return False, None, f"Exceeded size cap {self.max_file_bytes} bytes"
                self._egress_count(host, bytes_n)

        _atomic_write(tmp_file, target)
        with suppress(Exception):
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)

        hashes = _hashes_for_file(target)

        ct_header = r.headers.get("Content-Type")
        mime_magic = self._mime_from_magic(target)
        clam = self._clamav_scan(target)
        yara_hits = self._yara_scan(target)

        scans = ScanVerdicts(
            clamav=clam, yara_matches=yara_hits, mime_magic=mime_magic, content_type_header=ct_header
        )

        policy_blocked = False
        if self.enforce_mime_match and ct_header and mime_magic:
            c_top = ct_header.split(";")[0].strip().lower()
            try:
                mm_top = mime_magic.split(";")[0].strip().lower()
            except Exception:
                mm_top = mime_magic
            if not (c_top == mm_top or c_top.split("/")[0] == mm_top.split("/")[0]):
                policy_blocked = True
                self.log.warning(f"MIME mismatch header={c_top} magic={mime_magic} -> flagged")

        enc_path, nonce_hex, wrapped_hex = self.seal_mgr.encrypt_file(target)
        manifest_path, sig_path = (None, None)
        if enc_path:
            manifest_path, sig_path = self.seal_mgr.merkle_and_sign([target, enc_path, target.with_suffix(target.suffix + ".json")])

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
            transport=self.transport.value,
            tls_fingerprint_mode=self.tls_client_mode,
            headers_used=dict(s.headers),
            is_cover=False,
            enc_enabled=self.seal_mgr.enable,
            enc_alg=self.seal_mgr.alg if self.seal_mgr.enable else None,
            enc_nonce_b64=nonce_hex,
            enc_wrapped_key=wrapped_hex,
            enc_wrap_method=self.seal_mgr.wrap.value if self.seal_mgr.enable else None,
            manifest_path=str(manifest_path) if manifest_path else None,
            signature_path=str(sig_path) if sig_path else None,
        )
        sidecar = target.with_suffix(target.suffix + ".json")
        self._write_sidecar_and_audit(prov, sidecar)
        if self.seal_mgr.worm:
            with suppress(Exception):
                if sys.platform.startswith("linux"):
                    subprocess.run(["chattr"," +i", str(target), str(sidecar)], check=False)
                else:
                    os.chmod(target, stat.S_IREAD); os.chmod(sidecar, stat.S_IREAD)

        self.log.info(f"Saved: {target} ({total} bytes) sha256={hashes['sha256']}")
        if policy_blocked:
            self.log.warning("Artifact flagged by policy (MIME mismatch)")
        return True, target, None

    def load_urls(self, file: str = "urls.txt") -> List[str]:
        urls: List[str] = []
        try:
            with open(file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', line):
                        line = _guess_scheme_and_normalize(line)
                    urls.append(line)
        except Exception as e:
            self.log.error(f"Failed to read URL file: {e}")
        self.log.info(f"Loaded {len(urls)} URLs")
        return urls

    def download_all_sequential(self, urls: List[str]) -> None:
        total = len(urls); ok = 0; fail = 0
        for i, u in enumerate(urls, 1):
            self.log.info(f"[{i}/{total}] {u}")
            success, _, err = self.download_with_retry(u)
            if success: ok += 1
            else:
                fail += 1
                self.log.error(f"Failed: {u} — {err}")
            if i < total:
                time.sleep(_rand_jitter(1.0, 2.0))
        self._stats(total, ok, fail)

    def download_all_parallel(self, urls: List[str]) -> None:
        total = len(urls); ok = 0; fail = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            fut2url = {ex.submit(self.download_with_retry, u): u for u in urls}
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

class DownloaderShell(cmd.Cmd):
    intro = "Tor Blue Downloader — interactive mode. Type help or ? to list commands.\\n"
    prompt = "(tbd) "

    def __init__(self, downloader: TorBlueDownloader):
        super().__init__()
        self.d = downloader
        self.urls: List[str] = []

    def do_add(self, arg):
        "add <URL>  — enqueue a URL"
        url = arg.strip()
        if url:
            import re
            self.urls.append(url if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url) else _guess_scheme_and_normalize(url))
            print(f"[+] queued: {self.urls[-1]}")
        else:
            print("Usage: add https://… | host/path")

    def do_load(self, arg):
        "load <file> — load URLs from a file (default urls.txt)"
        fp = arg.strip() or "urls.txt"
        self.urls.extend(self.d.load_urls(fp))
        print(f"[+] queue size: {len(self.urls)}")

    def do_run(self, arg):
        "run [parallel|sequential] — start queued downloads"
        mode = (arg.strip() or os.environ.get("MODE","parallel")).lower()
        if not self.urls:
            print("No queued URLs. Use add/load.")
            return
        t0 = time.time()
        if mode == "sequential":
            self.d.download_all_sequential(self.urls)
        else:
            self.d.download_all_parallel(self.urls)
        print(f"Done. Elapsed {time.time()-t0:.2f}s")

    def do_status(self, arg):
        "status — print current config"
        print(f"transport={self.d.transport.value} tls_client={self.d.tls_client_mode} persona={self.d.persona} obf={self.d.obfuscation_level}")
        print(f"per_host_cap={self.d.per_host_cap} max_workers={self.d.max_workers} rate={self.d.per_host_rate}/s bps={self.d.per_host_bps}")
        print(f"cover_enabled={self.d.cover_mgr.enable} xdp_attached={self.d.xdp_mgr.attached} xdp_mode={self.d.xdp_mgr.mode}")
        print(f"encryption={'on' if self.d.seal_mgr.enable else 'off'} wrap={self.d.seal_mgr.wrap.value} sign={'on' if self.d.seal_mgr.sign_enable else 'off'} worm={'on' if self.d.seal_mgr.worm else 'off'}")

    def do_netstat(self, arg):
        "netstat — show egress telemetry"
        print("Host                         flows     bytes")
        for h in sorted(self.d.egress_bytes.keys()):
            print(f"{h:28} {self.d.egress_flows.get(h,0):5d}  {self.d.egress_bytes[h]:>10d}")

    def do_renew(self, arg):
        "renew — force Tor NEWNYM"
        ok = self.d.renew_tor_identity()
        print("NEWNYM: " + ("ok" if ok else "skipped/failed"))

    def do_cover(self, arg):
        "cover on|off — toggle cover traffic"
        v = arg.strip().lower()
        if v in ("on","1","true"):
            self.d.cover_mgr.set_enabled(True); print("cover: on")
        elif v in ("off","0","false"):
            self.d.cover_mgr.set_enabled(False); print("cover: off")
        else:
            print(f"cover is {'on' if self.d.cover_mgr.enable else 'off'}")

    def do_xdp(self, arg):
        "xdp attach|detach — manage egress hook"
        v = arg.strip().lower()
        if v == "attach":
            self.d.xdp_mgr.attach()
        elif v == "detach":
            self.d.xdp_mgr.detach()
        else:
            print(f"xdp attached={self.d.xdp_mgr.attached} mode={self.d.xdp_mgr.mode} iface={self.d.xdp_mgr.iface}")

    def do_quit(self, arg):
        "quit — exit"
        return True
    do_q = do_quit
    do_exit = do_quit

class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELED = "canceled"

class JobQueue:
    def __init__(self, downloader: TorBlueDownloader):
        self.d = downloader
        self.jobs: Dict[str, Dict] = {}
        self.lock = Lock()
        self.pool = ThreadPoolExecutor(max_workers=self.d.max_workers)

    def submit(self, urls: List[str]) -> str:
        import random, time
        jid = f"job-{int(time.time()*1000)}-{random.randint(1000,9999)}"
        with self.lock:
            self.jobs[jid] = {"id": jid, "state": JobState.PENDING, "urls": urls, "ok": 0, "fail": 0, "err": None}
        def run():
            with self.lock:
                self.jobs[jid]["state"] = JobState.RUNNING
            try:
                for u in urls:
                    ok, _, err = self.d.download_with_retry(u)
                    with self.lock:
                        if ok: self.jobs[jid]["ok"] += 1
                        else:
                            self.jobs[jid]["fail"] += 1
                            self.jobs[jid]["err"] = err
                with self.lock:
                    self.jobs[jid]["state"] = JobState.DONE
            except Exception as e:
                with self.lock:
                    self.jobs[jid]["state"] = JobState.ERROR
                    self.jobs[jid]["err"] = str(e)
        self.pool.submit(run)
        return jid

    def list(self):
        with self.lock:
            return list(self.jobs.values())

    def get(self, jid: str):
        with self.lock:
            return self.jobs.get(jid)

    def cancel(self, jid: str):
        with self.lock:
            if jid in self.jobs:
                self.jobs[jid]["state"] = JobState.CANCELED
                return True
        return False

def maybe_start_rest_server(d: TorBlueDownloader):
    if os.environ.get("SERVER","0") != "1":
        return
    jq = JobQueue(d)
    if "fastapi" in globals() and "uvicorn" in globals():
        app = fastapi.FastAPI(title="Tor Blue Downloader API")
        @app.post("/jobs")
        def submit(payload: Dict):
            urls = payload.get("urls") or []
            urls = [u if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', u) else _guess_scheme_and_normalize(u) for u in urls]
            return {"id": jq.submit(urls)}
        @app.get("/jobs")
        def list_jobs(): return jq.list()
        @app.get("/jobs/{jid}")
        def get_job(jid: str): return jq.get(jid) or fastapi.responses.JSONResponse({"error":"not found"}, status_code=404)
        @app.post("/jobs/{jid}/cancel")
        def cancel_job(jid: str): return {"ok": jq.cancel(jid)}
        @app.get("/telemetry")
        def telemetry():
            return {"bytes": d.egress_bytes, "flows": d.egress_flows}
        host = os.environ.get("SERVER_HOST","127.0.0.1"); port = int(os.environ.get("SERVER_PORT","8088"))
        threading.Thread(target=lambda: uvicorn.run(app, host=host, port=port, log_level="info"), daemon=True).start()
        d.log.info(f"REST server started on http://{host}:{port}")
    elif "flask" in globals():
        app = flask.Flask("tbd-api")
        @app.post("/jobs")
        def submit():
            payload = flask.request.get_json(force=True) or {}
            urls = payload.get("urls") or []
            urls = [u if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', u) else _guess_scheme_and_normalize(u) for u in urls]
            return {"id": jq.submit(urls)}
        @app.get("/jobs")
        def list_jobs(): return flask.jsonify(jq.list())
        @app.get("/jobs/<jid>")
        def get_job(jid): 
            j = jq.get(jid)
            return (flask.jsonify(j), 200) if j else ({"error":"not found"}, 404)
        @app.post("/jobs/<jid>/cancel")
        def cancel_job(jid: str): return {"ok": jq.cancel(jid)}
        @app.get("/telemetry")
        def telemetry(): return {"bytes": d.egress_bytes, "flows": d.egress_flows}
        host = os.environ.get("SERVER_HOST","127.0.0.1"); port = int(os.environ.get("SERVER_PORT","8088"))
        threading.Thread(target=lambda: app.run(host=host, port=port), daemon=True).start()
        d.log.info(f"REST server started on http://{host}:{port}")
    else:
        d.log.warning("SERVER=1 but FastAPI/Flask not installed; REST disabled.")

def main():
    banner = r"""
.___  ___.   ______    _______  __         _______..______      ___       __   __
|   \/   |  /  __  \  |   ____||  |       /       ||   _  \    /   \     |  | |  |
|  \  /  | |  |  |  | |  |__   |  |      |   (----`|  |_)  |  /  ^  \    |  | |  |
|  |\/|  | |  |  |  | |   __|  |  |       \   \    |   ___/  /  /_\  \   |  | |  |
|  |  |  | |  `--'  | |  |____ |  `----.---)   |   |  |     /  _____  \  |  | |  |
|__|  |__|  \______/  |_______||_______|_______/    |__|    /__/     \__\ |__| |__|
  Tor Blue Downloader v4.0 — Seal + Stealth + Scale + Safeguards (TUI by default)
"""
    print(banner)

    URLS_FILE = os.environ.get("URLS_FILE", "urls.txt")
    MODE = os.environ.get("MODE", "parallel")

    d = TorBlueDownloader(
        tor_proxy_port=int(os.environ.get("TOR_PROXY", "9050")),
        tor_control_port=int(os.environ.get("TOR_CTL", "9051")),
        tor_password=os.environ.get("TOR_PASS") or None,
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

    d.xdp_mgr.attach()
    d.cover_mgr.start()
    maybe_start_rest_server(d)

    headless = os.environ.get("HEADLESS","0") == "1"
    if headless:
        urls = d.load_urls(URLS_FILE)
        if not urls:
            print(f"[!] No URLs found in {URLS_FILE}")
            d.cover_mgr.stop(); d.xdp_mgr.detach(); sys.exit(2)
        t0 = time.time()
        try:
            if MODE == "parallel":
                d.download_all_parallel(urls)
            else:
                d.download_all_sequential(urls)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        finally:
            d.cover_mgr.stop(); d.xdp_mgr.detach()
            print(f"[*] Elapsed: {time.time() - t0:.2f}s")
    else:
        try:
            DownloaderShell(d).cmdloop()
        except KeyboardInterrupt:
            print()
        finally:
            d.cover_mgr.stop(); d.xdp_mgr.detach()

if __name__ == "__main__":
    main()
