# app/features.py
from __future__ import annotations
from urllib.parse import urlparse
import re
from typing import Dict, List
import numpy as np

# Keep this list STABLE and in the EXACT order your model expects.
# If your trained model used a different order, update this to match and keep it constant.
FEATURE_ORDER: List[str] = [
    "url_len",
    "host_len",
    "path_len",
    "query_len",
    "num_digits",
    "num_specials",
    "num_subdomains",
    "tld_len",
    "has_ip_host",
    "has_at_sign",
    "has_https_scheme",
    "suspicious_token_count",
]

SUSPICIOUS_TOKENS = [
    "login", "verify", "update", "secure", "account", "webscr", "confirm",
    "bank", "paypal", "appleid", "drive", "gift", "free", "bonus", "prize",
]

_ip_re = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"  # IPv4; keep simple to avoid heavy deps
)

def _count(pattern: str, text: str) -> int:
    return len(re.findall(pattern, text))

def extract_url_features(url: str) -> Dict[str, float]:
    # Normalize a bit
    url_s = url.strip()
    parsed = urlparse(url_s if re.match(r"^[a-zA-Z]+://", url_s) else "http://" + url_s)

    host = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    scheme = (parsed.scheme or "").lower()

    # host parts
    host_parts = host.split(".") if host else []
    num_subdomains = max(len(host_parts) - 2, 0) if len(host_parts) >= 2 else 0
    tld_len = len(host_parts[-1]) if len(host_parts) >= 2 else 0

    # counts
    num_digits = _count(r"\d", url_s)
    num_specials = _count(r"[^A-Za-z0-9]", url_s)

    # signals
    has_ip_host = 1.0 if _ip_re.match(host) else 0.0
    has_at_sign = 1.0 if "@" in url_s else 0.0
    has_https_scheme = 1.0 if scheme == "https" else 0.0

    # tokens
    lower_all = url_s.lower()
    suspicious_token_count = sum(1 for t in SUSPICIOUS_TOKENS if t in lower_all)

    feats = {
        "url_len": float(len(url_s)),
        "host_len": float(len(host)),
        "path_len": float(len(path)),
        "query_len": float(len(query)),
        "num_digits": float(num_digits),
        "num_specials": float(num_specials),
        "num_subdomains": float(num_subdomains),
        "tld_len": float(tld_len),
        "has_ip_host": float(has_ip_host),
        "has_at_sign": float(has_at_sign),
        "has_https_scheme": float(has_https_scheme),
        "suspicious_token_count": float(suspicious_token_count),
    }
    return feats

def vectorize(feats: Dict[str, float], feature_order: List[str] | None = None) -> np.ndarray:
    order = feature_order or FEATURE_ORDER
    return np.asarray([feats.get(k, 0.0) for k in order], dtype=float).reshape(1, -1)
