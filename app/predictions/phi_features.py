import re
from urllib.parse import urlparse
import numpy as np

_ip_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def extract_phi_features(url: str) -> dict[str, float]:
    u = url.strip()
    if not re.match(r"^[a-zA-Z]+://", u):
        u = "http://" + u

    parsed = urlparse(u)
    host = parsed.hostname or ""
    url_s = u

    feats = {
        "url_length": len(url_s),
        "dot_count": url_s.count("."),
        "hyphen_count": url_s.count("-"),
        "at_symbol_present": 1.0 if "@" in url_s else 0.0,
        "has_ip_address": 1.0 if _ip_re.match(host) else 0.0,
        "domain_age_days": np.nan,     # unknown at runtime → use imputer if available
        "num_subdomains": max(host.count(".") - 1, 0),
        "num_iframes": np.nan,         # unknown → imputer
        "num_password_inputs": np.nan, # unknown → imputer
        "num_js_redirects": np.nan,    # unknown → imputer
        "TLD_freq": np.nan,              # we don’t have train freqs → default 0

    }
    return feats
