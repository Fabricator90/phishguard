# phishguard/app/predictions/predict.py
from __future__ import annotations

import json, logging, os, pickle, re, threading
from urllib.parse import urlparse

import joblib
import numpy as np
from flask import Blueprint, jsonify, request

# -------------------------------------------------
# Artifact paths (ENV-overridable)
# -------------------------------------------------
_ART_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

_MODEL_PATH = os.getenv("PHISH_MODEL_PATH",
                        os.path.join(_ART_DIR, "phish_rf.joblib"))
_THRESHOLD_PATH = os.getenv("PHISH_THRESHOLD_PATH",
                            os.path.join(_ART_DIR, "threshold.json"))
_FEATURE_ORDER_PATH = os.getenv("PHISH_FEATURE_ORDER_PATH",
                                os.path.join(_ART_DIR, "feature_order.json"))
_IMPUTER_PATH = os.getenv("PHISH_IMPUTER_PATH",
                          os.path.join(_ART_DIR, "imputer_phi.joblib"))
_TLD_FREQ_PATH = os.getenv("PHISH_TLD_FREQ_PATH",
                           os.path.join(_ART_DIR, "tld_freq.json"))

# Built-in fallback order (used only if feature_order.json is missing)
# NOTE: 12 features, no "label".
DEFAULT_PHI_FEATURE_ORDER = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "at_symbol_present",
    "has_ip_address",
    "is_asset_url",
    "num_subdomains",
    "is_trusted_tld",
    "num_iframes",
    "num_password_inputs",
    "num_js_redirects",
    "TLD_freq",
]

# Neutral fill for missing page-only features when serving URL-only checks
_NAN_DEFAULT = float(os.getenv("PHISH_NAN_DEFAULT", "0.5"))

# Features we never compute at runtime from a bare URL:
_NEUTRALIZE_FEATURES = {
    "domain_age_days",
    "num_iframes",
    "num_password_inputs",
    "num_js_redirects",
    "TLD_freq",
}

# De-escalation allowlist by TLD only (HTTPS + non-punycode)
_ALLOWLIST_TLDS = (".gov", ".edu")

# Helpers for new schema
_ASSET_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|ico|webp|css|js|mjs|map|json|woff2?|ttf|eot|otf|mp4|mp3|webm|pdf|zip|rar|7z|gz|tar)(?:\?.*)?$",
    re.IGNORECASE,
)
# Keep conservative; we also treat "trusted" if its training frequency is high enough.
_TRUSTED_TLDS = {"gov", "edu"}

# Registered in app/__init__.py as: from .predictions.predict import bp as ml_bp
bp = Blueprint("ml", __name__, url_prefix="/api")

# -------------------------------------------------
# Lazy-loaded artifacts
# -------------------------------------------------
_model = None
_feature_order: list[str] | None = None
_pos_idx = 1
_imputer = None
_tld_freq_map: dict[str, float] | None = None
_tld_freq_mean: float | None = None
_lock = threading.Lock()

def _load_artifact(path: str):
    """Try joblib first (works for .pkl/.joblib), then raw pickle."""
    try:
        return joblib.load(path)
    except Exception:
        pass
    with open(path, "rb") as f:
        return pickle.load(f)

def _load_feature_order() -> list[str]:
    if os.path.exists(_FEATURE_ORDER_PATH):
        try:
            with open(_FEATURE_ORDER_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list) and all(isinstance(x, str) for x in data):
                return data
        except Exception:
            logging.exception("feature_order.json read failed; using default")
    return list(DEFAULT_PHI_FEATURE_ORDER)

def _load_tld_freq():
    """Load training TLD frequencies if provided; compute a safe mean for unknown TLDs."""
    global _tld_freq_map, _tld_freq_mean
    _tld_freq_map, _tld_freq_mean = None, None
    if not os.path.exists(_TLD_FREQ_PATH):
        return
    try:
        with open(_TLD_FREQ_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data:
            _tld_freq_map = {str(k).lower(): float(v) for k, v in data.items()}
            vals = [v for v in _tld_freq_map.values() if np.isfinite(v)]
            if vals:
                _tld_freq_mean = float(np.mean(vals))
    except Exception:
        logging.exception("tld_freq.json read failed; ignoring")

def _get_threshold(default: float = 0.85) -> float:
    """From file (supports dict with 'f1_opt'/'threshold' or bare number) or env PHISH_THRESHOLD."""
    try:
        if os.path.exists(_THRESHOLD_PATH):
            with open(_THRESHOLD_PATH, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            try:
                j = json.loads(raw)
                if isinstance(j, dict):
                    for k in ("threshold", "f1_opt"):
                        if k in j and 0.0 <= float(j[k]) <= 1.0:
                            return float(j[k])
                elif isinstance(j, (int, float)) and 0.0 <= float(j) <= 1.0:
                    return float(j)
            except Exception:
                # allow plain text number
                val = float(raw)
                if 0.0 <= val <= 1.0:
                    return val
    except Exception:
        pass
    try:
        t_env = float(os.getenv("PHISH_THRESHOLD", default))
        if 0.0 <= t_env <= 1.0:
            return t_env
    except Exception:
        pass
    return default

def _infer_positive_index(model) -> int:
    """Find which predict_proba column is positive class."""
    pos = 1
    classes = getattr(model, "classes_", None)
    if classes is None:
        return pos
    try:
        if 1 in classes:
            return int(np.where(classes == 1)[0][0])
        if "phish" in classes:
            return int(np.where(classes == "phish")[0][0])
        return len(classes) - 1
    except Exception:
        return 1 if len(classes) > 1 else 0

def _ensure_loaded():
    """Load model + artifacts once."""
    global _model, _feature_order, _pos_idx, _imputer
    if _model is not None:
        return
    with _lock:
        if _model is not None:
            return
        if not os.path.exists(_MODEL_PATH):
            raise FileNotFoundError(f"Model not found at {_MODEL_PATH}")
        _model = _load_artifact(_MODEL_PATH)
        _feature_order = _load_feature_order()
        _pos_idx = _infer_positive_index(_model)
        _imputer = None
        if os.path.exists(_IMPUTER_PATH):
            try:
                _imputer = _load_artifact(_IMPUTER_PATH)
            except Exception:
                logging.exception("Imputer load failed; continuing without it")
        _load_tld_freq()

# -------------------------------------------------
# Runtime feature extraction (phi)
# -------------------------------------------------
_ip_re = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

def _naive_etld1(host: str) -> str:
    parts = [p for p in (host or "").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")

def _extract_phi_features(url: str) -> dict[str, float]:
    u = url.strip()
    if not re.match(r"^[a-zA-Z]+://", u):
        u = "http://" + u
    parsed = urlparse(u)
    host = (parsed.hostname or "").lower()
    url_s = u
    path = parsed.path or ""

    # Best-effort TLD
    tld = ""
    try:
        parts = host.split(".")
        tld = parts[-1] if len(parts) >= 2 else ""
    except Exception:
        tld = ""

    # TLD_freq: use training map if present, else mean, else NaN
    if _tld_freq_map:
        tld_val = _tld_freq_map.get(tld, _tld_freq_mean if _tld_freq_mean is not None else np.nan)
    else:
        tld_val = np.nan

    is_trusted = 1.0 if (tld in _TRUSTED_TLDS or (isinstance(tld_val, (int, float)) and tld_val >= 0.02)) else 0.0
    is_asset   = 1.0 if _ASSET_RE.search(path) else 0.0

    return {
        "url_length": float(len(url_s)),
        "dot_count": float(url_s.count(".")),
        "hyphen_count": float(url_s.count("-")),
        "at_symbol_present": 1.0 if "@" in url_s else 0.0,
        "has_ip_address": 1.0 if _ip_re.match(host) else 0.0,

        # NEW schema features (pure URL-based)
        "is_asset_url": is_asset,
        "num_subdomains": float(max(host.count(".") - 1, 0)),
        "is_trusted_tld": is_trusted,

        # Page-only (neutralized if present in order)
        "num_iframes": np.nan,
        "num_password_inputs": np.nan,
        "num_js_redirects": np.nan,

        # Legacy / training-time extras (ignored if not in order)
        "domain_age_days": np.nan,
        "TLD_freq": tld_val,
    }

def _dict_to_vector(d: dict[str, float]) -> np.ndarray:
    """Neutralize page-only NaNs before imputer, to avoid 'missing == phish' bias."""
    _ensure_loaded()
    row = []
    for k in _feature_order:
        v = d.get(k, np.nan)
        if k in _NEUTRALIZE_FEATURES:
            try:
                if v is None or (isinstance(v, float) and np.isnan(v)):
                    v = _NAN_DEFAULT
            except Exception:
                v = _NAN_DEFAULT
        row.append(v)

    vec = np.asarray([row], dtype=float)

    if _imputer is not None:
        try:
            vec = _imputer.transform(vec)  # only imputes remaining NaNs
        except Exception:
            logging.exception("imputer.transform failed; NaN->neutral fallback")
            vec = np.nan_to_num(vec, nan=_NAN_DEFAULT)
    else:
        vec = np.nan_to_num(vec, nan=_NAN_DEFAULT)

    return vec

def _clamp_score(x: float) -> float:
    """Guard against NaN/inf/out-of-range probabilities."""
    try:
        if not np.isfinite(x):
            return 0.5
        return float(max(0.0, min(1.0, x)))
    except Exception:
        return 0.5

# -------------------------
# Rule-based post-processor
# -------------------------
def _postprocess_score(url: str, base_score: float) -> tuple[float, dict]:
    """
    Lightweight guardrails:
      - De-escalate HTTPS + .gov/.edu (non-punycode).
      - Escalate IP-host + login-ish paths.
    Returns (adjusted_score, debug_info).
    """
    info = {
        "gov_edu_deescalated": False,
        "ip_login_bump_applied": False,
        "etld1": None,
        "host": None,
        "scheme": None,
        "path": None,
    }

    try:
        parsed = urlparse(url if re.match(r"^[a-zA-Z]+://", url) else "http://" + url)
        host = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
        path = (parsed.path or "").lower()
        etld1 = _naive_etld1(host)

        info.update({"host": host, "scheme": scheme, "path": path, "etld1": etld1})

        score = _clamp_score(base_score)

        # Escalate: IP host + login-ish keyword in path
        if _ip_re.match(host) and any(k in path for k in ("login", "signin", "verify", "password", "account", "update")):
            score = max(score, 0.96)
            info["ip_login_bump_applied"] = True

        # De-escalate: HTTPS .gov/.edu, non-punycode
        if scheme == "https" and "xn--" not in host and host.endswith(_ALLOWLIST_TLDS):
            score = min(score, 0.15)
            info["gov_edu_deescalated"] = True

        return _clamp_score(score), info
    except Exception:
        return _clamp_score(base_score), info

# -------------------------------------------------
# Public helpers
# -------------------------------------------------
def score_url(url: str) -> float:
    _ensure_loaded()
    X = _dict_to_vector(_extract_phi_features(url))
    proba = _model.predict_proba(X)
    base = float(proba[0, _pos_idx] if proba.shape[1] > 1 else proba[0, 0])
    base = _clamp_score(base)
    adjusted, _ = _postprocess_score(url, base)
    return adjusted

def label_url(url: str) -> str:
    return "phish" if score_url(url) >= _get_threshold() else "legit"

# -------------------------------------------------
# Routes (mounted under /api via blueprint)
# -------------------------------------------------
@bp.get("/health")
def health():
    try:
        _ensure_loaded()
        classes = getattr(_model, "classes_", None)
        return jsonify({
            "ok": True,
            "model_loaded": True,
            "n_features_in": getattr(_model, "n_features_in_", None),
            "classes": classes.tolist() if hasattr(classes, "tolist") else classes,
            "feature_order_known": _feature_order is not None,
            "threshold": _get_threshold(),
            "tld_freq_loaded": bool(_tld_freq_map),
            "imputer_loaded": bool(_imputer is not None),
            "nan_default": _NAN_DEFAULT,
            "allowlist_tlds": list(_ALLOWLIST_TLDS),
        }), 200
    except Exception as e:
        logging.exception("health failed")
        return jsonify({"ok": False, "error": str(e)}), 500

@bp.post("/predict")
def predict():
    """Predict from a provided feature dict/list (mostly for internal testing)."""
    try:
        _ensure_loaded()
        data = request.get_json(force=True) or {}
        feats = data.get("features")
        if feats is None:
            return jsonify({"ok": False, "error": "Missing 'features'"}), 400

        if isinstance(feats, dict):
            X = _dict_to_vector(feats)
        elif isinstance(feats, list):
            if _feature_order and len(feats) != len(_feature_order):
                return jsonify({"ok": False, "error": f"Expected {len(_feature_order)} features, got {len(feats)}"}), 400
            X = np.asarray([feats], dtype=float)
            if _imputer is not None:
                try:
                    X = _imputer.transform(X)
                except Exception:
                    logging.exception("imputer.transform failed; NaN->neutral fallback")
                    X = np.nan_to_num(X, nan=_NAN_DEFAULT)
            else:
                X = np.nan_to_num(X, nan=_NAN_DEFAULT)
        else:
            return jsonify({"ok": False, "error": "'features' must be dict or list"}), 400

        if not hasattr(_model, "predict_proba"):
            return jsonify({"ok": False, "error": "Model has no predict_proba()"}), 500

        proba = _model.predict_proba(X)
        base = float(proba[0, _pos_idx] if proba.shape[1] > 1 else proba[0, 0])
        base = _clamp_score(base)
        thr = _get_threshold()
        label = "phish" if base >= thr else "legit"
        return jsonify({
            "ok": True, "label": label, "score": round(base, 6),
            "threshold": thr, "positive_class_index": _pos_idx,
            "features_checked": int(X.shape[1]),
        }), 200
    except Exception as e:
        logging.exception("predict error")
        return jsonify({"ok": False, "error": str(e)}), 500

def _predict_for_url_common(url: str):
    """Shared code for /predict_url and /check."""
    _ensure_loaded()
    url = (url or "").strip()
    if not url:
        return {"ok": False, "error": "Missing 'url'"}, 400
    X = _dict_to_vector(_extract_phi_features(url))
    proba = _model.predict_proba(X)
    base = float(proba[0, _pos_idx] if proba.shape[1] > 1 else proba[0, 0])
    base = _clamp_score(base)
    score, post_dbg = _postprocess_score(url, base)
    thr = _get_threshold()
    label = "phish" if score >= thr else "legit"
    return {
        "ok": True,
        "url": url,
        "label": label,
        "score": round(_clamp_score(score), 6),
        "base_score": round(base, 6),
        "threshold": thr,
        "postprocess": post_dbg,
    }, 200

@bp.post("/predict_url")
def predict_url_endpoint():
    try:
        data = request.get_json(force=True) or {}
        resp, code = _predict_for_url_common(data.get("url"))
        return jsonify(resp), code
    except Exception as e:
        logging.exception("predict_url error")
        return jsonify({"ok": False, "error": str(e)}), 500

# === Extension-compatible ===
@bp.post("/check")
def check_endpoint():
    """Extension uses POST /api/check with {url} → {label, score, url}."""
    try:
        data = request.get_json(force=True) or {}
        resp, code = _predict_for_url_common(data.get("url"))
        if code != 200:
            return jsonify(resp), code
        # essentials expected by the extension
        return jsonify({"ok": True, "url": resp["url"], "label": resp["label"], "score": resp["score"]}), 200
    except Exception as e:
        logging.exception("check error")
        return jsonify({"ok": False, "error": str(e)}), 500

@bp.get("/debug_check")
def debug_check():
    """
    Diagnostic: shows the raw feature dict, imputed vector, and scores (base + post-processed).
    """
    try:
        _ensure_loaded()
        url = (request.args.get("url") or "").strip()
        feats = _extract_phi_features(url) if url else {}
        X = _dict_to_vector(feats) if url else np.zeros((1, len(_feature_order or [])))

        base = None
        score = None
        post_dbg = None
        if url:
            proba = _model.predict_proba(X)
            base = float(proba[0, _pos_idx] if proba.shape[1] > 1 else proba[0, 0])
            base = _clamp_score(base)
            score, post_dbg = _postprocess_score(url, base)

        return jsonify({
            "ok": True,
            "url": url,
            "feature_order": _feature_order,
            "features_raw": feats,
            "vector_after_impute": list(map(float, X.ravel())),
            "threshold": _get_threshold(),
            "pos_idx": _pos_idx,
            "nan_default": _NAN_DEFAULT,
            "imputer_loaded": bool(_imputer is not None),
            "tld_freq_loaded": bool(_tld_freq_map),
            "base_score": base,
            "score_after_rules": score,
            "postprocess": post_dbg,
        }), 200
    except Exception as e:
        logging.exception("debug_check failed")
        return jsonify({"ok": False, "error": str(e)}), 500
