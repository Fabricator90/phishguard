#!/usr/bin/env python3
"""
flask_linker.py

Minimal Flask app that:
- resolves artifacts/model paths robustly (similar to model_generator)
- attempts to load joblib/sklearn or lightgbm models if present
- exposes lightweight endpoints that the extension expects:
    GET  /api/health        -> { "ok": true, "models_loaded": [...] }
    POST /api/check         -> accepts { "features": [ ... ] } and returns score/label
    POST /api/refresh       -> dummy token refresh endpoint (for extension compatibility)
    POST /api/login         -> dummy login (for extension compatibility)
    GET  /api/me            -> dummy user info (requires no auth in this minimal server)
    GET  /api/reports       -> returns empty list or sample data
    POST /api/report        -> records a report file in artifacts/reports (local only)
- Note: Real feature extraction from URLs is not implemented here. You can:
    * compute features externally and call /api/check with 'features' array, OR
    * add the project's feature-extractor code into this file where indicated.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from pathlib import Path
import os
import json
import logging
import traceback

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

try:
    import joblib
except Exception:
    joblib = None

try:
    import numpy as np
except Exception:
    np = None

try:
    import lightgbm as lgb
except Exception:
    lgb = None

# ---------- Path resolution (same approach as model_generator) ----------
def find_project_root(start: Path = None, max_up: int = 6) -> Path:
    start = (start or Path(__file__).parent).resolve()
    p = start
    for _ in range(max_up):
        if (p / "app").exists() or (p / "Test_Programs").exists() or (p / ".git").exists():
            return p
        p = p.parent
    return Path.cwd().resolve()

def resolve_artifacts_dir(root: Path) -> Path:
    candidates = [
        root / "app" / "artifacts",
        root / "Test_Programs" / "artifacts",
        root / "test programs" / "artifacts",
        root / "artifacts",
        Path(__file__).parent / "artifacts",
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    fallback = root / "app" / "artifacts"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback.resolve()

ENV_PROJECT_ROOT = os.environ.get("PROJECT_ROOT", "")
PROJECT_ROOT = Path(ENV_PROJECT_ROOT).resolve() if ENV_PROJECT_ROOT else find_project_root(Path(__file__).parent)
ART_DIR = resolve_artifacts_dir(PROJECT_ROOT)
MODELS_DIR = Path(os.environ.get("MODELS_DIR", ART_DIR))
REPORTS_DIR = ART_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.info("PROJECT_ROOT=%s", PROJECT_ROOT)
logging.info("ARTIFACTS_DIR=%s", ART_DIR)
logging.info("MODELS_DIR=%s", MODELS_DIR)
logging.info("REPORTS_DIR=%s", REPORTS_DIR)

# ---------- Model loading ----------
RF_MODEL_PATH = MODELS_DIR / "phish_rf.joblib"
GB_MODEL_PATH = MODELS_DIR / "phish_lgbm.joblib"
FEATURE_ORDER_PATH = MODELS_DIR / "feature_order.json"
RF_THRESH_PATH = MODELS_DIR / "threshold.json"
GB_THRESH_PATH = MODELS_DIR / "threshold_lgbm.json"

models_loaded = []
rf_model = None
gb_model = None
feature_order = None
rf_threshold = 0.5
gb_threshold = 0.5

def try_load_models():
    global rf_model, gb_model, feature_order, rf_threshold, gb_threshold, models_loaded
    models_loaded = []
    if joblib and RF_MODEL_PATH.exists():
        try:
            rf_model = joblib.load(str(RF_MODEL_PATH))
            models_loaded.append("rf")
            logging.info("Loaded RF model from %s", RF_MODEL_PATH)
        except Exception as e:
            logging.exception("Failed loading RF model: %s", e)
    else:
        logging.info("RF model not found at %s (or joblib missing)", RF_MODEL_PATH)

    if joblib and GB_MODEL_PATH.exists():
        try:
            gb_model = joblib.load(str(GB_MODEL_PATH))
            models_loaded.append("gb")
            logging.info("Loaded GB model from %s", GB_MODEL_PATH)
        except Exception as e:
            logging.exception("Failed loading GB model: %s", e)
    else:
        logging.info("GB model not found at %s (or joblib missing)", GB_MODEL_PATH)

    if FEATURE_ORDER_PATH.exists():
        try:
            feature_order = json.loads(FEATURE_ORDER_PATH.read_text()).get("feature_order", None)
            logging.info("Loaded feature order (%d features) from %s", len(feature_order) if feature_order else 0, FEATURE_ORDER_PATH)
        except Exception as e:
            logging.exception("Failed reading feature order: %s", e)

    if RF_THRESH_PATH.exists():
        try:
            rf_threshold = json.loads(RF_THRESH_PATH.read_text()).get("threshold", rf_threshold)
        except Exception:
            pass
    if GB_THRESH_PATH.exists():
        try:
            gb_threshold = json.loads(GB_THRESH_PATH.read_text()).get("threshold", gb_threshold)
        except Exception:
            pass

# initial load
try_load_models()

# ---------- Flask app ----------
app = Flask(__name__)
CORS(app)  # permissive for local dev

@app.route("/", methods=["GET"])
def index():
    return "PhishGuard Flask Linker (dev)", 200

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "models_loaded": models_loaded}), 200

@app.route("/api/refresh", methods=["POST"])
def refresh():
    # Minimal compatible endpoint for extension; replace with real token logic if you have it
    return jsonify({"access_token": "dev-access-token"}), 200

@app.route("/api/login", methods=["POST"])
def login():
    # This is a dummy login endpoint to satisfy extension flows.
    body = request.get_json(silent=True) or {}
    email = body.get("email")
    if not email:
        email = "dev@local"
    return jsonify({"access_token": "dev-access-token", "refresh_token": "dev-refresh-token", "user": {"email": email}}), 200

@app.route("/api/me", methods=["GET"])
def me():
    # Dummy user info endpoint
    return jsonify({"email": "dev@local", "name": "Dev User"}), 200

@app.route("/api/reports", methods=["GET"])
def reports():
    # Return latest reports found on disk
    reports = []
    for p in sorted(REPORTS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
            reports.append({"filename": p.name, "summary": obj.get("summary", {}), "created": p.stat().st_mtime})
        except Exception:
            continue
    return jsonify({"reports": reports}), 200

@app.route("/api/report", methods=["POST"])
def report():
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "expected json body"}), 400
    # store the report locally
    import time, uuid
    outname = REPORTS_DIR / f"report_{int(time.time())}_{uuid.uuid4().hex[:8]}.json"
    outname.write_text(json.dumps(body, indent=2), encoding="utf-8")
    logging.info("Saved report to %s", outname)
    return jsonify({"ok": True, "filename": outname.name}), 200

@app.route("/api/check", methods=["POST"])
def check():
    """
    Accepts JSON:
      { "features": [f1, f2, f3, ...] }  OR
      { "features_map": {"feat_name": value, ...} }

    If models are loaded and features provided, returns:
      { "score": <float>, "label": "phish"|"suspicious"|"legit", "model": "rf"|"gb"|"ensemble" }

    If no features provided, returns 400 and a guide on how to integrate feature extraction.
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "expected json body with 'features' or 'features_map' or 'url' (feature extraction not implemented)"}), 400

    # If features_map provided convert using feature_order
    features_vec = None
    if "features_map" in body:
        fmap = body["features_map"]
        if not FEATURE_ORDER_PATH.exists():
            return jsonify({"error": "feature_order.json not found on server; cannot map features_map to vector"}), 400
        try:
            order = json.loads(FEATURE_ORDER_PATH.read_text()).get("feature_order", [])
            features_vec = [fmap.get(k, 0.0) for k in order]
        except Exception as e:
            logging.exception("Failed to map features_map: %s", e)
            return jsonify({"error": "failed to map feature_map"}), 500
    elif "features" in body:
        features_vec = body["features"]
    elif "url" in body:
        # We cannot extract features automatically in this minimal server.
        return jsonify({
            "error": "feature extraction from URLs is not implemented in this minimal server.",
            "hint": "Call your feature-extractor locally and POST {'features': [...]} or implement feature extraction in this server."
        }), 400
    else:
        return jsonify({"error": "no 'features', 'features_map', or 'url' provided"}), 400

    # ensure features_vec is numeric array
    try:
        x = np.array(features_vec, dtype=float).reshape(1, -1) if np is not None else None
    except Exception:
        x = None

    if x is None:
        return jsonify({"error": "invalid features vector or numpy not installed"}), 400

    # If both models loaded, produce ensemble average of probabilities (if predict_proba available)
    try:
        scores = {}
        if rf_model is not None and hasattr(rf_model, "predict_proba"):
            p = rf_model.predict_proba(x)[0, 1]
            scores["rf"] = float(p)
        if gb_model is not None:
            # lightgbm booster uses predict, scikit-learn LGBMClassifier might have predict_proba
            try:
                if hasattr(gb_model, "predict_proba"):
                    p = gb_model.predict_proba(x)[0, 1]
                else:
                    p = gb_model.predict(x)[0]  # lgb.Booster -> predict returns prob
                scores["gb"] = float(p)
            except Exception:
                logging.exception("gb_model scoring failed")
        # ensemble
        if scores:
            avg = sum(scores.values()) / len(scores)
            label = "legit"
            # simple thresholds: you may adjust these by reading threshold files
            try:
                rf_thresh = json.loads(RF_THRESH_PATH.read_text()).get("threshold", 0.5) if RF_THRESH_PATH.exists() else 0.5
            except Exception:
                rf_thresh = 0.5
            try:
                gb_thresh = json.loads(GB_THRESH_PATH.read_text()).get("threshold", 0.5) if GB_THRESH_PATH.exists() else 0.5
            except Exception:
                gb_thresh = 0.5
            # if average exceeds mean of thresholds -> suspicious, above max -> phish
            mean_thresh = (rf_thresh + gb_thresh) / 2.0 if (RF_THRESH_PATH.exists() and GB_THRESH_PATH.exists()) else 0.5
            high = max(rf_thresh, gb_thresh) if (RF_THRESH_PATH.exists() and GB_THRESH_PATH.exists()) else 0.85
            if avg >= high:
                label = "phish"
            elif avg >= mean_thresh:
                label = "suspicious"
            else:
                label = "legit"
            return jsonify({"score": avg, "label": label, "scores": scores}), 200
    except Exception as e:
        logging.exception("scoring failed: %s", e)
        return jsonify({"error": "scoring failed", "exception": str(e)}), 500

    return jsonify({"error": "no model available to score features"}), 400

# ---------- CLI run ----------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(prog="flask_linker.py")
    parser.add_argument("--host", default=os.environ.get("FLASK_HOST", "127.0.0.1"))
    parser.add_argument("--port", default=int(os.environ.get("PORT", 5000)))
    parser.add_argument("--reload-models", action="store_true", help="Reload models from disk then exit")
    args = parser.parse_args()

    if args.reload_models:
        try_load_models()
        print("Models loaded:", models_loaded)
        raise SystemExit(0)

    # Start Flask
    logging.info("Starting Flask on %s:%s", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=False)
