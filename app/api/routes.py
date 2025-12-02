# app/api/routes.py
import os
from datetime import datetime
from urllib.parse import urlparse

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    jwt_required, get_jwt_identity, create_access_token, create_refresh_token
)

from app.extensions import db
from app.models import User, Report

api_bp = Blueprint("api", __name__, url_prefix="/api")


# ---------- helpers ----------
def _is_url(s: str) -> bool:
    try:
        p = urlparse(s)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def _is_dev() -> bool:
    return os.getenv("FLASK_DEBUG") == "1" or os.getenv("FLASK_ENV") == "development"


# ---------- auth ----------
@api_bp.route("/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "missing_credentials"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401

    # allow unconfirmed locally; require confirmation in prod
    if not getattr(user, "is_confirmed", True) and not _is_dev():
        return jsonify({"error": "email_not_confirmed"}), 403

    access  = create_access_token(identity=str(user.id), additional_claims={"email": user.email})
    refresh = create_refresh_token(identity=str(user.id))
    return jsonify({"access_token": access, "refresh_token": refresh})


@api_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    uid = int(get_jwt_identity())
    u = User.query.get(uid)
    return jsonify({"id": u.id, "email": u.email, "confirmed": getattr(u, "is_confirmed", True)})


@api_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    uid = get_jwt_identity()
    new_access = create_access_token(identity=str(uid))
    return jsonify({"access_token": new_access})


# ---------- reports ----------
@api_bp.route("/report", methods=["POST"])
@jwt_required()
def make_report():
    """
    Create a report row that the dashboard will show.
    Body: { url, score?, label?, source? }
    Works with both old (is_phishing/timestamp) and new (label/evaluated_at/created_at/source) schemas.
    """
    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not _is_url(url):
        return jsonify({"error": "invalid_url"}), 400

    uid = int(get_jwt_identity())

    # Only hard requirements in constructor
    r = Report(user_id=uid, url=url[:2048])

    # Optional: source
    if hasattr(Report, "source"):
        r.source = (data.get("source") or "api")[:32]

    # Optional: score
    if hasattr(Report, "score"):
        try:
            r.score = float(data.get("score"))
        except (TypeError, ValueError):
            pass

    # Optional: label (new schema)
    label_in = (data.get("label") or "").strip().lower()
    if hasattr(Report, "label") and label_in:
        r.label = label_in

    # Old schema: is_phishing is NOT NULL → compute a boolean
    if hasattr(Report, "is_phishing"):
        ph = None
        if label_in == "phish":
            ph = True
        elif label_in in ("legit", "suspicious"):
            ph = False
        elif "score" in data:
            try:
                thr = float(os.getenv("PHISH_THRESHOLD", "0.9"))
                ph = float(data["score"]) >= thr
            except (TypeError, ValueError):
                ph = None
        if ph is None:
            ph = False  # safe default to satisfy NOT NULL
        r.is_phishing = bool(ph)

    # Timestamps: set whichever column exists
    now = datetime.utcnow()
    if hasattr(Report, "evaluated_at") and getattr(r, "evaluated_at", None) is None:
        r.evaluated_at = now
    if hasattr(Report, "created_at") and getattr(r, "created_at", None) is None:
        r.created_at = now
    if hasattr(Report, "timestamp") and getattr(r, "timestamp", None) is None:
        r.timestamp = now

    db.session.add(r)
    db.session.commit()
    return jsonify({"ok": True, "id": r.id}), 201


@api_bp.route("/reports", methods=["GET"])
@jwt_required()
def list_reports():
    uid = int(get_jwt_identity())
    q = Report.query.filter_by(user_id=uid)

    # optional limit
    try:
        limit = max(1, min(200, int(request.args.get("limit", "50"))))
    except Exception:
        limit = 50

    # choose the best available timestamp column
    ts_col = None
    for name in ("evaluated_at", "created_at", "timestamp"):
        if hasattr(Report, name):
            ts_col = getattr(Report, name)
            break
    if ts_col is None:
        ts_col = Report.id

    rows = q.order_by(ts_col.desc()).limit(limit).all()

    def _iso(dt):
        try:
            return dt.isoformat()
        except Exception:
            return None

    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "url": r.url,
            "source": getattr(r, "source", None),
            "label": getattr(r, "label", None),
            "is_phishing": getattr(r, "is_phishing", None),
            "score": getattr(r, "score", None),
            "created_at": _iso(getattr(r, "created_at", None)),
            "evaluated_at": _iso(getattr(r, "evaluated_at", None)),
            "timestamp": _iso(getattr(r, "timestamp", None)),
        })
    return jsonify(out)


# ---------- scoring ----------
@api_bp.route("/check", methods=["POST"])
@jwt_required()
def check_url():
    """Score a single URL (does NOT persist automatically)."""
    from app.predictions.predict import score_url, label_url  # lazy import

    data = request.get_json() or {}
    url = (data.get("url") or "").strip()
    if not _is_url(url):
        return jsonify({"error": "invalid_url"}), 400

    s = float(score_url(url))
    l = label_url(url)
    return jsonify({"url": url, "score": round(s, 6), "label": l}), 200
