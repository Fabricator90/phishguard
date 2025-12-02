# app/main/routes.py
from datetime import datetime, timedelta
from flask import Blueprint, render_template
from flask_login import login_required, current_user
from sqlalchemy import func

from app.extensions import db
from app.models import Report

bp = Blueprint("main", __name__)

@bp.route("/")
def index():
    return render_template("index.html")

@bp.route("/dashboard")
@login_required
def dashboard():
    # pick whichever timestamp column exists in your model/table
    ts_col = (getattr(Report, "evaluated_at", None)
              or getattr(Report, "created_at", None)
              or getattr(Report, "timestamp", None))

    def safe_count(q):
        try:
            return int(q.scalar() or 0)
        except Exception:
            return 0

    now = datetime.utcnow()
    day_ago = now - timedelta(days=1)

    # base query for this user
    base_q = db.session.query(Report.id).filter(Report.user_id == current_user.id)

    # totals
    total_scans = safe_count(db.session.query(func.count(Report.id))
                             .filter(Report.user_id == current_user.id))

    # threats: use whichever your schema has
    if hasattr(Report, "is_phishing"):
        threats_detected = safe_count(db.session.query(func.count(Report.id))
                                      .filter(Report.user_id == current_user.id,
                                              Report.is_phishing.is_(True)))
    elif hasattr(Report, "label"):
        threats_detected = safe_count(db.session.query(func.count(Report.id))
                                      .filter(Report.user_id == current_user.id,
                                              Report.label == "phish"))
    else:
        threats_detected = 0

    # safe sites count (best-effort)
    if hasattr(Report, "label"):
        safe_sites = safe_count(db.session.query(func.count(Report.id))
                                .filter(Report.user_id == current_user.id,
                                        Report.label == "legit"))
    elif hasattr(Report, "is_phishing"):
        safe_sites = safe_count(db.session.query(func.count(Report.id))
                                .filter(Report.user_id == current_user.id,
                                        Report.is_phishing.is_(False)))
    else:
        safe_sites = max(0, total_scans - threats_detected)

    # last 24h scans
    if ts_col is not None:
        scans_24h = safe_count(db.session.query(func.count(Report.id))
                               .filter(Report.user_id == current_user.id,
                                       ts_col >= day_ago))
    else:
        scans_24h = 0

    # recent rows for table
    try:
        q = Report.query.filter_by(user_id=current_user.id)
        order_col = ts_col.desc() if ts_col is not None else Report.id.desc()
        recent = q.order_by(order_col).limit(25).all()
    except Exception:
        recent = []

    stats = {
        "total_scans": total_scans,
        "threats_detected": threats_detected,
        "safe_sites": safe_sites,
    }

    # pass both keys so either dashboard.html variant works
    return render_template(
        "dashboard.html",
        current_user=current_user,
        stats=stats,
        scans_24h=scans_24h,
        recent=recent,
        recent_activity=recent,
    )
