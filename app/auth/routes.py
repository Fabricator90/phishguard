# app/auth/routes.py
from datetime import datetime
import re

from flask import (
    Blueprint, render_template, redirect, url_for,
    flash, request, current_app
)
from flask_login import login_user, logout_user, login_required, current_user
from sqlalchemy.exc import IntegrityError

from ..extensions import db
from app.models import User
from .forms import RegisterForm, LoginForm, RequestResetForm, ResetPasswordForm
from ..email_utils import generate_token, verify_token, send_email

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _generate_username_from_email(email: str) -> str:
    """Make a safe, unique username from the email local-part."""
    base = (email.split("@", 1)[0]).lower()
    base = re.sub(r"[^a-z0-9_]+", "", base) or "user"

    candidate = base
    i = 1
    while User.query.filter_by(username=candidate).first() is not None:
        i += 1
        candidate = f"{base}{i}"
    return candidate


def _is_confirmed(user: User) -> bool:
    """True if user looks confirmed under either schema."""
    return bool(getattr(user, "is_confirmed", False) or getattr(user, "email_confirmed_at", None))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()

        # Block duplicates by email up front
        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "warning")
            return redirect(url_for("auth.login"))

        username = _generate_username_from_email(email)
        user = User(username=username, email=email)
        user.set_password(form.password.data)
        db.session.add(user)

        try:
            db.session.commit()
        except IntegrityError:
            # In the unlikely event of a race on username, try once more.
            db.session.rollback()
            username = _generate_username_from_email(email)
            user.username = username
            db.session.add(user)
            db.session.commit()

        # Email confirmation (never crash the request on email problems)
        try:
            token = generate_token(user.email, "confirm")
            confirm_url = url_for("auth.confirm_email", token=token, _external=True)
            send_email(
                "Confirm your PhishGuard account",
                [user.email],
                "emails/confirm.html",
                confirm_url=confirm_url,
            )
        except Exception:
            current_app.logger.exception("register: send_email failed")

        flash("Account created! Check your inbox for a confirmation link.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    email = verify_token(token, "confirm")
    if not email:
        flash("Confirmation link is invalid or expired.", "danger")
        return redirect(url_for("auth.resend_confirmation"))

    user = User.query.filter_by(email=email).first_or_404()
    if _is_confirmed(user):
        flash("Email already confirmed. Please log in.", "info")
    else:
        # support either boolean flag or timestamp field depending on your model
        if hasattr(user, "email_confirmed_at"):
            user.email_confirmed_at = datetime.utcnow()
        if hasattr(user, "is_confirmed"):
            user.is_confirmed = True
        db.session.commit()
        flash("Your email has been confirmed!", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/resend-confirmation")
def resend_confirmation():
    if not current_user.is_authenticated:
        flash("Log in to resend your confirmation email.", "warning")
        return redirect(url_for("auth.login"))

    if _is_confirmed(current_user):
        flash("Your email is already confirmed.", "info")
        return redirect(url_for("main.index"))

    try:
        token = generate_token(current_user.email, "confirm")
        confirm_url = url_for("auth.confirm_email", token=token, _external=True)
        send_email(
            "Confirm your PhishGuard account",
            [current_user.email],
            "emails/confirm.html",
            confirm_url=confirm_url,
        )
        flash("Confirmation email sent!", "success")
    except Exception:
        current_app.logger.exception("resend_confirmation: send_email failed")
        flash("We couldn't send the email right now. Please try again shortly.", "warning")

    return redirect(url_for("main.index"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(form.password.data):
            # If you want to require confirmation for web login, uncomment below:
            # if not _is_confirmed(user):
            #     flash("Please confirm your email first. We just re-sent the link.", "warning")
            #     try:
            #         token = generate_token(user.email, "confirm")
            #         confirm_url = url_for("auth.confirm_email", token=token, _external=True)
            #         send_email("Confirm your PhishGuard account", [user.email],
            #                    "emails/confirm.html", confirm_url=confirm_url)
            #     except Exception:
            #         current_app.logger.exception("login: resend confirm failed")
            #     return redirect(url_for("auth.login"))

            login_user(user)
            flash("Welcome back!", "success")
            next_page = request.args.get("next") or url_for("main.index")
            return redirect(next_page)

        flash("Invalid email or password.", "danger")
    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/reset", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    form = RequestResetForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                token = generate_token(user.email, "reset")
                reset_url = url_for("auth.reset_token", token=token, _external=True)
                send_email(
                    "Reset your PhishGuard password",
                    [user.email],
                    "emails/reset_password.html",
                    reset_url=reset_url,
                )
            except Exception:
                current_app.logger.exception("reset_request: send_email failed")
        flash("If that email exists, a reset link has been sent.", "info")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password_request.html", form=form)


@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    email = verify_token(token, "reset")
    if not email:
        flash("Reset link is invalid or expired.", "danger")
        return redirect(url_for("auth.reset_request"))

    user = User.query.filter_by(email=email).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash("Password updated. You can now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", form=form)
