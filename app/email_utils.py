# app/email_utils.py
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app, render_template
from flask_mail import Message
from .extensions import mail
import re

def _serializer(purpose: str) -> URLSafeTimedSerializer:
    secret = current_app.config.get("SECRET_KEY", "")
    # pick the right salt; default so we never KeyError
    if purpose == "confirm":
        salt = current_app.config.get("SECURITY_EMAIL_SALT", "confirm-salt")
    else:
        salt = current_app.config.get("SECURITY_RESET_SALT", "reset-salt")
    return URLSafeTimedSerializer(secret_key=secret, salt=salt)

def generate_token(email: str, purpose: str) -> str:
    return _serializer(purpose).dumps(email)

def verify_token(token: str, purpose: str, max_age: int | None = None) -> str | None:
    if max_age is None:
        max_age = int(current_app.config.get("TOKEN_MAX_AGE", 86400))
    try:
        return _serializer(purpose).loads(token, max_age=max_age)
    except (BadSignature, SignatureExpired):
        return None

def _strip_html(html: str) -> str:
    return re.sub(r"<[^>]+>", "", html or "")

def send_email(subject: str, recipients: list[str], template_name: str | None = None, **context) -> None:
    """
    Renders a template if available; otherwise builds a simple fallback body.
    Never raises; logs errors instead.
    """
    try:
        sender = current_app.config.get("MAIL_DEFAULT_SENDER")
        msg = Message(subject=subject, recipients=recipients, sender=sender)

        html = None
        if template_name:
            try:
                html = render_template(template_name, **context)
            except Exception:
                current_app.logger.exception("Email template render failed: %s", template_name)

        if not html:
            # Minimal safe fallback body
            parts = []
            if "confirm_url" in context:
                parts.append(f'<p>Confirm your account: <a href="{context["confirm_url"]}">{context["confirm_url"]}</a></p>')
            if "reset_url" in context:
                parts.append(f'<p>Reset your password: <a href="{context["reset_url"]}">{context["reset_url"]}</a></p>')
            if not parts:
                parts.append("<p>Hello from PhishGuard.</p>")
            html = "\n".join(parts)

        msg.html = html
        msg.body = _strip_html(html)

        try:
            mail.send(msg)
        except Exception:
            current_app.logger.exception("SMTP send failed")
            # Do not raise; we still continue the web flow.
    except Exception:
        current_app.logger.exception("send_email() wrapper failed")
