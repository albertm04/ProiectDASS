"""
v2_secure/app.py – Aplicația Flask securizată (AuthX v2). Aceleași rute ca v1, cu validare parolă, mesaj generic la login, rate limiting, token reset one-time. Port 5001.
"""
import os
import secrets
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt

from config import (
    SQLALCHEMY_DATABASE_URI,
    SECRET_KEY,
    PERMANENT_SESSION_LIFETIME,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE,
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_REQUIRE_UPPER,
    PASSWORD_REQUIRE_LOWER,
    PASSWORD_REQUIRE_DIGIT,
    LOGIN_MAX_ATTEMPTS,
    LOCKOUT_MINUTES,
    RESET_TOKEN_EXPIRY_HOURS,
)
from models import db, User, UserRole, AuditLog

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_DUMMY_HASH = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.G2nYqBqRlQK.8e"

app = Flask(__name__, template_folder=os.path.join(_BASE_DIR, "templates"))
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_COOKIE_HTTPONLY"] = SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
db.init_app(app)
bcrypt = Bcrypt(app)
app.bcrypt = bcrypt


def _get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or ""


def _audit(action: str, resource: str, resource_id: str = None, user_id: int = None):
    with app.app_context():
        log = AuditLog(
            user_id=user_id or (session.get("user_id") if session else None),
            action=action,
            resource=resource,
            resource_id=resource_id,
            ip_address=_get_client_ip(),
        )
        db.session.add(log)
        db.session.commit()


def _validate_password(password: str) -> tuple[bool, str]:
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Parola trebuie să aibă cel puțin {PASSWORD_MIN_LENGTH} caractere."
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, "Parola este prea lungă."
    if PASSWORD_REQUIRE_UPPER and not any(c.isupper() for c in password):
        return False, "Parola trebuie să conțină cel puțin o literă mare."
    if PASSWORD_REQUIRE_LOWER and not any(c.islower() for c in password):
        return False, "Parola trebuie să conțină cel puțin o literă mică."
    if PASSWORD_REQUIRE_DIGIT and not any(c.isdigit() for c in password):
        return False, "Parola trebuie să conțină cel puțin o cifră."
    return True, ""


@app.context_processor
def inject_user():
    user = None
    if session.get("user_id"):
        user = User.query.get(session["user_id"])
    return {"current_user": user}


def _init_db():
    with app.app_context():
        db.create_all()


@app.route("/")
def index():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    password_confirm = request.form.get("password_confirm") or ""
    if not email or not password:
        flash("Date invalide. Verifică emailul și parola.", "error")
        return render_template("register.html")
    ok, err = _validate_password(password)
    if not ok:
        flash(err, "error")
        return render_template("register.html")
    if password != password_confirm:
        flash("Parolele nu coincid.", "error")
        return render_template("register.html")
    if User.query.filter_by(email=email).first():
        flash("Date invalide. Verifică emailul și parola.", "error")
        return render_template("register.html")
    user = User(email=email, role=UserRole.USER)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    _audit("REGISTER", "auth", resource_id=str(user.id), user_id=user.id)
    flash("Cont creat. Poți face login.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    user = User.query.filter_by(email=email).first()
    if not user:
        bcrypt.check_password_hash(_DUMMY_HASH, password)
        _audit("LOGIN_FAIL", "auth", resource_id=email or None, user_id=None)
        flash("Credențiale invalide.", "error")
        return render_template("login.html")
    if user.is_locked_out():
        db.session.commit()
        flash("Cont blocat temporar. Încearcă mai târziu.", "error")
        return render_template("login.html")
    if not user.check_password(password):
        user.failed_login_count += 1
        if user.failed_login_count >= LOGIN_MAX_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        db.session.commit()
        _audit("LOGIN_FAIL", "auth", resource_id=str(user.id), user_id=user.id)
        flash("Credențiale invalide.", "error")
        return render_template("login.html")
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()
    session.permanent = True
    session["user_id"] = user.id
    _audit("LOGIN", "auth", resource_id=str(user.id), user_id=user.id)
    flash("Te-ai autentificat cu succes.", "success")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    uid = session.get("user_id")
    if uid:
        _audit("LOGOUT", "auth", resource_id=str(uid), user_id=uid)
    session.clear()
    flash("Ai fost deconectat.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")
    email = (request.form.get("email") or "").strip().lower()
    user = User.query.filter_by(email=email).first()
    flash("Dacă există un cont cu acest email, vei primi un link de resetare.", "success")
    if not user:
        return redirect(url_for("login"))
    token = secrets.token_urlsafe(32)
    user.reset_token = token
    user.reset_token_created = datetime.utcnow()
    db.session.commit()
    reset_url = url_for("reset_password", token=token, _external=True)
    flash(f"Link resetare (lab): {reset_url}", "success")
    return redirect(url_for("login"))


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_created:
        flash("Link invalid sau expirat.", "error")
        return redirect(url_for("forgot_password"))
    expiry = user.reset_token_created + timedelta(hours=RESET_TOKEN_EXPIRY_HOURS)
    if datetime.utcnow() > expiry:
        user.reset_token = None
        user.reset_token_created = None
        db.session.commit()
        flash("Link invalid sau expirat.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "GET":
        return render_template("reset_password.html", token=token)
    password = request.form.get("password") or ""
    password_confirm = request.form.get("password_confirm") or ""
    ok, err = _validate_password(password)
    if not ok:
        flash(err, "error")
        return render_template("reset_password.html", token=token)
    if password != password_confirm:
        flash("Parolele nu coincid.", "error")
        return render_template("reset_password.html", token=token)
    user.set_password(password)
    user.reset_token = None
    user.reset_token_created = None
    db.session.commit()
    _audit("PASSWORD_RESET", "auth", resource_id=str(user.id), user_id=user.id)
    flash("Parola a fost actualizată. Poți face login.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    _init_db()
    app.run(debug=True, port=5001)
