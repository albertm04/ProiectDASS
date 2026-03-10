"""
v1_vulnerable/app.py – Aplicația Flask vulnerabilă (AuthX v1). Rute: /, /register, /login, /logout, /forgot-password, /reset-password/<token>. Port 5000.
"""
import os
from datetime import datetime

from flask import Flask, render_template, request, redirect, url_for, flash, session
from config import (
    SQLALCHEMY_DATABASE_URI,
    SECRET_KEY,
    PERMANENT_SESSION_LIFETIME,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE,
)
from models import db, User, UserRole, AuditLog

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(_BASE_DIR, "templates"))
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = SECRET_KEY
app.config["PERMANENT_SESSION_LIFETIME"] = PERMANENT_SESSION_LIFETIME
app.config["SESSION_COOKIE_HTTPONLY"] = SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
db.init_app(app)


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
        flash("Email și parola sunt obligatorii.", "error")
        return render_template("register.html")
    if password != password_confirm:
        flash("Parolele nu coincid.", "error")
        return render_template("register.html")
    if User.query.filter_by(email=email).first():
        flash("Există deja un cont cu acest email.", "error")
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
        flash("Utilizatorul cu acest email nu există.", "error")
        return render_template("login.html")
    if user.locked:
        flash("Cont blocat. Contactează administratorul.", "error")
        return render_template("login.html")
    if not user.check_password(password):
        flash("Parola este incorectă.", "error")
        return render_template("login.html")
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
    if not user:
        flash("Dacă există un cont cu acest email, vei primi un link de resetare.", "success")
        return redirect(url_for("login"))
    token = f"reset-{user.id}-{user.email}-{datetime.utcnow().strftime('%Y%m%d%H')}"
    user.reset_token = token
    user.reset_token_created = datetime.utcnow()
    db.session.commit()
    reset_url = url_for("reset_password", token=token, _external=True)
    flash(f"Link resetare (v1 ): {reset_url}", "success")
    return redirect(url_for("login"))


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("Token invalid sau expirat.", "error")
        return redirect(url_for("forgot_password"))
    if request.method == "GET":
        return render_template("reset_password.html", token=token)
    password = request.form.get("password") or ""
    password_confirm = request.form.get("password_confirm") or ""
    if not password or password != password_confirm:
        flash("Parola nu este validă sau nu coincide.", "error")
        return render_template("reset_password.html", token=token)
    user.set_password(password)
    db.session.commit()
    _audit("PASSWORD_RESET", "auth", resource_id=str(user.id), user_id=user.id)
    flash("Parola a fost actualizată. Poți face login.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    _init_db()
    app.run(debug=True, port=5000)
