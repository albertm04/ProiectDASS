"""
v2_secure/config.py – Setări pentru versiunea securizată: DB, sesiune, cookie, politică parolă, rate limit, token reset.
"""
import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "authx_v2.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
PERMANENT_SESSION_LIFETIME = 60 * 60

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = "Strict"

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
PASSWORD_REQUIRE_UPPER = True
PASSWORD_REQUIRE_LOWER = True
PASSWORD_REQUIRE_DIGIT = True

LOGIN_MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

RESET_TOKEN_EXPIRY_HOURS = 1
