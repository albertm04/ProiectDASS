"""
v1_vulnerable/config.py – Setări pentru versiunea vulnerabilă (DB, sesiune, cookie).
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "authx_v1.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False

SECRET_KEY = "authx-insecure-secret-key-12345"
PERMANENT_SESSION_LIFETIME = 60 * 60 * 24 * 365

SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_SAMESITE = "Lax"
