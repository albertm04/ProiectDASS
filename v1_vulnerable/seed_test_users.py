"""
v1_vulnerable/seed_test_users.py – Creează 3 utilizatori de test în DB v1. Rulezi după ce ai pornit app.py o dată.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, _init_db
from models import User, UserRole, db

with app.app_context():
    _init_db()
    if User.query.filter_by(email="victim@test.com").first():
        print("Utilizatorii de test există deja în v1.")
    else:
        for email, password in [
            ("victim@test.com", "123"),
            ("admin@test.com", "parola"),
            ("user@test.com", "1"),
        ]:
            u = User(email=email, role=UserRole.USER)
            u.set_password(password)
            db.session.add(u)
        db.session.commit()
        print("v1: Am creat 3 utilizatori de test.")
        print("  victim@test.com / 123")
        print("  admin@test.com  / parola")
        print("  user@test.com   / 1")
