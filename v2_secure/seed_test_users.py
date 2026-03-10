"""
v2_secure/seed_test_users.py – Creează 3 utilizatori de test în DB v2. Rulezi după ce ai pornit app.py o dată.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, _init_db
from models import User, UserRole, db

with app.app_context():
    _init_db()
    if User.query.filter_by(email="victim@test.com").first():
        print("Utilizatorii de test există deja în v2.")
    else:
        for email, password in [
            ("victim@test.com", "Parola123"),
            ("admin@test.com", "Admin123!"),
            ("user@test.com", "User2024"),
        ]:
            u = User(email=email, role=UserRole.USER)
            u.set_password(password)
            db.session.add(u)
        db.session.commit()
        print("v2: Am creat 3 utilizatori de test.")
        print("  victim@test.com / Parola123")
        print("  admin@test.com  / Admin123!")
        print("  user@test.com   / User2024")
