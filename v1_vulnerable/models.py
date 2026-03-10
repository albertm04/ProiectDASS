"""
v1_vulnerable/models.py – Modele SQLAlchemy: User (parolă MD5), Ticket, AuditLog.
"""
import hashlib
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
import enum

db = SQLAlchemy()


class UserRole(enum.Enum):
    USER = "USER"
    ANALYST = "ANALYST"
    MANAGER = "MANAGER"


class TicketSeverity(enum.Enum):
    LOW = "LOW"
    MED = "MED"
    HIGH = "HIGH"


class TicketStatus(enum.Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    locked = db.Column(db.Boolean, default=False, nullable=False)
    reset_token = db.Column(db.String(255), nullable=True)
    reset_token_created = db.Column(db.DateTime, nullable=True)

    tickets = db.relationship("Ticket", backref="owner", foreign_keys="Ticket.owner_id")
    audit_logs = db.relationship("AuditLog", backref="user", foreign_keys="AuditLog.user_id")

    def set_password(self, raw_password: str) -> None:
        self.password_hash = hashlib.md5(raw_password.encode()).hexdigest()

    def check_password(self, raw_password: str) -> bool:
        return self.password_hash == hashlib.md5(raw_password.encode()).hexdigest()


class Ticket(db.Model):
    __tablename__ = "tickets"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.Enum(TicketSeverity), default=TicketSeverity.LOW)
    status = db.Column(db.Enum(TicketStatus), default=TicketStatus.OPEN)
    owner_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    resource = db.Column(db.String(64), nullable=False)
    resource_id = db.Column(db.String(64), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
