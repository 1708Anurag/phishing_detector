from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="member")  # member | admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship("ScanHistory", backref="user", lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    subject = db.Column(db.String(255))
    sender = db.Column(db.String(255))
    raw_text = db.Column(db.Text, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)  # phishing | suspicious | safe
    risk_score = db.Column(db.Float, nullable=False)
    reasons = db.Column(db.Text)  # JSON-encoded list of reason strings
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
