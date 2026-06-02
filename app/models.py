from app import db
from datetime import datetime, timezone
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user') #admin or auditor
    created_at =db.Column(db.DateTime, default=datetime.now(timezone.utc))


class ScanTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    system_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    checks = db.relationship('ComplianceCheck', backref='target', lazy=True)


class ComplianceCheck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target_id = db.Column(db.Integer, db.ForeignKey('scan_target.id'), nullable=False)
    requirement = db.Column(db.String(20))
    description = db.Column(db.String(200))
    status = db.Column(db.String(20))
    evidence = db.Column(db.Text)
    risk_level = db.Column(db.String(20))
    scanned_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))


class RemediationTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey('compliance_check.id'), nullable=False)
    description = db.Column(db.Text)
    assigned_to = db.Column(db.String(100))
    status = db.Column(db.String(20), default='Open')
    due_date = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    