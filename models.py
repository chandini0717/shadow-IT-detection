from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="employee")  # admin | employee
    department = db.Column(db.String(80), default="General")
    risk_score = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "department": self.department,
            "risk_score": self.risk_score,
        }


class AttendanceRecord(db.Model):
    __tablename__ = "attendance_records"
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    attendance_date = db.Column(db.Date, nullable=False, default=lambda: datetime.utcnow().date())
    status = db.Column(db.String(20), nullable=False, default="Present")
    check_in = db.Column(db.String(20), default="09:00")
    check_out = db.Column(db.String(20), default="18:00")
    notes = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    employee = db.relationship("User", backref="attendance_records")

    def to_dict(self):
        return {
            "id": self.id,
            "employee_id": self.employee_id,
            "employee_name": self.employee.name if self.employee else None,
            "employee_email": self.employee.email if self.employee else None,
            "attendance_date": self.attendance_date.isoformat() if self.attendance_date else None,
            "status": self.status,
            "check_in": self.check_in,
            "check_out": self.check_out,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class EmployeeOnboarding(db.Model):
    __tablename__ = "employee_onboarding"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(80), default="General")
    role = db.Column(db.String(40), default="employee")
    manager_name = db.Column(db.String(120), default="")
    start_date = db.Column(db.Date, nullable=False, default=lambda: datetime.utcnow().date())
    status = db.Column(db.String(20), default="Pending")
    notes = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.String(120), default="Admin")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "department": self.department,
            "role": self.role,
            "manager_name": self.manager_name,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "status": self.status,
            "notes": self.notes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }


class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    os = db.Column(db.String(60), default="Windows 11")
    last_scanned = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref="devices")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "os": self.os,
            "user": self.user.name if self.user else None,
            "last_scanned": self.last_scanned.isoformat() if self.last_scanned else None,
        }


class ApprovedSoftware(db.Model):
    __tablename__ = "approved_software"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "name": self.name}


RISK_LEVELS = {
    "Dropbox": ("High", "Cloud Storage", 78, "Unsanctioned cloud storage risks data exfiltration and loss of data governance.", "Block and migrate data to approved storage."),
    "Telegram": ("Medium", "Messaging", 55, "Unmonitored messaging app may be used to exfiltrate sensitive information.", "Restrict usage; monitor if business need exists."),
    "uTorrent": ("Critical", "P2P/File Sharing", 92, "P2P clients are a major malware vector and often violate compliance policy.", "Block immediately and scan device for malware."),
    "AnyDesk": ("High", "Remote Access", 80, "Unauthorized remote access tools can be used for unauthorized remote control.", "Block unless explicitly approved by IT for support use."),
    "Unknown Software": ("Critical", "Unknown", 95, "Unidentified application with no known publisher; high potential for malware.", "Quarantine device and investigate immediately."),
    "Personal Cloud Storage Apps": ("High", "Cloud Storage", 75, "Personal storage apps risk uncontrolled data leakage outside company boundary.", "Block and enforce approved storage policy."),
}

DEFAULT_UNKNOWN = ("Medium", "Uncategorized", 50, "Application not recognized by the whitelist; risk undetermined.", "Investigate and classify the application.")


class Application(db.Model):
    __tablename__ = "applications"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id"))
    is_authorized = db.Column(db.Boolean, default=False)
    risk_level = db.Column(db.String(20), default="Low")
    risk_percentage = db.Column(db.Integer, default=0)
    category = db.Column(db.String(80), default="Uncategorized")
    threat_description = db.Column(db.String(255), default="")
    recommended_action = db.Column(db.String(255), default="")
    status = db.Column(db.String(20), default="Pending")  # Pending | Approved | Blocked | Ignored
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    device = db.relationship("Device", backref="applications")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "device": self.device.name if self.device else None,
            "employee": self.device.user.name if self.device and self.device.user else None,
            "is_authorized": self.is_authorized,
            "risk_level": self.risk_level,
            "risk_percentage": self.risk_percentage,
            "category": self.category,
            "threat_description": self.threat_description,
            "recommended_action": self.recommended_action,
            "status": self.status,
            "detected_at": self.detected_at.isoformat() if self.detected_at else None,
        }


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("applications.id"))
    employee = db.Column(db.String(120))
    device = db.Column(db.String(120))
    application_name = db.Column(db.String(120))
    category = db.Column(db.String(80))
    risk_level = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Pending")  # Pending | Approved | Blocked | Ignored
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_sent = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "application_id": self.application_id,
            "employee": self.employee,
            "device": self.device,
            "application": self.application_name,
            "category": self.category,
            "risk": self.risk_level,
            "status": self.status,
            "time": self.created_at.isoformat() if self.created_at else None,
            "email_sent": self.email_sent,
        }
