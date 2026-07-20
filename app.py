import io
import csv
import random
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
)

from config import Config
from models import (
    db, User, Device, ApprovedSoftware, Application, Alert,
    AttendanceRecord, EmployeeOnboarding, RISK_LEVELS, DEFAULT_UNKNOWN,
)
from code_analysis import analyze_code

try:
    from openpyxl import Workbook
    HAS_OPENPYXL = True
except ImportError:
    HAS_OPENPYXL = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Allow the React dev server (and any origin during local dev) to call the API
    CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

    db.init_app(app)
    jwt = JWTManager(app)

    with app.app_context():
        db.create_all()
        seed_data()

    register_routes(app)

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error", "detail": str(e)}), 500

    return app


APPROVED = [
    "Microsoft Office", "Microsoft Teams", "Google Chrome",
    "Microsoft Edge", "Visual Studio Code", "Slack",
]
UNAUTHORIZED = list(RISK_LEVELS.keys())


def seed_data():
    if User.query.first():
        return

    admin = User(name="Admin User", email="admin@company.com", role="admin", department="IT")
    admin.set_password("admin123")
    db.session.add(admin)

    employees_data = [
        ("likitha", "likitha@gmail.com", "HR"),
        ("Alice Johnson", "alice@company.com", "Finance"),
        ("David Lee", "david@company.com", "IT"),
        ("Priya Nair", "priya@company.com", "Marketing"),
        ("Carlos Gomez", "carlos@company.com", "Sales"),
    ]
    employees = []
    for name, email, dept in employees_data:
        u = User(name=name, email=email, role="employee", department=dept)
        u.set_password("employee123")
        db.session.add(u)
        employees.append(u)
    db.session.commit()

    for name in APPROVED:
        db.session.add(ApprovedSoftware(name=name))
    db.session.commit()

    devices = []
    for emp in employees:
        d = Device(name=f"{emp.name.split()[0]}-Laptop", user_id=emp.id, os=random.choice(["Windows 11", "macOS Sonoma", "Windows 10"]))
        db.session.add(d)
        devices.append(d)
    db.session.commit()

    # Seed some authorized + shadow applications with alerts
    for device in devices:
        for app_name in random.sample(APPROVED, k=3):
            db.session.add(Application(
                name=app_name, device_id=device.id, is_authorized=True,
                risk_level="Low", risk_percentage=5, category="Productivity",
                status="Approved",
            ))
        if random.random() < 0.7:
            shadow_name = random.choice(UNAUTHORIZED)
            level, category, pct, desc, action = RISK_LEVELS.get(shadow_name, DEFAULT_UNKNOWN)
            app_row = Application(
                name=shadow_name, device_id=device.id, is_authorized=False,
                risk_level=level, risk_percentage=pct, category=category,
                threat_description=desc, recommended_action=action,
                status="Pending",
                detected_at=datetime.utcnow() - timedelta(hours=random.randint(0, 48)),
            )
            db.session.add(app_row)
            db.session.flush()
            device.user.risk_score = max(device.user.risk_score, pct)
            db.session.add(Alert(
                application_id=app_row.id,
                employee=device.user.name,
                device=device.name,
                application_name=shadow_name,
                category=category,
                risk_level=level,
                status="Pending",
                created_at=app_row.detected_at,
                email_sent=level in ("High", "Critical"),
            ))
    db.session.commit()


def register_routes(app):

    # ---------------------------------------------------------------- AUTH
    @app.route("/api/login", methods=["POST"])
    def login():
        data = request.get_json(silent=True) or {}
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        user = User.query.filter(db.func.lower(User.email) == email).first()
        if not user or not user.check_password(password):
            return jsonify({"error": "Invalid email or password"}), 401

        token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "name": user.name},
        )
        return jsonify({"token": token, "user": user.to_dict()})

    @app.route("/api/me", methods=["GET"])
    @jwt_required()
    def me():
        user = User.query.get(int(get_jwt_identity()))
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user.to_dict())

    # ----------------------------------------------------------- DASHBOARD
    @app.route("/api/dashboard", methods=["GET"])
    @jwt_required()
    def dashboard():
        total_users = User.query.filter_by(role="employee").count()
        total_devices = Device.query.count()
        authorized_apps = Application.query.filter_by(is_authorized=True).count()
        unauthorized_apps = Application.query.filter_by(is_authorized=False).count()
        high_risk = Application.query.filter(Application.risk_level.in_(["High", "Critical"])).count()
        today = datetime.utcnow().date()
        alerts_today = Alert.query.filter(db.func.date(Alert.created_at) == today).count()

        risk_scores = [u.risk_score for u in User.query.filter_by(role="employee").all()]
        overall_risk = round(sum(risk_scores) / len(risk_scores)) if risk_scores else 0

        risk_breakdown = {}
        for level in ["Low", "Medium", "High", "Critical"]:
            risk_breakdown[level] = Application.query.filter_by(risk_level=level, is_authorized=False).count()

        category_breakdown = {}
        for row in db.session.query(Application.category, db.func.count(Application.id)).filter_by(is_authorized=False).group_by(Application.category).all():
            category_breakdown[row[0] or "Uncategorized"] = row[1]

        return jsonify({
            "total_users": total_users,
            "total_devices": total_devices,
            "authorized_apps": authorized_apps,
            "unauthorized_apps": unauthorized_apps,
            "high_risk_apps": high_risk,
            "alerts_today": alerts_today,
            "overall_risk_score": overall_risk,
            "risk_breakdown": risk_breakdown,
            "category_breakdown": category_breakdown,
        })

    # -------------------------------------------------------------- USERS
    @app.route("/api/users", methods=["GET"])
    @jwt_required()
    def list_users():
        users = User.query.filter_by(role="employee").all()
        return jsonify([u.to_dict() for u in users])

    # ----------------------------------------------------------- ATTENDANCE
    @app.route("/api/attendance", methods=["GET"])
    @jwt_required()
    def list_attendance():
        employee_id = request.args.get("employee_id")
        date = request.args.get("date")
        q = AttendanceRecord.query
        if employee_id:
            q = q.filter_by(employee_id=int(employee_id))
        if date:
            q = q.filter(AttendanceRecord.attendance_date == datetime.strptime(date, "%Y-%m-%d").date())
        records = q.order_by(AttendanceRecord.attendance_date.desc(), AttendanceRecord.created_at.desc()).all()
        return jsonify([r.to_dict() for r in records])

    @app.route("/api/attendance/mark", methods=["POST"])
    @jwt_required()
    def mark_attendance():
        data = request.get_json(silent=True) or {}
        employee_id = data.get("employee_id")
        if not employee_id:
            return jsonify({"error": "employee_id is required"}), 400

        attendance_date = data.get("attendance_date") or datetime.utcnow().date().isoformat()
        try:
            attendance_date = datetime.strptime(attendance_date, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"error": "attendance_date must be YYYY-MM-DD"}), 400

        record = AttendanceRecord.query.filter_by(employee_id=employee_id, attendance_date=attendance_date).first()
        if not record:
            record = AttendanceRecord(employee_id=employee_id, attendance_date=attendance_date)

        record.status = data.get("status", record.status or "Present")
        record.check_in = data.get("check_in", record.check_in or "09:00")
        record.check_out = data.get("check_out", record.check_out or "18:00")
        record.notes = data.get("notes", record.notes or "")
        db.session.add(record)
        db.session.commit()
        return jsonify(record.to_dict())

    @app.route("/api/attendance/<int:record_id>", methods=["DELETE"])
    @jwt_required()
    def delete_attendance(record_id):
        record = AttendanceRecord.query.get(record_id)
        if not record:
            return jsonify({"error": "Attendance record not found"}), 404
        db.session.delete(record)
        db.session.commit()
        return jsonify({"message": "Attendance record deleted"})

    # -------------------------------------------------------- ONBOARDING
    @app.route("/api/onboarding", methods=["GET"])
    @jwt_required()
    def list_onboarding():
        records = EmployeeOnboarding.query.order_by(EmployeeOnboarding.created_at.desc()).all()
        return jsonify([r.to_dict() for r in records])

    @app.route("/api/onboarding", methods=["POST"])
    @jwt_required()
    def create_onboarding():
        data = request.get_json(silent=True) or {}
        name = (data.get("name") or "").strip()
        email = (data.get("email") or "").strip().lower()
        if not name or not email:
            return jsonify({"error": "name and email are required"}), 400

        existing = EmployeeOnboarding.query.filter_by(email=email).first() or User.query.filter(db.func.lower(User.email) == email).first()
        if existing:
            return jsonify({"error": "Employee with this email already exists"}), 400

        start_date = data.get("start_date") or datetime.utcnow().date().isoformat()
        try:
            start_date = datetime.strptime(start_date, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"error": "start_date must be YYYY-MM-DD"}), 400

        onboarding = EmployeeOnboarding(
            name=name,
            email=email,
            department=data.get("department", "General"),
            role=data.get("role", "employee"),
            manager_name=data.get("manager_name", ""),
            start_date=start_date,
            status=data.get("status", "Pending"),
            notes=data.get("notes", ""),
            created_by=data.get("created_by", "Admin"),
        )
        db.session.add(onboarding)
        db.session.commit()

        if data.get("create_user", False):
            user = User(name=name, email=email, role=data.get("role", "employee"), department=data.get("department", "General"))
            user.set_password(data.get("password") or "Welcome123!")
            db.session.add(user)
            db.session.commit()

        return jsonify(onboarding.to_dict()), 201

    @app.route("/api/onboarding/<int:record_id>", methods=["DELETE"])
    @jwt_required()
    def delete_onboarding(record_id):
        record = EmployeeOnboarding.query.get(record_id)
        if not record:
            return jsonify({"error": "Onboarding record not found"}), 404
        db.session.delete(record)
        db.session.commit()
        return jsonify({"message": "Onboarding record deleted"})

    # ------------------------------------------------------------ DEVICES
    @app.route("/api/devices", methods=["GET"])
    @jwt_required()
    def list_devices():
        devices = Device.query.all()
        return jsonify([d.to_dict() for d in devices])

    # -------------------------------------------------------- APPLICATIONS
    @app.route("/api/applications", methods=["GET"])
    @jwt_required()
    def list_applications():
        status = request.args.get("status")
        risk = request.args.get("risk")
        q = Application.query
        if status:
            q = q.filter_by(status=status)
        if risk:
            q = q.filter_by(risk_level=risk)
        apps = q.order_by(Application.detected_at.desc()).all()
        return jsonify([a.to_dict() for a in apps])

    # ----------------------------------------------------------- SCAN
    @app.route("/api/scan", methods=["POST"])
    @jwt_required()
    def scan():
        """Simulate scanning installed applications on employee devices."""
        devices = Device.query.all()
        new_alerts = []
        candidate_pool = APPROVED + UNAUTHORIZED

        for device in devices:
            simulated_app = random.choice(candidate_pool)
            existing = Application.query.filter_by(device_id=device.id, name=simulated_app).first()
            if existing:
                continue

            is_authorized = simulated_app in APPROVED
            if is_authorized:
                db.session.add(Application(
                    name=simulated_app, device_id=device.id, is_authorized=True,
                    risk_level="Low", risk_percentage=5, category="Productivity",
                    status="Approved",
                ))
                continue

            level, category, pct, desc, action = RISK_LEVELS.get(simulated_app, DEFAULT_UNKNOWN)
            app_row = Application(
                name=simulated_app, device_id=device.id, is_authorized=False,
                risk_level=level, risk_percentage=pct, category=category,
                threat_description=desc, recommended_action=action,
                status="Pending",
            )
            db.session.add(app_row)
            db.session.flush()

            if device.user:
                device.user.risk_score = max(device.user.risk_score, pct)

            email_sent = level in ("High", "Critical")
            alert = Alert(
                application_id=app_row.id,
                employee=device.user.name if device.user else "Unknown",
                device=device.name,
                application_name=simulated_app,
                category=category,
                risk_level=level,
                status="Pending",
                email_sent=email_sent,
            )
            db.session.add(alert)
            db.session.flush()

            if email_sent:
                send_alert_email(alert)

            new_alerts.append(alert.to_dict())

        db.session.commit()
        return jsonify({"message": "Scan complete", "new_alerts": new_alerts, "count": len(new_alerts)})

    # ------------------------------------------------------------ ALERTS
    @app.route("/api/alerts", methods=["GET"])
    @jwt_required()
    def list_alerts():
        search = request.args.get("search", "").strip().lower()
        status = request.args.get("status")
        risk = request.args.get("risk")

        q = Alert.query
        if status:
            q = q.filter_by(status=status)
        if risk:
            q = q.filter_by(risk_level=risk)
        alerts = q.order_by(Alert.created_at.desc()).all()

        if search:
            alerts = [a for a in alerts if search in a.employee.lower() or search in a.application_name.lower() or search in a.device.lower()]

        return jsonify([a.to_dict() for a in alerts])

    @app.route("/api/approve", methods=["POST"])
    @jwt_required()
    def approve():
        return _update_status(request, "Approved")

    @app.route("/api/block", methods=["POST"])
    @jwt_required()
    def block():
        return _update_status(request, "Blocked")

    @app.route("/api/ignore", methods=["POST"])
    @jwt_required()
    def ignore():
        return _update_status(request, "Ignored")

    def _update_status(req, new_status):
        data = req.get_json(silent=True) or {}
        alert_id = data.get("alert_id")
        alert = Alert.query.get(alert_id)
        if not alert:
            return jsonify({"error": "Alert not found"}), 404
        alert.status = new_status
        if alert.application_id:
            app_row = Application.query.get(alert.application_id)
            if app_row:
                app_row.status = new_status
                if new_status == "Approved":
                    app_row.is_authorized = True
        db.session.commit()
        return jsonify({"message": f"Alert {new_status.lower()}", "alert": alert.to_dict()})

    # -------------------------------------------------------------- RISK
    @app.route("/api/risk", methods=["GET"])
    @jwt_required()
    def risk_summary():
        breakdown = {}
        for level in ["Low", "Medium", "High", "Critical"]:
            breakdown[level] = Application.query.filter_by(risk_level=level, is_authorized=False).count()
        top_risky = Application.query.filter(Application.is_authorized == False).order_by(Application.risk_percentage.desc()).limit(10).all()
        return jsonify({
            "breakdown": breakdown,
            "top_risky_applications": [a.to_dict() for a in top_risky],
        })

    # -------------------------------------------------- CODE SOURCE/RISK
    @app.route("/api/analyze-code", methods=["POST"])
    @jwt_required()
    def analyze_code_route():
        data = request.get_json(silent=True) or {}
        code = data.get("code", "")
        result = analyze_code(code)
        if "error" in result:
            return jsonify(result), 400
        return jsonify(result)

    # ----------------------------------------------------------- REPORTS
    @app.route("/api/reports", methods=["GET"])
    @jwt_required()
    def reports():
        fmt = request.args.get("format", "csv").lower()
        apps = Application.query.filter_by(is_authorized=False).order_by(Application.detected_at.desc()).all()

        rows = [[
            a.id, a.device.user.name if a.device and a.device.user else "N/A",
            a.device.name if a.device else "N/A", a.name, a.risk_level,
            a.risk_percentage, a.status, a.detected_at.strftime("%Y-%m-%d %H:%M") if a.detected_at else ""
        ] for a in apps]
        headers = ["ID", "Employee", "Device", "Application", "Risk Level", "Risk %", "Status", "Detected At"]

        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(headers)
            writer.writerows(rows)
            mem = io.BytesIO(buf.getvalue().encode("utf-8"))
            return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="shadow_it_report.csv")

        elif fmt == "excel":
            if not HAS_OPENPYXL:
                return jsonify({"error": "Excel export unavailable (openpyxl not installed)"}), 500
            wb = Workbook()
            ws = wb.active
            ws.title = "Shadow IT Report"
            ws.append(headers)
            for row in rows:
                ws.append(row)
            mem = io.BytesIO()
            wb.save(mem)
            mem.seek(0)
            return send_file(mem, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                              as_attachment=True, download_name="shadow_it_report.xlsx")

        elif fmt == "pdf":
            if not HAS_REPORTLAB:
                return jsonify({"error": "PDF export unavailable (reportlab not installed)"}), 500
            mem = io.BytesIO()
            doc = SimpleDocTemplate(mem, pagesize=letter)
            styles = getSampleStyleSheet()
            elements = [Paragraph("Shadow IT Detection Report", styles["Title"])]
            table_data = [headers] + [[str(c) for c in row] for row in rows]
            table = Table(table_data, repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(table)
            doc.build(elements)
            mem.seek(0)
            return send_file(mem, mimetype="application/pdf", as_attachment=True, download_name="shadow_it_report.pdf")

        return jsonify({"error": "Invalid format. Use csv, excel, or pdf."}), 400

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok", "service": "Shadow IT Detection Platform API"})


def send_alert_email(alert):
    """
    Sends (or, if SMTP isn't configured, logs) an email notification to the
    IT administrator. This keeps the demo runnable without real SMTP creds.
    """
    from flask import current_app

    subject = "Shadow IT Alert Detected"
    body = (
        f"Unauthorized application detected.\n\n"
        f"Employee: {alert.employee}\n"
        f"Device: {alert.device}\n"
        f"Application: {alert.application_name}\n"
        f"Risk Level: {alert.risk_level}\n"
        f"Detection Time: {alert.created_at}\n\n"
        f"Immediate action is recommended."
    )

    mail_server = current_app.config.get("MAIL_SERVER")
    if not mail_server:
        current_app.logger.info("[EMAIL SIMULATED - no SMTP configured]\nSubject: %s\n%s", subject, body)
        return

    try:
        import smtplib
        from email.mime.text import MIMEText

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = current_app.config["MAIL_USERNAME"]
        msg["To"] = current_app.config["ADMIN_EMAIL"]

        with smtplib.SMTP(mail_server, current_app.config["MAIL_PORT"]) as server:
            server.starttls()
            server.login(current_app.config["MAIL_USERNAME"], current_app.config["MAIL_PASSWORD"])
            server.send_message(msg)
    except Exception as e:
        current_app.logger.warning("Email send failed (continuing without blocking request): %s", e)


app = create_app()

if __name__ == "__main__":
    import os
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_mode)
