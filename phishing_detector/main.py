import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, Response
from flask_login import login_required, current_user

from extensions import db
from models import ScanHistory
from detection.analyzer import analyze_email
from detection.report import generate_report, report_to_text

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/about")
def about():
    return render_template("about.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    recent = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .limit(5)
        .all()
    )
    total = ScanHistory.query.filter_by(user_id=current_user.id).count()
    phishing_count = ScanHistory.query.filter_by(user_id=current_user.id, verdict="phishing").count()
    suspicious_count = ScanHistory.query.filter_by(user_id=current_user.id, verdict="suspicious").count()
    safe_count = ScanHistory.query.filter_by(user_id=current_user.id, verdict="safe").count()

    return render_template(
        "dashboard.html",
        recent=recent,
        total=total,
        phishing_count=phishing_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
    )


@main_bp.route("/scan", methods=["POST"])
@login_required
def scan():
    sender = request.form.get("sender", "").strip()
    subject = request.form.get("subject", "").strip()
    body = request.form.get("body", "").strip()

    if not body:
        flash("Please paste the email body to analyze.", "error")
        return redirect(url_for("main.dashboard"))

    result = analyze_email(sender, subject, body)

    record = ScanHistory(
        user_id=current_user.id,
        subject=subject or "(no subject)",
        sender=sender or "(unknown sender)",
        raw_text=body,
        verdict=result["verdict"],
        risk_score=result["score"],
        reasons=json.dumps(result["reasons"]),
    )
    db.session.add(record)
    db.session.commit()

    return redirect(url_for("main.result", scan_id=record.id))


@main_bp.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    record = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    reasons = json.loads(record.reasons or "[]")
    return render_template("result.html", record=record, reasons=reasons)


@main_bp.route("/report/<int:scan_id>")
@login_required
def report_view(scan_id):
    record = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    reasons = json.loads(record.reasons or "[]")
    report = generate_report(record, reasons, recipient_username=current_user.username)
    return render_template("report.html", record=record, report=report)


@main_bp.route("/report/<int:scan_id>/download")
@login_required
def report_download(scan_id):
    record = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    reasons = json.loads(record.reasons or "[]")
    report = generate_report(record, reasons, recipient_username=current_user.username)
    text = report_to_text(report)

    filename = f"incident_report_scan_{scan_id}.txt"
    return Response(
        text,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@main_bp.route("/history")
@login_required
def history():
    page = request.args.get("page", 1, type=int)
    pagination = (
        ScanHistory.query.filter_by(user_id=current_user.id)
        .order_by(ScanHistory.created_at.desc())
        .paginate(page=page, per_page=10, error_out=False)
    )
    return render_template("history.html", pagination=pagination)


@main_bp.route("/history/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_history(scan_id):
    record = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(record)
    db.session.commit()
    flash("Scan record deleted.", "success")
    return redirect(url_for("main.history"))


@main_bp.route("/api/stats")
@login_required
def api_stats():
    total = ScanHistory.query.filter_by(user_id=current_user.id).count()
    phishing_count = ScanHistory.query.filter_by(user_id=current_user.id, verdict="phishing").count()
    suspicious_count = ScanHistory.query.filter_by(user_id=current_user.id, verdict="suspicious").count()
    safe_count = ScanHistory.query.filter_by(user_id=current_user.id, verdict="safe").count()
    return jsonify(
        {
            "total": total,
            "phishing": phishing_count,
            "suspicious": suspicious_count,
            "safe": safe_count,
        }
    )
