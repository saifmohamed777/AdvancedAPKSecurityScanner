from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
import os
import uuid
from pathlib import Path

from scanner.apk_scanner import APKScanner
from scanner.report_generator import save_json_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["REPORT_FOLDER"] = str(REPORT_DIR)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_apk():
    if "apk_file" not in request.files:
        return render_template("index.html", error="No file uploaded"), 400

    file = request.files["apk_file"]
    if file.filename == "":
        return render_template("index.html", error="No file selected"), 400

    if not file.filename.lower().endswith(".apk"):
        return render_template("index.html", error="Only APK files are allowed"), 400

    filename = secure_filename(file.filename)
    file_uuid = uuid.uuid4().hex
    upload_path = UPLOAD_DIR / f"{file_uuid}_{filename}"
    
    try:
        file.save(upload_path)
        
        if not APKScanner.is_valid_apk(upload_path):
            upload_path.unlink()
            return render_template("index.html", error="Invalid APK file"), 400
        
        scanner = APKScanner(upload_path)
        report = scanner.scan()
        report_path = save_json_report(report, REPORT_DIR)
        report["report_file"] = f"/download_report/{Path(report_path).name}"
        
        # Clean up
        upload_path.unlink(missing_ok=True)
        
        return render_template("report.html", report=report)
    
    except Exception as exc:
        upload_path.unlink(missing_ok=True)
        return render_template("index.html", error=f"Scan failed: {str(exc)}"), 500


@app.route("/download_report/<filename>")
def download_report(filename):
    safe_path = REPORT_DIR / filename
    if not safe_path.exists() or not str(safe_path).startswith(str(REPORT_DIR)):
        return jsonify({"error": "File not found"}), 404
    
    from flask import send_file
    return send_file(safe_path, as_attachment=True)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "Advanced APK Security Scanner"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
