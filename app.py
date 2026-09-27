from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
import os
import uuid

from scanner.apk_scanner import APKScanner
from scanner.report_generator import save_json_report

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "uploads")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan_apk():
    file = request.files.get("apk_file")
    if file is None or file.filename == "":
        return render_template("index.html", error="Please upload an APK file.")

    original_name = secure_filename(file.filename)
    if not original_name.lower().endswith(".apk"):
        return render_template("index.html", error="Only APK files are supported.")

    file_uuid = uuid.uuid4().hex
    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], f"{file_uuid}_{original_name}")
    file.save(upload_path)

    try:
        scanner = APKScanner(upload_path)
        report = scanner.scan()
        report_path = save_json_report(report, os.path.join(os.getcwd(), "reports"))
        report["report_file"] = report_path
        return render_template("report.html", report=report)
    except Exception as exc:
        return render_template("index.html", error=f"Error while scanning APK: {str(exc)}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
