import json
import os
from datetime import datetime


def save_json_report(report, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    report_name = f"scan_report_{timestamp}.json"
    output_path = os.path.join(output_dir, report_name)
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
    return output_path


def summarize_findings(report):
    findings = report.get("findings", [])
    return {
        "total_findings": len(findings),
        "critical": sum(1 for item in findings if item.get("severity") == "critical"),
        "high": sum(1 for item in findings if item.get("severity") == "high"),
        "medium": sum(1 for item in findings if item.get("severity") == "medium"),
        "low": sum(1 for item in findings if item.get("severity") == "low"),
    }


def render_summary(report):
    return {
        "risk_score": report.get("risk_score", 0),
        "risk_level": report.get("risk_level", "low"),
        "summary": summarize_findings(report),
    }


__all__ = ["save_json_report", "summarize_findings", "render_summary"]
