import json
import os
from datetime import datetime, timezone


def save_json_report(report, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"scan_report_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path = os.path.join(output_dir, filename)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
    return path


def summarize_findings(report):
    findings = report.get("findings", [])
    return {level: sum(item.get("severity") == level for item in findings) for level in ("critical", "high", "medium", "low")}
