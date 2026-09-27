import os
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime


class APKScanner:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_name = os.path.basename(apk_path)

    def scan(self):
        if not os.path.exists(self.apk_path):
            raise FileNotFoundError(f"APK was not found: {self.apk_path}")

        manifest_root = self._read_manifest_xml()
        permissions = self._extract_permissions(manifest_root)
        exported_components = self._extract_exported_components(manifest_root)
        findings = self._collect_findings(manifest_root, permissions, exported_components)

        report = {
            "apk_name": self.apk_name,
            "scan_time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "package_name": self._extract_package_name(manifest_root),
            "version_name": self._extract_version_name(manifest_root),
            "version_code": self._extract_version_code(manifest_root),
            "permissions": permissions,
            "exported_components": exported_components,
            "findings": findings,
        }
        report["risk_score"] = self._calculate_risk_score(findings)
        report["risk_level"] = self._risk_level(report["risk_score"])
        return report

    def _read_manifest_xml(self):
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                manifest_name = next((n for n in zf.namelist() if n.endswith("AndroidManifest.xml")), None)
                if not manifest_name:
                    return None
                data = zf.read(manifest_name)
                return ET.fromstring(data)
        except Exception:
            return None

    def _extract_package_name(self, manifest_root):
        if manifest_root is None:
            return "unknown"
        return manifest_root.attrib.get("package", "unknown")

    def _extract_version_name(self, manifest_root):
        if manifest_root is None:
            return "unknown"
        manifest = manifest_root.find("manifest")
        if manifest is not None:
            return manifest.attrib.get("versionName", "unknown")
        return "unknown"

    def _extract_version_code(self, manifest_root):
        if manifest_root is None:
            return "unknown"
        manifest = manifest_root.find("manifest")
        if manifest is not None:
            return manifest.attrib.get("versionCode", "unknown")
        return "unknown"

    def _extract_permissions(self, manifest_root):
        if manifest_root is None:
            return []

        ns = "http://schemas.android.com/apk/res/android"
        perms = []
        for item in manifest_root.findall("./uses-permission"):
            perm_name = item.attrib.get(f"{{{ns}}}name")
            if perm_name:
                perms.append(perm_name)
        return sorted(set(perms))

    def _extract_exported_components(self, manifest_root):
        if manifest_root is None:
            return []

        ns = "http://schemas.android.com/apk/res/android"
        results = []
        for tag in ["activity", "service", "receiver", "provider"]:
            for elem in manifest_root.iter(tag):
                name = elem.attrib.get(f"{{{ns}}}name")
                if not name:
                    continue
                results.append({
                    "type": tag,
                    "name": name,
                    "exported": elem.attrib.get(f"{{{ns}}}exported", "false"),
                    "permission": elem.attrib.get(f"{{{ns}}}permission"),
                })
        return results

    def _collect_findings(self, manifest_root, permissions, exported_components):
        findings = []

        if manifest_root is None:
            return [{
                "severity": "medium",
                "title": "Manifest could not be parsed",
                "description": "The APK manifest could not be parsed, so static review coverage is limited.",
            }]

        ns = "http://schemas.android.com/apk/res/android"
        app = manifest_root.find("application")
        if app is not None:
            allow_backup = app.attrib.get(f"{{{ns}}}allowBackup")
            cleartext = app.attrib.get(f"{{{ns}}}usesCleartextTraffic")
            debuggable = app.attrib.get(f"{{{ns}}}debuggable")

            if allow_backup is None or str(allow_backup).lower() == "true":
                findings.append({
                    "severity": "high",
                    "title": "Backup is enabled",
                    "description": "allowBackup is enabled. Sensitive app data may be exposed through backups.",
                })

            if cleartext and str(cleartext).lower() == "true":
                findings.append({
                    "severity": "high",
                    "title": "Cleartext traffic is enabled",
                    "description": "The app allows unencrypted HTTP traffic, which may leak sensitive data.",
                })

            if debuggable and str(debuggable).lower() == "true":
                findings.append({
                    "severity": "medium",
                    "title": "App is debuggable",
                    "description": "The application may expose debugging data in production builds.",
                })

        risky_permissions = {
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CALL_PHONE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.GET_ACCOUNTS",
        }

        for permission in permissions:
            if permission in risky_permissions:
                findings.append({
                    "severity": "medium",
                    "title": "Sensitive permission requested",
                    "description": f"The app requests a sensitive Android permission: {permission}",
                    "permission": permission,
                })

        for component in exported_components:
            if str(component.get("exported", "false")).lower() == "true":
                findings.append({
                    "severity": "high",
                    "title": "Exported component detected",
                    "description": f"{component['type']} {component['name']} is exported and may be reachable externally.",
                    "component": component,
                })

        insecure_urls = self._find_insecure_http_urls()
        if insecure_urls:
            findings.append({
                "severity": "high",
                "title": "Insecure HTTP endpoints detected",
                "description": "The APK contains plaintext HTTP URLs, which can expose sensitive data.",
                "urls": insecure_urls[:10],
            })

        secrets = self._find_hardcoded_secrets()
        if secrets:
            findings.append({
                "severity": "critical",
                "title": "Potential hardcoded secrets found",
                "description": "Sensitive values may be embedded inside APK resources or code strings.",
                "matches": secrets[:10],
            })

        if not findings:
            findings.append({
                "severity": "low",
                "title": "No clear issues were found",
                "description": "The static scan did not flag obvious critical risks in this APK.",
            })

        return findings

    def _find_insecure_http_urls(self):
        matches = set()
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                for name in zf.namelist():
                    if not name.lower().endswith((".xml", ".txt", ".smali", ".java", ".kt", ".properties", ".json", ".gradle")):
                        continue
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    for match in re.findall(r"https?://[^\s\"'<>]+", content, flags=re.IGNORECASE):
                        matches.add(match)
        except Exception:
            pass
        return sorted(matches)

    def _find_hardcoded_secrets(self):
        secret_patterns = [
            r"(?i)(api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret)\s*[:=]\s*[\"']?([A-Za-z0-9/+=._:-]{8,})",
            r"(?i)Bearer\s+[A-Za-z0-9._~+/-]+=*",
            r"(?i)(authorization|auth[_-]?token)\s*[:=]\s*[\"']?[A-Za-z0-9._~+/-]{12,}",
        ]
        results = []
        try:
            with zipfile.ZipFile(self.apk_path) as zf:
                for name in zf.namelist():
                    if not name.lower().endswith((".xml", ".txt", ".smali", ".java", ".kt", ".properties", ".json", ".gradle")):
                        continue
                    try:
                        content = zf.read(name).decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    for pattern in secret_patterns:
                        for item in re.findall(pattern, content, flags=re.IGNORECASE):
                            if isinstance(item, tuple):
                                label, value = item
                                results.append({"file": name, "label": label, "value": value[:40]})
                            else:
                                results.append({"file": name, "value": str(item)[:40]})
        except Exception:
            pass
        return results

    def _calculate_risk_score(self, findings):
        weights = {"critical": 30, "high": 20, "medium": 10, "low": 3}
        score = 0
        for finding in findings:
            score += weights.get(finding.get("severity", "low"), 3)
        return min(score, 100)

    def _risk_level(self, score):
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"
