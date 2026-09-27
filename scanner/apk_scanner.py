import hashlib
import re
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
import json


class APKScanner:
    ANDROID_NS = "http://schemas.android.com/apk/res/android"
    TEXT_EXTENSIONS = (".xml", ".txt", ".smali", ".java", ".kt", ".properties", ".json", ".gradle", ".pro")

    def __init__(self, apk_path):
        self.apk_path = Path(apk_path)
        self.findings = []
        self.severity_scores = {"critical": 40, "high": 25, "medium": 15, "low": 5}

    @staticmethod
    def is_valid_apk(path):
        try:
            with zipfile.ZipFile(path) as archive:
                return "AndroidManifest.xml" in archive.namelist()
        except Exception:
            return False

    def scan(self):
        if not self.apk_path.exists() or not self.is_valid_apk(self.apk_path):
            raise ValueError("Invalid APK: AndroidManifest.xml not found")

        manifest_root = self._load_manifest()
        
        # جمع كل البيانات
        permissions = self._check_permissions(manifest_root)
        components = self._check_components(manifest_root)
        app_findings = self._check_application_config(manifest_root)
        storage_findings = self._check_insecure_storage()
        network_findings = self._check_network_security()
        database_findings = self._check_database_vulns()
        crypto_findings = self._check_crypto_issues()
        auth_findings = self._check_auth_vulns()
        code_findings = self._check_code_vulns()
        webview_findings = self._check_webview_vulns()
        secret_findings = self._check_hardcoded_secrets()
        logging_findings = self._check_sensitive_logging()
        broadcast_findings = self._check_unsafe_broadcasts(manifest_root)
        sql_injection_findings = self._check_sql_injection()
        
        # حساب الـ score
        score = self._calculate_score()
        
        return {
            "apk_name": self.apk_path.name,
            "sha256": self._sha256(),
            "scan_time": datetime.now(timezone.utc).isoformat(),
            "package_name": manifest_root.attrib.get("package", "unknown") if manifest_root else "unknown",
            "permissions": permissions,
            "exported_components": components,
            "findings": self.findings,
            "findings_count": len(self.findings),
            "critical_count": len([f for f in self.findings if f["severity"] == "critical"]),
            "high_count": len([f for f in self.findings if f["severity"] == "high"]),
            "medium_count": len([f for f in self.findings if f["severity"] == "medium"]),
            "low_count": len([f for f in self.findings if f["severity"] == "low"]),
            "risk_score": min(100, score),
            "risk_level": self._get_risk_level(score),
        }

    def _load_manifest(self):
        try:
            with zipfile.ZipFile(self.apk_path) as archive:
                return ET.fromstring(archive.read("AndroidManifest.xml"))
        except Exception:
            return None

    def _check_permissions(self, root):
        if root is None:
            return []
        permissions = []
        for item in root.findall("uses-permission"):
            perm = item.attrib.get(f"{{{self.ANDROID_NS}}}name")
            if perm:
                permissions.append(perm)
        return sorted(set(permissions))

    def _check_components(self, root):
        if root is None:
            return []
        components = []
        for tag in ("activity", "service", "receiver", "provider"):
            for elem in root.iter(tag):
                name = elem.attrib.get(f"{{{self.ANDROID_NS}}}name")
                if name:
                    exported = elem.attrib.get(f"{{{self.ANDROID_NS}}}exported", "false")
                    permission = elem.attrib.get(f"{{{self.ANDROID_NS}}}permission")
                    components.append({"type": tag, "name": name, "exported": exported, "permission": permission})
                    
                    # تحقق من المكونات المصدرة بدون حماية
                    if exported.lower() == "true" and not permission:
                        self._add_finding("critical", "Unprotected Exported Component", 
                                        f"{tag} '{name}' is exported without permission protection. Can be accessed by any app.",
                                        {"component_type": tag, "component_name": name})
        return components

    def _check_application_config(self, root):
        if root is None:
            return
        app = root.find("application")
        if app is None:
            return
        
        # debuggable
        if app.attrib.get(f"{{{self.ANDROID_NS}}}debuggable") == "true":
            self._add_finding("critical", "App is Debuggable", 
                            "Application is debuggable in production. Attackers can inspect, modify code at runtime.",
                            {"attribute": "debuggable"})
        
        # allowBackup
        allow_backup = app.attrib.get(f"{{{self.ANDROID_NS}}}allowBackup")
        if allow_backup is None or allow_backup == "true":
            self._add_finding("high", "Backup Data Enabled", 
                            "allowBackup is enabled. Sensitive app data can be extracted via adb backup.",
                            {"attribute": "allowBackup"})
        
        # usesCleartextTraffic
        if app.attrib.get(f"{{{self.ANDROID_NS}}}usesCleartextTraffic") == "true":
            self._add_finding("high", "Cleartext Traffic Enabled", 
                            "usesCleartextTraffic is enabled. HTTP traffic will not be encrypted.",
                            {"attribute": "usesCleartextTraffic"})

    def _check_insecure_storage(self):
        """فحص التخزين غير الآمن للبيانات الحساسة"""
        patterns = [
            (r"SharedPreferences|getSharedPreferences", "SharedPreferences (insecure by default)"),
            (r"SQLiteDatabase|openDatabase", "SQLite without encryption"),
            (r"FileOutputStream|write.*File", "Writing to internal/external storage"),
            (r"new File\(", "Direct file operations without encryption"),
            (r"getExternalFilesDir|getExternalCacheDir", "External storage access (world-readable)"),
        ]
        
        for pattern, description in patterns:
            count = self._search_in_files(pattern)
            if count > 0:
                self._add_finding("high", f"Insecure Storage: {description}",
                                f"Found {count} instances of potentially insecure storage mechanism.",
                                {"pattern": pattern, "count": count})

    def _check_network_security(self):
        """فحص أمان الشبكة"""
        # HTTP URLs
        http_urls = self._find_http_urls()
        if http_urls:
            self._add_finding("high", "Plaintext HTTP URLs Detected",
                            f"Found {len(http_urls)} HTTP endpoints. Should use HTTPS.",
                            {"urls": http_urls[:5], "count": len(http_urls)})
        
        # تحقق من عدم التحقق من SSL
        patterns = [
            (r"ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier.*verify.*true", "SSL Hostname Verification Bypass"),
            (r"trustAllCerts|X509TrustManager.*checkClientTrusted.*{}", "SSL Certificate Verification Disabled"),
            (r"SSLContext\.getInstance|setDefaultHostnameVerifier", "Custom SSL/TLS handling (potential weakness)"),
        ]
        
        for pattern, desc in patterns:
            if self._search_in_files(pattern) > 0:
                self._add_finding("critical", desc,
                                "Detected potential SSL/TLS verification bypass. Vulnerable to MITM attacks.",
                                {"pattern": pattern})

    def _check_database_vulns(self):
        """فحص ثغرات قاعدة البيانات"""
        patterns = [
            (r"getReadableDatabase|getWritableDatabase.*raw", "Raw database access without encryption"),
            (r"execSQL\(['\"].*\$|execSQL.*concat|select.*FROM.*WHERE|insert.*into", "SQL Injection vulnerability"),
            (r"SQLiteDatabase\.rawQuery|db\.rawQuery", "Raw SQL queries (SQL injection risk)"),
        ]
        
        for pattern, desc in patterns:
            count = self._search_in_files(pattern)
            if count > 0:
                self._add_finding("high", f"Database Security Issue: {desc}",
                                f"Detected {count} instances of potentially vulnerable database operations.",
                                {"pattern": pattern, "count": count})

    def _check_crypto_issues(self):
        """فحص مشاكل التشفير"""
        patterns = [
            (r"ECB|DES|MD5|SHA1(?!256|384|512)", "Weak cryptographic algorithm"),
            (r"Random\(\)|Math\.random\(\)", "Weak random number generator"),
            (r"SecureRandom\(\).*new", "Potentially insecure SecureRandom initialization"),
            (r"Cipher\.getInstance\(['\"].*ECB", "ECB mode encryption (deterministic)"),
        ]
        
        for pattern, desc in patterns:
            if self._search_in_files(pattern) > 0:
                self._add_finding("high", f"Cryptography Issue: {desc}",
                                "Weak or insecure cryptographic implementation detected.",
                                {"pattern": pattern})

    def _check_auth_vulns(self):
        """فحص ثغرات المصادقة"""
        patterns = [
            (r"hardcoded.*password|password.*=.*['\"][^'\"]{4,}", "Hardcoded credentials"),
            (r"sharedUserId|permission.*android:name=\"android\.permission\.(READ|WRITE)\"" , "Shared User ID or dangerous permissions"),
            (r"checkPermission.*false|enforcePermission.*false", "Permission enforcement bypassed"),
        ]
        
        for pattern, desc in patterns:
            if self._search_in_files(pattern) > 0:
                self._add_finding("critical", f"Authentication Issue: {desc}",
                                "Detected potential authentication/authorization vulnerability.",
                                {"pattern": pattern})

    def _check_code_vulns(self):
        """فحص ثغرات الكود"""
        patterns = [
            (r"System\.load|Runtime\.exec|ProcessBuilder", "Native code execution"),
            (r"Intent.*startActivity|startService|sendBroadcast.*component", "Implicit intent usage (potential hijacking)"),
            (r"getIntent\(\).*getStringExtra|getSerializableExtra.*cast", "Unsafe intent data handling"),
        ]
        
        for pattern, desc in patterns:
            count = self._search_in_files(pattern)
            if count > 0:
                self._add_finding("medium", f"Code Security: {desc}",
                                f"Found {count} instances of potentially vulnerable code pattern.",
                                {"pattern": pattern, "count": count})

    def _check_webview_vulns(self):
        """فحص ثغرات WebView"""
        patterns = [
            (r"WebView|addJavascriptInterface", "WebView detected"),
            (r"setJavaScriptEnabled\(true\)|allowFileAccess\(true\)", "WebView with dangerous settings"),
            (r"shouldInterceptRequest|loadUrl.*file://", "Potential XSS/Local file access via WebView"),
        ]
        
        for pattern, desc in patterns:
            count = self._search_in_files(pattern)
            if count > 0:
                if "dangerous" in desc:
                    severity = "high"
                else:
                    severity = "medium"
                self._add_finding(severity, f"WebView Issue: {desc}",
                                f"Found {count} instances. Ensure WebView security controls are in place.",
                                {"pattern": pattern, "count": count})

    def _check_hardcoded_secrets(self):
        """فحص الأسرار المخزنة بشكل مباشر"""
        patterns = [
            r"(?i)(api[_-]?key|secret|token|password|private[_-]?key|client[_-]?secret|bearer|authorization)\s*[:=]\s*[\"']?([A-Za-z0-9/+=._:-]{12,})",
            r"(?i)aws[_-]?(access[_-]?key|secret[_-]?access|key|id)\s*[:=]",
            r"(?i)db[_-]?password|database[_-]?password\s*[:=]",
            r"(?i)admin[_-]?password|user[_-]?password\s*[:=]",
            r"(?i)firebase[_-]?key|google[_-]?api[_-]?key\s*[:=]",
        ]
        
        secrets_found = []
        try:
            with zipfile.ZipFile(self.apk_path) as archive:
                for name in archive.namelist():
                    if not name.lower().endswith(self.TEXT_EXTENSIONS):
                        continue
                    text = archive.read(name).decode("utf-8", errors="ignore")
                    for pattern in patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            secrets_found.append({"file": name, "pattern": pattern[:30]})
        except Exception:
            pass
        
        if secrets_found:
            self._add_finding("critical", "Hardcoded Secrets Detected",
                            f"Found {len(secrets_found)} potential hardcoded secrets/credentials in {len(set(f['file'] for f in secrets_found))} files.",
                            {"files": list(set(f["file"] for f in secrets_found))[:5], "count": len(secrets_found)})

    def _check_sensitive_logging(self):
        """فحص تسجيل البيانات الحساسة"""
        patterns = [
            (r"Log\.d|Log\.v|System\.out\.println|Log\.e.*password|Log\.e.*token", "Sensitive data logging"),
            (r"Toast\.makeText.*password|Toast\.makeText.*token|Toast\.makeText.*email", "Sensitive data in Toast messages"),
        ]
        
        for pattern, desc in patterns:
            count = self._search_in_files(pattern)
            if count > 0:
                self._add_finding("high", f"Logging Issue: {desc}",
                                f"Found {count} instances. Ensure sensitive data is not logged.",
                                {"pattern": pattern, "count": count})

    def _check_unsafe_broadcasts(self, root):
        """فحص Broadcasts غير الآمن"""
        if root is None:
            return
        for receiver in root.iter("receiver"):
            name = receiver.attrib.get(f"{{{self.ANDROID_NS}}}name")
            exported = receiver.attrib.get(f"{{{self.ANDROID_NS}}}exported", "false")
            if exported.lower() == "true" and not receiver.attrib.get(f"{{{self.ANDROID_NS}}}permission"):
                self._add_finding("high", "Unprotected Broadcast Receiver",
                                f"Broadcast receiver '{name}' is exported without permission. Can receive broadcasts from any app.",
                                {"receiver": name})

    def _check_sql_injection(self):
        """فحص حقن SQL"""
        patterns = [
            r"rawQuery|execSQL|query.*\+.*string|select.*from.*where.*\+",
            r"select.*\$\{|select.*%s.*format|database.*query.*concat",
        ]
        
        for pattern in patterns:
            count = self._search_in_files(pattern)
            if count > 0:
                self._add_finding("critical", "SQL Injection Vulnerability",
                                f"Found {count} instances of potential SQL injection vulnerabilities. Use parameterized queries.",
                                {"pattern": pattern, "count": count})

    def _find_http_urls(self):
        urls = set()
        try:
            with zipfile.ZipFile(self.apk_path) as archive:
                for name in archive.namelist():
                    if not name.lower().endswith(self.TEXT_EXTENSIONS):
                        continue
                    text = archive.read(name).decode("utf-8", errors="ignore")
                    urls.update(re.findall(r"http://[^\s\"'<>{}]+", text))
        except Exception:
            pass
        return sorted(list(urls))

    def _search_in_files(self, pattern):
        count = 0
        try:
            with zipfile.ZipFile(self.apk_path) as archive:
                for name in archive.namelist():
                    if not name.lower().endswith(self.TEXT_EXTENSIONS):
                        continue
                    text = archive.read(name).decode("utf-8", errors="ignore")
                    count += len(re.findall(pattern, text, re.IGNORECASE))
        except Exception:
            pass
        return count

    def _add_finding(self, severity, title, description, details=None):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "details": details or {}
        })

    def _calculate_score(self):
        score = 0
        for finding in self.findings:
            score += self.severity_scores.get(finding["severity"], 0)
        return min(100, score)

    def _get_risk_level(self, score):
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        return "LOW"

    def _sha256(self):
        sha256_hash = hashlib.sha256()
        with open(self.apk_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
