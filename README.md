# Advanced APK Security Scanner

A legal, security-focused static analysis tool for Android APK files. It helps security researchers and developers review app risk signals including manifest permissions, exported components, cleartext traffic, hardcoded secrets, and insecure URLs.

This project is designed for authorized security testing only.

## Features

- APK upload and analysis through a Flask web app
- Manifest inspection for dangerous permissions and exported entry points
- Risk scoring with severity levels
- Cleartext traffic and backup vulnerability detection
- Hardcoded secrets scanning in APK content
- Insecure HTTP URL detection
- JSON report export and browser report view
- Ready for extension with more rule sets and integrations

## Project Structure

```text
AdvancedAPKSecurityScanner/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── scanner/
│   ├── __init__.py
│   ├── apk_scanner.py
│   ├── report_generator.py
│   └── utils.py
├── templates/
│   ├── index.html
│   └── report.html
└── reports/
```

## Quick Start

1. Clone the repository
2. Create a virtual environment
3. Install dependencies
4. Run the app

```bash
git clone https://github.com/saifmohamed777/AdvancedAPKSecurityScanner.git
cd AdvancedAPKSecurityScanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Usage

- Upload an APK file
- The scanner inspects the manifest and file contents
- Review the generated report with severity labels and findings
- Export JSON output when needed

## Legal Notice

Use only on APKs you own or have explicit written authorization to test. This project is intended for legitimate security review, vulnerability assessment, and developer hardening work.

## License

MIT License
