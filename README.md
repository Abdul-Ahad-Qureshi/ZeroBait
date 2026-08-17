# 🛡️ ZeroBait — Phishing & Threat Intelligence Platform


A comprehensive Cyber Threat Intelligence dashboard, real-time URL heuristic/ML analysis engine, and SOC monitoring toolkit built with **FastAPI**, **Jinja2**, and **Scikit-Learn**.

---

## ✨ Features

- **Live URL Phishing Scanner**: Analyzes target URLs using Shannon Entropy, DNS A/MX/SPF validation, WHOIS age checks, homograph/punycode spoofing detection, and brand impersonation radar.
- **Threat Intelligence Feed**: Global threat tracker, threat levels (Low, Medium, High), and threat distribution metrics.
- **Security Analyst Tools**: Integrated DNS inspector, domain registrar lookup, and reputation checker.
- **SOC Admin & Audit Dashboard**: User management, role-based access control (Admin / Analyst), and audit logging.
- **Interactive API Documentation**: Full OpenAPI/Swagger documentation accessible directly at `/docs` and `/redoc`.

---

## 🚀 Quickstart (Local Run)

### 1. Clone the repository & install Git LFS
```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
git lfs pull
```

### 2. Create and activate a virtual environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
uvicorn app:app --reload --port 8000
```
Open your browser at [http://127.0.0.1:8000](http://127.0.0.1:8000).


