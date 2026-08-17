# 🛡️ ZeroBait — Phishing & Threat Intelligence Platform

A comprehensive Cyber Threat Intelligence dashboard, real-time URL heuristic/ML analysis engine, and SOC monitoring toolkit built with **FastAPI**, **Jinja2**, and **Scikit-Learn**.

---

## 📑 Table of Contents
- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Quickstart](#-quickstart-local-run)
- [Usage](#-usage)
- [License](#-license)

---

## ✨ Features

* **Live URL Phishing Scanner:** Analyzes target URLs using Shannon Entropy, DNS A/MX/SPF validation, WHOIS age checks, homograph/punycode spoofing detection, and brand impersonation radar.
* **Threat Intelligence Feed:** Global threat tracker, threat levels (Low, Medium, High), and threat distribution metrics.
* **Security Analyst Tools:** Integrated DNS inspector, domain registrar lookup, and reputation checker.
* **SOC Admin & Audit Dashboard:** User management, role-based access control (Admin / Analyst), and audit logging.
* **Interactive API Documentation:** Full OpenAPI/Swagger documentation accessible directly at `/docs` and `/redoc`.

---

## ⚙️ Prerequisites

Before you begin, ensure you have the following installed:
* [Python 3.8+](https://www.python.org/downloads/)
* [Git Large File Storage (LFS)](https://git-lfs.com/)

---

## 🚀 Quickstart (Local Run)

### 1. Clone the repository & pull LFS files
```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
git lfs pull
```

### 2. Create and activate a virtual environment

**For Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**For Linux / macOS:**
```bash
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

---

## 💻 Usage

Once the server is running, you can access the platform and its tools via your web browser:

* **Main Dashboard:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
