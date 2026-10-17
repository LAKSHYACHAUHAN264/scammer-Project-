# 🛡️ PhishGuard — AI Email Phishing Detector

[![GitHub stars](https://img.shields.io/github/stars/LAKSHYACHAUHAN264/scammer-Project-?style=for-the-badge&color=blue)](https://github.com/LAKSHYACHAUHAN264/scammer-Project-)
[![GitHub forks](https://img.shields.io/github/forks/LAKSHYACHAUHAN264/scammer-Project-?style=for-the-badge&color=purple)](https://github.com/LAKSHYACHAUHAN264/scammer-Project-)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

> **PhishGuard** is an intelligent, full-stack cybersecurity application designed to analyze and detect phishing emails in real-time. By leveraging heuristic rule engines, social engineering detection, brand-spoofing algorithms, and deep URL inspection, PhishGuard shields users from malicious attacks, scams, and credential harvesting.

---

## ✨ Features

- 🔍 **Deep URL & Link Analysis**: Detects suspicious top-level domains (`.xyz`, `.tk`, `.click`), IP-based hosts, punycode/typosquatting, known shorteners (`bit.ly`, `tinyurl`), and excessive subdomains.
- 👤 **Sender & Domain Verification**: Identifies display name spoofing, mismatched sender domains, and free webmail addresses impersonating trusted institutions (e.g., PayPal, Microsoft, Amazon).
- 🧠 **Content & Heuristic NLP Evaluation**: Scans message content for psychological triggers, artificial urgency, fear tactics, threat of account suspension, and sensitive credential prompts.
- 📊 **Risk Scoring Engine (0–100)**: Computes a multi-dimensional threat index:
  - **Verdict Categories**: `LEGITIMATE`, `SUSPICIOUS`, or `PHISHING`
  - **Granular Breakdown**: URL Risk, Sender Risk, Content Risk, Urgency Level, and Legitimacy Rating.
- 💡 **Actionable Security Recommendations**: Provides users with immediate mitigation steps based on specific detected threats.
- 🎨 **Modern Cyber-Themed UI**: Sleek dark mode interface featuring glassmorphism, animated background mesh, reactive status badges, and clean typography.
- ⚡ **Dual Operation Mode**: Runs standalone in any modern web browser or pairs with the high-performance **FastAPI** backend for extended analysis.

---

## 🏗️ Architecture & Project Structure

```
├── 📄 index.html              # Main application web interface
├── 🎨 style.css                # Custom glassmorphism & responsive cyber styling
├── ⚡ app.js                   # Client-side controller, UI interactions & analyzer logic
├── 📄 .gitignore               # Ignored environments, cache, and OS artifacts
├── 📄 README.md                # Project documentation
└── 📁 backend/
    ├── 🐍 main.py              # FastAPI server & threat detection engine
    ├── 📋 requirements.txt     # Backend Python dependencies
    └── ⚙️ start_server.bat     # Windows one-click backend launcher script
```

---

## 🚀 Quick Start Guide

### Option 1: Standalone Web Interface (No Setup Required)

Simply open [`index.html`](index.html) in your favorite web browser:
- Double click `index.html` or run:
  ```powershell
  start index.html
  ```

---

### Option 2: Full-Stack Mode (FastAPI Backend + Web UI)

#### 1. Clone the Repository
```bash
git clone https://github.com/LAKSHYACHAUHAN264/scammer-Project-.git
cd scammer-Project-
```

#### 2. Setup & Launch Backend
Make sure you have **Python 3.9+** installed.

**On Windows:**
Simply double-click `backend/start_server.bat` or run:
```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The API will be available at:
- **API URL**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **ReDoc Documentation**: `http://localhost:8000/redoc`

#### 3. Open the Frontend
Launch [`index.html`](index.html) in your browser. The connection badge in the top right will change to `● Backend Connected`.

---

## 📡 API Reference

### Health Check
```http
GET /health
```
**Response:**
```json
{
  "status": "ok",
  "service": "PhishGuard API",
  "version": "1.0.0"
}
```

### Analyze Email
```http
POST /analyze
Content-Type: application/json
```

**Request Body:**
```json
{
  "sender": "security-alert@paypal-update-account.xyz",
  "subject": "URGENT: Your account has been suspended!",
  "body": "Dear customer, your account has unusual activity. Click http://192.168.1.1/login to verify your password immediately or your funds will be frozen."
}
```

**Response:**
```json
{
  "verdict": "PHISHING",
  "risk_score": 96,
  "breakdown": {
    "url_risk": 0.95,
    "sender_risk": 0.88,
    "content_risk": 0.92,
    "urgency_score": 0.9,
    "legitimacy": 0.05
  },
  "indicators": [
    {
      "severity": "HIGH",
      "description": "Suspicious IP-based URL detected: http://192.168.1.1/login"
    },
    {
      "severity": "HIGH",
      "description": "Sender domain mimics trusted brand (paypal) on suspicious TLD (.xyz)"
    }
  ],
  "recommendations": [
    {
      "icon": "alert-triangle",
      "text": "Do not click any links or download attachments from this email."
    }
  ]
}
```

---

## 🛡️ Detection Capabilities

| Threat Vector | Indicators Checked |
|---|---|
| **Domain & URLs** | Suspicious TLDs, IP hostnames, Punycode, excessive subdomains, link obfuscation, HTTP on sensitive paths |
| **Identity & Brand** | Brand typosquatting (PayPal, Amazon, Google, Microsoft, Apple, Banks), Free webmail spoofing |
| **Social Engineering** | Urgent deadlines ("within 24 hours", "immediate action required"), account lock threats, fake lottery/prizes |
| **Credential Harvesting** | Requests for passwords, OTPs, SSNs, credit card numbers, or PINs |

---

## 💻 Tech Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript (ES6+)
- **Backend**: Python 3, FastAPI, Pydantic, Uvicorn
- **Threat Engine**: Regular expressions, heuristic risk weighting, domain pattern matching

---

## 🤝 Contributing

Contributions are welcome! If you'd like to improve detection rules or add features:
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewRule`)
3. Commit your Changes (`git commit -m 'Add new phishing detection rule'`)
4. Push to the Branch (`git push origin feature/NewRule`)
5. Open a Pull Request

---

## 📝 License

Distributed under the **MIT License**. See `LICENSE` for more information.

---

<p align="center">
  Built with ❤️ for a safer web by <a href="https://github.com/LAKSHYACHAUHAN264"><strong>LAKSHYACHAUHAN264</strong></a>
</p>
