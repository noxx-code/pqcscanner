# AegisGuard PQC Scanner v2.1.0

**Quantum-Safe Cryptographic Scanner · CBOM Generator · PQC Certificate Issuer**

AegisGuard scans TLS endpoints for post-quantum cryptography readiness, generates
Cryptographic Bills of Materials (CBOM) in CycloneDX 1.6 format, and issues
compliance certificates against NIST FIPS 203/204/205 standards.

---

## Features

| Feature | Description |
|---------|-------------|
| **TLS Probe** | Raw socket scanning with cipher/KEX/certificate extraction |
| **PQC Analysis** | ML-KEM, ML-DSA, SLH-DSA detection with known-host heuristics |
| **Risk Scoring** | Weighted 0–100 scoring with grade (A+ to F) |
| **CBOM Export** | CycloneDX 1.6 compliant JSON with remediation plans |
| **PQC Certificate** | PDF compliance certificate for fully quantum-safe assets |
| **Bulk Scan** | Concurrent scanning of up to 20 targets |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the server
python run.py

# 3. Open dashboard
# http://127.0.0.1:8000
```

## Project Structure

```
prototype20/
├── backend/
│   └── app/
│       ├── __init__.py
│       ├── config.py          # Constants, crypto databases
│       ├── models.py          # Pydantic request/response models
│       ├── main.py            # FastAPI server + scan orchestration
│       └── services/
│           ├── tls_probe.py       # Raw TLS scanning engine
│           ├── pqc_analyzer.py    # PQC readiness detection
│           ├── risk_scorer.py     # Weighted risk scoring
│           ├── cbom_generator.py  # CycloneDX CBOM builder
│           └── certificate_issuer.py  # PDF certificate generator
├── frontend/
│   ├── index.html             # Dashboard HTML
│   ├── css/
│   │   └── style.css          # Premium dark-mode theme
│   └── js/
│       └── dashboard.js       # Vanilla JS controller
├── run.py                     # Startup script
├── requirements.txt           # Python dependencies
└── start.sh                   # Linux/macOS launcher
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Dashboard UI |
| `GET` | `/health` | Server health check |
| `POST` | `/scan` | Single target scan |
| `POST` | `/scan/bulk` | Bulk scan (max 20) |
| `POST` | `/cbom` | Export CBOM as JSON |
| `POST` | `/certificate` | Generate PQC certificate PDF |
| `GET` | `/scan/test` | Quick test scan (example.com) |

## NIST Standards

- **FIPS 203** — ML-KEM (Kyber) key encapsulation
- **FIPS 204** — ML-DSA (Dilithium) digital signatures
- **FIPS 205** — SLH-DSA (SPHINCS+) hash-based signatures

## License

Internal use only.
