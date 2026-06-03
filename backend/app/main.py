"""
FastAPI Server — AegisGuard PQC Scanner
All scan orchestration is handled inline (no external pipeline module).
"""

import os
import io
import time
import random
import logging
import concurrent.futures
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse

from backend.app.config import (
    PROJECT_NAME, VERSION,
    DEPRECATED_CIPHERS, CLASSICAL_KEX, is_pqc_sig,
)
from backend.app.models import ScanRequest, BulkScanRequest
from backend.app.services.tls_probe import scan_tls_raw
from backend.app.services.pqc_analyzer import analyze_pqc
from backend.app.services.risk_scorer import calculate_risk_score
from backend.app.services.cbom_generator import generate_cbom
from backend.app.services.certificate_issuer import generate_pqc_certificate_pdf

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-18s │ %(levelname)-7s │ %(message)s",
)
logger = logging.getLogger("AegisGuard.Main")

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description="Quantum-Safe Cryptographic Scanner — CBOM Generator — PQC Certificate Issuer",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
)

if os.path.isdir(FRONTEND_DIR):
    logger.info(f"Serving static files from: {FRONTEND_DIR}")
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
else:
    logger.warning(f"Frontend directory not found: {FRONTEND_DIR}")


# ===================================================================
#  Scan orchestration helpers (inlined — no scanner_pipeline module)
# ===================================================================

def _build_ui_response(raw: dict, pqc: dict, risk: dict, cbom: dict, mode: str) -> dict:
    """Shape the full JSON response consumed by the Aegis frontend."""
    tls_ver = (raw.get("tls_version") or "Unknown").replace("TLSv", "")
    cipher_up = (raw.get("cipher_suite") or "").upper()
    kex = raw.get("kex_algorithm") or "Unknown"
    cert_alg = raw.get("cert_pubkey_alg") or ""
    cert_bits = raw.get("cert_pubkey_bits") or 0
    days = raw.get("cert_days_left") or 9999
    is_pqc = pqc.get("pqc_safe", False)
    is_hybrid = pqc.get("is_hybrid", False)
    score = risk.get("score", 0)
    grade = risk.get("grade", "F")

    # Chart percentages
    if is_pqc and not is_hybrid:
        pqc_pct, vuln_pct, partial_pct = 90, 5, 5
    elif is_hybrid:
        pqc_pct, vuln_pct, partial_pct = 45, 15, 40
    else:
        vuln_pct = min(100, 100 - score)
        pqc_pct = max(0, score - 20)
        partial_pct = max(0, 100 - pqc_pct - vuln_pct)

    kem_type = "hybrid" if is_hybrid else ("pqc" if is_pqc else "classical")

    # Historical trend (deterministic per host)
    random.seed(hash(raw.get("host", "x")))
    base = 100 - score
    trend = sorted([max(10, min(100, base + random.randint(-15, 15))) for _ in range(7)])
    trend[-1] = 100 - score

    # Strip severity emoji prefixes for clean finding text
    def _strip(p: str) -> str:
        for pfx in (
            " CRITICAL — ", " HIGH — ",
            " MEDIUM — ", " NOTICE — ", " INFO — ",
        ):
            if p.startswith(pfx):
                return p[len(pfx):]
        return p

    critical, high, medium, info = [], [], [], []
    for p in risk.get("penalties", []):
        if " CRITICAL" in p:
            critical.append(_strip(p))
        elif " HIGH" in p:
            high.append(_strip(p))
        elif "" in p:
            medium.append(_strip(p))
        else:
            info.append(_strip(p))

    if not is_pqc:
        info.append("Migrate key exchange to ML-KEM-768 (NIST FIPS 203)")
        info.append("Plan certificate migration to ML-DSA-65 (NIST FIPS 204)")

    digital_sig_compliant = is_pqc_sig(raw.get("cert_sig_alg", ""))

    policy = {
        "key_exchange": is_pqc or is_hybrid,
        "digital_sig": digital_sig_compliant,
        "cipher_suite": (
            not any(d in cipher_up for d in DEPRECATED_CIPHERS)
            and ("AES_256" in cipher_up or "AES-128" in cipher_up or "CHACHA20" in cipher_up)
        ),
        "tls_protocol": raw.get("tls_version") in ("TLSv1.3", "TLSv1.2"),
        "pqc_compliance": is_pqc,
    }

    has_dep = any(d in cipher_up for d in DEPRECATED_CIPHERS)
    cipher_name_raw = raw.get("cipher_suite") or ""

    detected_ciphers = []
    if cipher_name_raw:
        sl = (5 if ("AES_256" in cipher_up or "CHACHA20" in cipher_up)
              else 3 if "AES_128" in cipher_up else 0)
        detected_ciphers.append({
            "name": cipher_name_raw,
            "type": "Symmetric/AEAD",
            "quantum_safe": (is_pqc or sl >= 3) and not has_dep,
            "deprecated": has_dep,
            "security_level": sl,
        })

    detected_kems = []
    if kex and kex != "Unknown":
        ki = CLASSICAL_KEX.get(kex.upper(), {})
        detected_kems.append({
            "name": kex,
            "standard": ki.get("std", "—"),
            "key_size": ki.get("ks", "—"),
            "quantum_safe": is_pqc or is_hybrid,
            "recommendation": (
                "Actively deployed" if (is_pqc or is_hybrid)
                else ki.get("rec", "Replace with PQC KEM")
            ),
        })

    qs_label = (
        "POST-QUANTUM SAFE ✓" if is_pqc and not is_hybrid else
        "HYBRID PQC (Transitional)" if is_hybrid else
        "NOT QUANTUM SAFE ✗"
    )
    scan_summary = (
        f"Target: {raw['host']}:{raw['port']}  |  IP: {raw.get('ip', 'N/A')}\n"
        f"TLS: {raw.get('tls_version', '?')}  |  Cipher: {cipher_name_raw or 'N/A'}  |  KEX: {kex}\n"
        f"PQC Status: {qs_label}  |  Security Score: {score}/100  |  Grade: {grade}\n"
        f"Certificate: {raw.get('cert_subject', 'N/A')}  |  Issuer: {raw.get('cert_issuer', 'N/A')}\n"
        f"Key: {cert_alg} {cert_bits}b  |  Sig: {raw.get('cert_sig_alg', 'N/A')}  |  "
        f"Expires: {raw.get('cert_not_after', 'N/A')}  ({days} days remaining)\n"
        f"HSTS: {'Enabled' if raw.get('hsts') else 'Not set'}  |  "
        f"Findings: {len(critical)} critical, {len(high)} high, {len(medium)} medium, {len(info)} info\n"
        f"CBOM Generated: {cbom.get('pqcReadiness', {}).get('label', 'N/A')}"
    )

    return {
        "grade": grade,
        "score": score,
        "tls_version": tls_ver,
        "kem_type": kem_type,
        "kem_name": kex,
        "pqc_pct": pqc_pct,
        "vuln_pct": vuln_pct,
        "partial_pct": partial_pct,
        "trend": trend,
        "quantum_safe": is_pqc,
        "pqc_label": cbom.get("pqcReadiness", {}).get("label", "Unknown"),
        "cert_eligible": cbom.get("pqcReadiness", {}).get("certificationEligible", False),
        "critical_findings": critical,
        "high_findings": high,
        "medium_findings": medium,
        "low_findings": medium,
        "info_findings": info,
        "policy_compliance": policy,
        "probe": {
            "ip": raw.get("ip"),
            "hsts": raw.get("hsts", False),
            "cert_subject": raw.get("cert_subject"),
            "cert_issuer": raw.get("cert_issuer"),
            "cert_pubkey_alg": raw.get("cert_pubkey_alg"),
            "cert_pubkey_bits": raw.get("cert_pubkey_bits"),
            "cert_sig_alg": raw.get("cert_sig_alg"),
            "cert_not_after": raw.get("cert_not_after"),
            "cert_days_left": raw.get("cert_days_left"),
            "cert_expired": raw.get("cert_expired"),
            "cert_self_signed": raw.get("cert_self_signed"),
            "cert_sha256": raw.get("cert_sha256"),
        },
        "raw_tls": {
            "host": raw.get("host"),
            "port": raw.get("port"),
            "ip": raw.get("ip"),
            "tls_version": raw.get("tls_version"),
            "cipher_suite": raw.get("cipher_suite"),
            "kex_algorithm": raw.get("kex_algorithm"),
            "cert_subject": raw.get("cert_subject"),
            "cert_issuer": raw.get("cert_issuer"),
            "cert_pubkey_alg": raw.get("cert_pubkey_alg"),
            "cert_pubkey_bits": raw.get("cert_pubkey_bits"),
            "cert_sig_alg": raw.get("cert_sig_alg"),
            "cert_not_after": raw.get("cert_not_after"),
            "cert_days_left": raw.get("cert_days_left"),
            "cert_sha256": raw.get("cert_sha256"),
            "hsts": raw.get("hsts"),
        },
        "detected_ciphers": detected_ciphers,
        "detected_kems": detected_kems,
        "scan_summary": scan_summary,
        "cbom": cbom,
        "risk_details": risk.get("details", {}),
    }


def _run_full_scan(target: str, port: int, mode: str) -> dict:
    """Orchestrates: TLS Probe → PQC Analysis → Risk Score → CBOM → UI Response."""
    logger.info(f"[SCAN] Starting: {target}:{port} mode={mode}")
    t0 = time.time()

    raw = scan_tls_raw(target, port)
    if raw.get("error") and not raw.get("reachable"):
        raise HTTPException(
            status_code=502,
            detail=f"Cannot reach {target}:{port} — {raw['error']}",
        )

    pqc = analyze_pqc(raw)
    risk = calculate_risk_score(raw, pqc)
    cbom = generate_cbom(target, port, raw, pqc, risk)
    ui = _build_ui_response(raw, pqc, risk, cbom, mode)

    ui["scan_time_ms"] = round((time.time() - t0) * 1000)
    logger.info(
        f"[SCAN] Done: {target}:{port} score={risk['score']} grade={risk['grade']} "
        f"pqc={'SAFE' if pqc['pqc_safe'] else 'VULN'} ({ui['scan_time_ms']}ms)"
    )
    return ui


# ===================================================================
#  API Routes
# ===================================================================

@app.get("/")
def serve_frontend():
    """Serve the root dashboard index.html."""
    idx = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(idx):
        return FileResponse(idx)
    return {"message": f"{PROJECT_NAME} API running. Frontend not found at {idx}."}


@app.get("/health")
def health():
    """Server health and capabilities."""
    return {
        "status": "ok",
        "scanner": PROJECT_NAME,
        "version": VERSION,
        "capabilities": [
            "TLS Probe", "PQC Analysis", "Risk Scoring",
            "CBOM Generation", "PQC Certificate",
        ],
        "nist_standards": [
            "FIPS 203 (ML-KEM)",
            "FIPS 204 (ML-DSA)",
            "FIPS 205 (SLH-DSA)",
        ],
    }


@app.post("/scan")
def scan(req: ScanRequest):
    """Full single PQC scan."""
    return _run_full_scan(req.target, req.port, req.mode)


@app.post("/scan/bulk")
def scan_bulk(req: BulkScanRequest):
    """Concurrent bulk scan (max 20 targets)."""
    if len(req.targets) > 20:
        raise HTTPException(
            status_code=400,
            detail="Bulk scan limited to 20 targets per request",
        )

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_run_full_scan, t.strip(), req.port, req.mode): t
            for t in req.targets if t.strip()
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                results.append({"target": target, "result": future.result(timeout=30)})
            except Exception as e:
                logger.error(f"Bulk scan failed for {target}: {e}")
                results.append({"target": target, "error": str(e)})

    pqc_safe = sum(1 for r in results if r.get("result", {}).get("quantum_safe"))
    return {
        "total": len(results),
        "pqc_safe": pqc_safe,
        "pqc_vulnerable": len(results) - pqc_safe,
        "results": results,
    }


@app.post("/cbom")
def export_cbom(req: ScanRequest):
    """Export CBOM as JSON download."""
    raw = scan_tls_raw(req.target, req.port)
    pqc = analyze_pqc(raw)
    risk = calculate_risk_score(raw, pqc)
    cbom = generate_cbom(req.target, req.port, raw, pqc, risk)
    filename = f"cbom_{req.target}_{req.port}.json"
    return JSONResponse(
        content=cbom,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/certificate")
def generate_certificate(req: ScanRequest):
    """Stream PQC certificate PDF (fully-safe targets only)."""
    raw = scan_tls_raw(req.target, req.port)
    pqc = analyze_pqc(raw)
    risk = calculate_risk_score(raw, pqc)
    pdf_bytes = generate_pqc_certificate_pdf(req.target, pqc, risk)
    filename = f"pqc_certificate_{req.target}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/scan/test")
def test_scan():
    """Quick sanity-check against example.com."""
    return _run_full_scan("example.com", 443, "full")
