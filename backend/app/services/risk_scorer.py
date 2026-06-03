"""
Risk Scorer (Weighted penalty scoring 0–100)
"""

import logging
from backend.app.config import RISK_WEIGHTS, DEPRECATED_CIPHERS, is_pqc_sig

logger = logging.getLogger("ciphernet.RiskScorer")


def calculate_risk_score(raw: dict, pqc: dict) -> dict:
    """
    Detailed risk scoring with per-category penalties.
    All severity labels are consistent:  CRITICAL,  HIGH,  MEDIUM,  INFO.

    Preserves BUG-4 (checks cert signature algorithm, separate HSTS category)
    and BUG-7 (renames low_findings to medium_findings).
    """
    score = 100
    penalties = []
    tls_pen = cipher_pen = cert_pen = pqc_pen = 0

    tls_ver = raw.get("tls_version", "") or ""
    cipher_name = (raw.get("cipher_suite") or "").upper()
    cert_days = raw.get("cert_days_left", 999) or 999
    sig_algo = (raw.get("cert_sig_alg") or "").lower()
    cert_bits = raw.get("cert_pubkey_bits", 2048) or 2048

    # 1. TLS version
    if tls_ver == "TLSv1":
        d = RISK_WEIGHTS["tls_1_0"]
        score -= d
        tls_pen += d
        penalties.append(" CRITICAL — TLS 1.0 Detected (Deprecated RFC 8996)")
    elif tls_ver == "TLSv1.1":
        d = RISK_WEIGHTS["tls_1_1"]
        score -= d
        tls_pen += d
        penalties.append(" HIGH — TLS 1.1 Detected (Deprecated RFC 8996)")
    elif tls_ver == "TLSv1.2":
        d = RISK_WEIGHTS["tls_1_2"]
        score -= d
        tls_pen += d
        penalties.append(" MEDIUM — TLS 1.2: Upgrade to TLS 1.3 for PQC hybrid support")
    elif tls_ver == "TLSv1.3":
        penalties.append(" INFO — TLS 1.3 Confirmed: PQC cipher suites supported")

    # 2. Cipher
    for dep in DEPRECATED_CIPHERS:
        if dep in cipher_name:
            d = RISK_WEIGHTS["weak_cipher"]
            score -= d
            cipher_pen += d
            penalties.append(f" CRITICAL — Broken/Deprecated Cipher: {dep} in {raw.get('cipher_suite', '')}")
            break
    if "CBC" in cipher_name and tls_ver != "TLSv1.3":
        score -= 8
        cipher_pen += 8
        penalties.append(" MEDIUM — CBC mode detected — BEAST/Lucky13 risk")
    if cert_bits and cert_bits < 128:
        score -= 20
        cipher_pen += 20
        penalties.append(f" HIGH — Weak key size: {cert_bits} bits below 128-bit minimum")

    # 3. Certificate
    if raw.get("cert_expired"):
        d = RISK_WEIGHTS["expired_cert"]
        score -= d
        cert_pen += d
        penalties.append(" CRITICAL — Certificate Expired: Immediate renewal required")
    elif 0 < cert_days <= 14:
        score -= 15
        cert_pen += 15
        penalties.append(f" HIGH — Certificate expires in {cert_days} days: Renew immediately")
    elif 14 < cert_days <= 30:
        score -= 8
        cert_pen += 8
        penalties.append(f" MEDIUM — Certificate expires in {cert_days} days")
    elif 30 < cert_days <= 45:
        d = RISK_WEIGHTS["cert_expiry_warning"]
        score -= d
        cert_pen += d
        penalties.append(f" MEDIUM — Certificate expires in {cert_days} days: Plan renewal soon")

    if "sha1" in sig_algo:
        d = RISK_WEIGHTS["sha1_sig"]
        score -= d
        cert_pen += d
        penalties.append(" HIGH — SHA-1 Signature: Cryptographically broken")
    if "md5" in sig_algo:
        d = RISK_WEIGHTS["md5_sig"]
        score -= d
        cert_pen += d
        penalties.append(" CRITICAL — MD5 Signature: Completely broken, replace immediately")

    # 4. HSTS — separate transport-layer penalty
    hsts_pen = 0
    if not raw.get("hsts", False):
        d = RISK_WEIGHTS["missing_hsts"]
        score -= d
        hsts_pen += d
        penalties.append(" MEDIUM — HSTS Not Configured: Add Strict-Transport-Security header to prevent protocol downgrade attacks")

    # 5. Certificate Signature check (PQC signature)
    if not is_pqc_sig(raw.get("cert_sig_alg", "")):
        d = RISK_WEIGHTS["classical_cert_sig"]
        score -= d
        cert_pen += d
        cert_alg_label = raw.get("cert_pubkey_alg") or "RSA/EC"
        sig_alg_label = raw.get("cert_sig_alg") or "sha256WithRSAEncryption"
        penalties.append(
            f" MEDIUM — Classical Certificate Signature Detected (pubkey: {cert_alg_label}, sig: {sig_alg_label}): "
            "Certificate is not yet signed with a NIST PQC signature algorithm (ML-DSA / SLH-DSA). "
            "Plan migration to ML-DSA-65 (FIPS 204) for full PQC compliance."
        )

    # 6. PQC Key Exchange check
    if not pqc.get("pqc_safe"):
        d = RISK_WEIGHTS["quantum_vulnerable_kex"]
        score -= d
        pqc_pen += d
        penalties.append(
            " HIGH — No Post-Quantum KEM Detected: Asset QUANTUM VULNERABLE. "
            "Exposed to Harvest-Now-Decrypt-Later (HNDL) attacks. "
            "Migrate to NIST FIPS 203 (ML-KEM-768) immediately."
        )
        penalties.append(
            " HIGH — NIST FIPS 203 (ML-KEM) Not Implemented: "
            "Classical KEX (RSA/ECDH) broken by Shor's Algorithm. "
            "Recommended: ML-KEM-768 (KEM) + ML-DSA-65 (Signatures)."
        )
    elif pqc.get("is_hybrid"):
        penalties.append(" INFO — Hybrid PQC Mode Active: Defense-in-depth achieved. NIST FIPS 203 compliant during migration.")
        penalties.append(" MEDIUM — Hybrid PQC (Transitional): Classical component still present. Plan full migration to standalone ML-KEM once ecosystem matures.")
    else:
        penalties.append(" INFO — Full PQC Active: NIST FIPS 203/204/205 compliance confirmed. Quantum Safe.")

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Capped grade if not PQC-safe
    if not pqc.get("pqc_safe") and grade in ("A+", "A"):
        grade = "B"
        penalties.append(" MEDIUM — Grade capped at B: ML-KEM not deployed. Grade A requires full PQC compliance.")

    total_deducted = tls_pen + cipher_pen + cert_pen + pqc_pen + hsts_pen

    return {
        "score": score,
        "grade": grade,
        "penalties": penalties,
        "pqc_safe": pqc.get("pqc_safe", False),
        "details": {
            "tls_penalty": tls_pen,
            "cipher_penalty": cipher_pen,
            "cert_penalty": cert_pen,
            "hsts_penalty": hsts_pen,
            "pqc_penalty": pqc_pen,
            "total_deducted": total_deducted,
        },
    }
