"""
CBOM Generator (CycloneDX 1.6 Cryptographic Bill of Materials)
"""

import datetime
import logging
from backend.app.config import PORT_ASSET_MAP, is_pqc_sig

logger = logging.getLogger("ciphernet.CBOMGenerator")


def generate_cbom(target: str, port: int, raw: dict, pqc: dict, risk: dict) -> dict:
    """
    Generates CycloneDX-inspired CBOM for the scanned asset.

    Preserves BUG-5 (simplifies cert eligibility logic), BUG-10 (makes metadata standard dynamic),
    and BUG-12 (fills notes for all eligibility states).
    """
    asset_type = PORT_ASSET_MAP.get(port, f"Network Service (Port {port})")
    cipher = raw.get("cipher_suite") or ""
    tls_ver = raw.get("tls_version") or ""

    cert = {
        "subject": raw.get("cert_subject"),
        "issuer": raw.get("cert_issuer"),
        "signatureAlgorithm": raw.get("cert_sig_alg"),
        "publicKeyAlgorithm": raw.get("cert_pubkey_alg"),
        "publicKeyBits": raw.get("cert_pubkey_bits"),
        "notAfter": raw.get("cert_not_after"),
        "daysToExpiry": raw.get("cert_days_left"),
        "expired": raw.get("cert_expired"),
        "selfSigned": raw.get("cert_self_signed"),
        "sha256Fingerprint": raw.get("cert_sha256"),
    }

    is_pqc_safe = pqc.get("pqc_safe", False)
    is_hybrid = pqc.get("is_hybrid", False)
    has_pqc_sig = is_pqc_sig(raw.get("cert_sig_alg", ""))

    # 1. PQC Label
    if is_pqc_safe and not is_hybrid:
        pqc_label = "Fully Quantum Safe"
    elif is_pqc_safe and is_hybrid:
        pqc_label = "Hybrid PQC (Partial)"
    else:
        pqc_label = "Not Quantum Safe"

    # 2. NIST Standards — only list what is actually satisfied (BUG-10)
    nist_standards = []
    if is_pqc_safe:
        nist_standards.append("FIPS 203 (ML-KEM)")
    if has_pqc_sig:
        nist_standards.append("FIPS 204 (ML-DSA)")
        nist_standards.append("FIPS 205 (SLH-DSA)")

    # 3. Dynamic metadata standard string (BUG-10)
    if nist_standards:
        fips_nums = [s.split("(")[0].strip() for s in nist_standards]
        metadata_standard = "NIST " + "/".join(fips_nums) + ", CycloneDX 1.6"
    else:
        metadata_standard = "CycloneDX 1.6 (No NIST PQC standards satisfied)"

    # 4. Certification Eligibility (BUG-5)
    # Full certification = PQC-safe + stand-alone (not hybrid) + PQC signed certificate
    cert_eligible = is_pqc_safe and not is_hybrid and has_pqc_sig

    # 5. Certification Note covering all states (BUG-12)
    if cert_eligible:
        cert_note = "All criteria met. Fully Quantum Safe certification issued."
    elif is_pqc_safe and not is_hybrid and not has_pqc_sig:
        cert_note = (
            "PQC key exchange active. Certificate signature migration to "
            "ML-DSA (FIPS 204) pending — required for full certification."
        )
    elif is_pqc_safe and is_hybrid:
        cert_note = (
            "Hybrid mode: full certification requires standalone ML-KEM deployment "
            "and PQC certificate signature (ML-DSA / SLH-DSA)."
        )
    else:
        cert_note = (
            "Not eligible: asset uses classical key exchange. "
            "Deploy ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) to qualify."
        )

    # 6. Remediation Plan
    remediation = []
    if not is_pqc_safe:
        remediation.append({
            "action": "Migrate Key Exchange",
            "target": "ML-KEM-768 (NIST FIPS 203)",
            "priority": "CRITICAL",
            "description": "Replace classical KEX (RSA/ECDH/DHE) with ML-KEM-768 or hybrid X25519+ML-KEM-768.",
        })
        remediation.append({
            "action": "Migrate Digital Signatures",
            "target": "ML-DSA-65 (NIST FIPS 204)",
            "priority": "HIGH",
            "description": "Replace RSA/ECDSA certificate signatures with ML-DSA-65 or SLH-DSA.",
        })
        if tls_ver != "TLSv1.3":
            remediation.append({
                "action": "Enable TLS 1.3",
                "target": "RFC 8446",
                "priority": "HIGH",
                "description": "TLS 1.3 is required for hybrid PQC key exchange groups.",
            })

    if is_pqc_safe and not has_pqc_sig:
        sig_label = raw.get("cert_sig_alg") or "sha256WithRSAEncryption"
        pubk_label = raw.get("cert_pubkey_alg") or "EC/RSA"
        remediation.append({
            "action": "Migrate Certificate Signature",
            "target": "ML-DSA-65 (NIST FIPS 204)",
            "priority": "MEDIUM",
            "description": (
                f"Current certificate: public key algorithm = {pubk_label}, "
                f"signature algorithm = {sig_label}. "
                "Replace the signature algorithm with ML-DSA-65 or SLH-DSA-128s "
                "for full post-quantum assurance across both key exchange and authentication."
            ),
        })

    if not raw.get("hsts", False):
        remediation.append({
            "action": "Enable HSTS",
            "target": "Strict-Transport-Security header (RFC 6797)",
            "priority": "MEDIUM",
            "description": (
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' "
                "to all HTTPS responses to prevent downgrade attacks."
            ),
        })

    return {
        "bomFormat": "CycloneDX-PQC",
        "specVersion": "1.6",
        "cbomVersion": "1.0",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "metadata": {
            "tool": {
                "name": "ciphernet PQC Scanner",
                "version": "2.1.0",
                "vendor": "ciphernet",
            },
            "scanEngine": "ciphernet Unified PQC Scanner",
            "standard": metadata_standard,
        },
        "target": {
            "host": target,
            "port": port,
            "ip": raw.get("ip"),
            "assetType": asset_type,
            "hsts": raw.get("hsts"),
        },
        "cryptographicInventory": {
            "protocol": {
                "name": "TLS",
                "version": tls_ver,
                "status": "active",
                "pqcReady": tls_ver == "TLSv1.3",
            },
            "cipherSuite": {
                "name": cipher,
                "keyExchange": raw.get("kex_algorithm"),
                "quantumSafe": is_pqc_safe,
                "pqcComponents": pqc.get("safe_components", []),
                "vulnerableComponents": pqc.get("vulnerable_components", []),
            },
            "certificate": cert,
        },
        "pqcReadiness": {
            "label": pqc_label,
            "status": pqc.get("status"),
            "isQuantumSafe": is_pqc_safe and not is_hybrid,
            "isHybrid": is_hybrid,
            "reason": pqc.get("reason"),
            "nistCompliant": is_pqc_safe,
            "nistStandards": nist_standards,
            "certificationEligible": cert_eligible,
            "certificationNote": cert_note,
        },
        "riskAssessment": {
            "score": risk.get("score"),
            "grade": risk.get("grade"),
            "vulnerabilities": risk.get("penalties", []),
            "scoreBreakdown": risk.get("details", {}),
        },
        "remediationPlan": remediation,
    }
