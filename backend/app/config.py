"""
AegisGuard Configuration & Cryptographic Database
"""

from typing import Dict, List, Set

PROJECT_NAME = "AegisGuard PQC Scanner"
VERSION = "2.1.0"

PQC_SAFE_ALGORITHMS: List[str] = [
    "Kyber", "ML-KEM", "MLKEM",
    "Dilithium", "ML-DSA", "MLDSA",
    "Falcon", "FN-DSA", "FNDSA",
    "SPHINCS+", "SPHINCS", "SLH-DSA", "SLHDSA",
    "NTRU", "BIKE", "HQC", "McEliece",
    "X25519MLKEM", "X25519Kyber768",
]

VULNERABLE_ALGORITHMS: List[str] = [
    "RSA", "Diffie-Hellman", "DH", "ECDH", "ECDHE", "ECDSA", "DSA", "ElGamal"
]

RISK_WEIGHTS: Dict[str, int] = {
    "tls_1_0": 40,
    "tls_1_1": 30,
    "tls_1_2": 10,
    "expired_cert": 30,
    "sha1_sig": 20,
    "md5_sig": 50,
    "weak_cipher": 25,
    "quantum_vulnerable_kex": 20,
    "missing_hsts": 5,
    "cert_expiry_warning": 5,
    "classical_cert_sig": 3,
}

PORT_ASSET_MAP: Dict[int, str] = {
    443: "Web Server (HTTPS)",
    8443: "Web Server (HTTPS Alt)",
    465: "Mail Server (SMTPS)",
    587: "Mail Server (SMTP Submission)",
    993: "Mail Server (IMAPS)",
    995: "Mail Server (POP3S)",
    636: "Directory Server (LDAPS)",
    3389: "Remote Desktop (RDP)",
    853: "DNS over TLS (DoT)",
    8080: "Web App (HTTP Alt)",
    8888: "API Gateway",
    9443: "API Server (HTTPS)",
}

PQC_SAFE_SET: Set[str] = {a.upper() for a in PQC_SAFE_ALGORITHMS}
HYBRID_INDICATORS: List[str] = ["X25519KYBER768", "X25519MLKEM", "X25519+ML-KEM", "P256KYBER", "HYBRID"]

CLASSICAL_KEX: Dict[str, Dict[str, str]] = {
    "ECDHE": {"std": "ANSI X9.63", "ks": "~256 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "ECDH":  {"std": "ANSI X9.63", "ks": "~256 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "DHE":   {"std": "RFC 3526",   "ks": "2048 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "DH":    {"std": "RFC 3526",   "ks": "2048 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "RSA":   {"std": "PKCS#1",     "ks": "~256B (vulnerable)",     "rec": "Replace with ML-KEM-1024"},
}

DEPRECATED_CIPHERS: Set[str] = {"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "RC2", "MD5"}
TLS_PENALTY: Dict[str, int] = {"TLSv1.3": 0, "TLSv1.2": 25, "TLSv1.1": 70, "TLSv1": 80, "SSLv3": 100}

KNOWN_PQC_HOSTS: Dict[str, List[str]] = {
    "google.com":                ["X25519Kyber768 (Hybrid)"],
    "cloudflare.com":            ["X25519MLKEM768 (Hybrid PQC)"],
    "test.openquantumsafe.org":  ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "pq.cloudflareresearch.com": ["X25519MLKEM768"],
}

PQC_SIG_NAMES: Set[str] = {
    "ML-DSA", "SLH-DSA", "FALCON", "MLDSA", "SLHDSA", "FNDSA", "DILITHIUM", "SPHINCS"
}

def is_pqc_sig(sig_alg: str) -> bool:
    """Return True if sig_alg is a recognised post-quantum signature algorithm."""
    s = (sig_alg or "").upper()
    return any(name in s for name in PQC_SIG_NAMES)
