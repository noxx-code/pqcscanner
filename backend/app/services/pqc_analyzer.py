"""
PQC Analyzer (NIST FIPS 203/204/205 detection)
"""

import logging
from backend.app.config import KNOWN_PQC_HOSTS, PQC_SAFE_ALGORITHMS, HYBRID_INDICATORS

logger = logging.getLogger("AegisGuard.PQCAnalyzer")


def analyze_pqc(raw: dict) -> dict:
    """
    AegisGuard PQC analysis — maps cipher + known-host heuristics to a
    structured PQC readiness result.

    Preserves BUG-1 / BUG-2 / BUG-11 fixes:
      - is_safe initialised to False before all branches.
      - Restructured cleanly to scan for safe algorithms first, then fall back.
    """
    target = raw.get("host", "")
    cipher_name = (raw.get("cipher_suite") or "").lower()
    kex = (raw.get("kex_algorithm") or "").upper()
    cipher_up = cipher_name.upper()

    safe_components = []
    vulnerable_components = []
    is_safe = False  # Fixed BUG-1/11: Initialised at the start

    # Known-host override
    matched_host = None
    for kh in KNOWN_PQC_HOSTS:
        if target == kh or target.endswith("." + kh):
            matched_host = kh
            break

    if matched_host:
        safe_components = list(KNOWN_PQC_HOSTS[matched_host])
        is_safe = True
    else:
        # Fixed BUG-2: Search for safe ciphers first
        for algo in PQC_SAFE_ALGORITHMS:
            if algo.lower() in cipher_name or algo.upper() in cipher_up:
                safe_components.append(algo)

        if safe_components:
            is_safe = True
        else:
            is_safe = False
            if "rsa" in cipher_name:
                vulnerable_components.append("RSA (Key Exchange/Auth)")
            if "ecdhe" in cipher_name:
                vulnerable_components.append("ECDHE (Key Exchange)")
            elif "dhe" in cipher_name:
                vulnerable_components.append("DHE (Key Exchange)")
            # If cipher gave us nothing, fall back to the detected KEX
            if not vulnerable_components and kex and kex not in ("UNKNOWN", ""):
                vulnerable_components.append(f"{kex} (Key Exchange)")

    # Hybrid detection
    is_hybrid = (
        any(h in cipher_up for h in HYBRID_INDICATORS)
        or any("HYBRID" in c.upper() for c in safe_components)
    )

    # Status derivation
    if safe_components:
        if is_hybrid:
            status = "Hybrid (Transitional)"
            reason = f"Protected by hybrid scheme: {', '.join(safe_components)}"
        else:
            status = "Quantum Safe"
            reason = f"Protected by: {', '.join(safe_components)}"
    else:
        status = "Quantum Vulnerable"
        reason = (
            f"Relies on classical algorithms: "
            f"{', '.join(vulnerable_components) or kex or 'Unknown'}"
        )
        is_safe = False

    return {
        "status": status,
        "pqc_safe": is_safe,
        "is_hybrid": is_hybrid,
        "reason": reason,
        "vulnerable_components": vulnerable_components,
        "safe_components": safe_components,
    }
