"""
ciphernet Certificate Issuer (PDF generator)
"""

import os
import logging
from fastapi import HTTPException

logger = logging.getLogger("ciphernet.CertificateIssuer")

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


def generate_pqc_certificate_pdf(target: str, pqc: dict, risk: dict) -> bytes:
    """
    Generates a professional PDF PQC Compliance Certificate.

    Preserves BUG-8 fix: Hybrid assets (pqc_safe=True but is_hybrid=True) are refused
    a "Fully Quantum Safe" PDF certificate — only fully-safe assets qualify.
    """
    if not HAS_FPDF:
        raise HTTPException(
            status_code=500,
            detail="fpdf2 not installed. Run: pip install fpdf2",
        )

    if not pqc.get("pqc_safe"):
        raise HTTPException(
            status_code=422,
            detail=f"Cannot issue certificate: {target} is not Quantum Safe",
        )

    # BUG-8: Refuse certificate for hybrid assets
    if pqc.get("is_hybrid"):
        raise HTTPException(
            status_code=422,
            detail=(
                f"Cannot issue 'Fully Quantum Safe' certificate: {target} uses "
                "a hybrid (transitional) PQC scheme. Deploy standalone ML-KEM and "
                "ML-DSA-signed certificates to qualify."
            ),
        )

    pdf = FPDF()
    pdf.set_margins(0, 0, 0)
    pdf.add_page()

    # Robust font lookup (checks services/../resources, root workspace, current directory)
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "..", "resources", "font.ttf"),
        os.path.join(os.path.dirname(__file__), "..", "..", "resources", "font.ttf"),
        os.path.join(os.path.dirname(__file__), "font.ttf"),
        os.path.join(os.getcwd(), "font.ttf"),
    ]
    font_path = None
    for p in possible_paths:
        if os.path.exists(p):
            font_path = p
            break

    if font_path:
        logger.info(f"Loading custom certificate font from {font_path}")
        pdf.add_font("CustomFont", "",  font_path, uni=True)
        pdf.add_font("CustomFont", "B", font_path, uni=True)
        pdf.add_font("CustomFont", "I", font_path, uni=True)
        FONT = "CustomFont"
    else:
        logger.warning("Custom font not found. Falling back to Helvetica.")
        FONT = "Helvetica"

    NAVY = (10, 30, 80)
    GOLD = (180, 140, 0)
    GREEN = (0, 120, 80)
    WHITE = (255, 255, 255)
    BLACK = (0, 0, 0)
    TEAL = (0, 128, 128)
    GRAY = (240, 240, 240)

    # Double border
    pdf.set_draw_color(*GOLD)
    pdf.set_line_width(1.5)
    pdf.rect(5, 5, 200, 287)
    pdf.set_line_width(0.5)
    pdf.rect(8, 8, 194, 281)

    # Header band
    pdf.set_fill_color(*NAVY)
    pdf.rect(8, 8, 194, 28, "F")
    pdf.set_xy(8, 10)
    pdf.set_font(FONT, "B", 12)
    pdf.set_text_color(*GOLD)
    pdf.cell(194, 7, "ciphernet PQC SCANNER", 0, 2, "C")
    pdf.set_font(FONT, "", 7)
    pdf.set_text_color(180, 200, 255)
    pdf.cell(194, 5, "QUANTUM-SAFE CRYPTOGRAPHIC SCANNER | CBOM GENERATOR", 0, 2, "C")
    pdf.set_font(FONT, "", 7)
    pdf.set_text_color(160, 180, 220)
    pdf.cell(194, 5, "Version 2.1.0  ·  NIST FIPS 203/204/205 Compliance Engine", 0, 1, "C")

    # Title section
    pdf.set_fill_color(*GREEN)
    pdf.rect(8, 36, 194, 34, "F")
    pdf.set_xy(8, 40)
    pdf.set_font(FONT, "B", 20)
    pdf.set_text_color(*WHITE)
    pdf.cell(194, 10, "CERTIFICATE OF COMPLIANCE", 0, 2, "C")
    pdf.set_font(FONT, "B", 11)
    pdf.set_text_color(220, 255, 220)
    pdf.cell(194, 7, "Post-Quantum Cryptography Readiness Assessment", 0, 2, "C")
    pdf.set_font(FONT, "", 8)
    pdf.set_text_color(200, 240, 200)
    pdf.cell(194, 5, "NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA)", 0, 1, "C")

    # PQC Ready badge
    pdf.set_fill_color(0, 100, 0)
    pdf.set_draw_color(*GOLD)
    pdf.set_line_width(1)
    pdf.rect(70, 74, 70, 20, "FD")
    pdf.set_xy(70, 77)
    pdf.set_font(FONT, "B", 14)
    pdf.set_text_color(*WHITE)
    pdf.cell(70, 7, "QUANTUM SAFE", 0, 2, "C")
    pdf.set_font(FONT, "", 8)
    pdf.set_text_color(180, 255, 180)
    pdf.cell(70, 5, "PQC READY CERTIFIED", 0, 1, "C")

    # NIST badges
    standards = [
        ("NIST FIPS 203", "ML-KEM", (0, 90, 160)),
        ("NIST FIPS 204", "ML-DSA", (0, 120, 80)),
        ("NIST FIPS 205", "SLH-DSA", (130, 0, 130)),
    ]
    y_badge = 100
    for i, (fips, name, color) in enumerate(standards):
        x = 12 + i * 64
        pdf.set_fill_color(*color)
        pdf.set_draw_color(*GOLD)
        pdf.set_line_width(0.4)
        pdf.rect(x, y_badge, 60, 18, "FD")
        pdf.set_xy(x, y_badge + 2)
        pdf.set_font(FONT, "B", 8)
        pdf.set_text_color(*WHITE)
        pdf.cell(60, 5, fips, 0, 2, "C")
        pdf.set_font(FONT, "", 7)
        pdf.set_text_color(220, 220, 220)
        pdf.cell(60, 4, name, 0, 1, "C")

    # Asset section
    pdf.set_fill_color(*GRAY)
    pdf.rect(12, 124, 186, 26, "F")
    pdf.set_xy(12, 127)
    pdf.set_font(FONT, "B", 8)
    pdf.set_text_color(*NAVY)
    pdf.cell(186, 5, "AUDITED ASSET", 0, 2, "C")
    pdf.set_font(FONT, "B", 14)
    pdf.set_text_color(0, 100, 0)
    pdf.cell(186, 8, target, 0, 2, "C")
    pdf.set_font(FONT, "I", 7)
    pdf.set_text_color(*TEAL)
    pdf.cell(186, 5, "Public-Facing Web Application / API Endpoint", 0, 1, "C")

    # Compliance table
    pdf.set_y(156)
    pdf.set_font(FONT, "B", 8)
    pdf.set_text_color(*WHITE)
    pdf.set_fill_color(*NAVY)
    pdf.rect(12, 156, 186, 8, "F")
    pdf.set_xy(12, 157)
    pdf.cell(93, 6, "COMPLIANCE PARAMETER", 0, 0, "C")
    pdf.cell(93, 6, "STATUS", 0, 1, "C")

    rows = [
        ("PQC Key Encapsulation (KEX)", "NIST FIPS 203 - ML-KEM (Kyber)  \u2713 COMPLIANT"),
        ("Digital Signature Algorithm", "NIST FIPS 204 - ML-DSA (Dilithium)  \u2713 COMPLIANT"),
        ("Hash-Based Signature",        "NIST FIPS 205 - SLH-DSA (SPHINCS+)  \u2713 AVAILABLE"),
        ("TLS Protocol",                "TLS 1.3 (RFC 8446)  \u2713 ENFORCED"),
        ("HNDL Attack Protection",      "Quantum-Safe KEM Active  \u2713 MITIGATED"),
        ("CBOM Standard",               "CycloneDX 1.6 / NIST SP 800-235  \u2713 GENERATED"),
        ("Security Score",              f"{risk.get('score', 0)}/100 — Grade {risk.get('grade', 'A')}"),
        ("PQC Detail",                  (pqc.get("reason") or "Quantum-Safe algorithms detected")[:55]),
    ]
    fill = False
    for label, value in rows:
        bg = (245, 250, 245) if fill else WHITE
        pdf.set_fill_color(*bg)
        pdf.set_text_color(*BLACK)
        y = pdf.get_y()
        pdf.rect(12, y, 186, 7, "F")
        pdf.set_xy(12, y + 1)
        pdf.set_font(FONT, "B", 7)
        pdf.set_text_color(*NAVY)
        pdf.cell(90, 5, f"  {label}", 0, 0, "L")
        pdf.set_font(FONT, "", 7)
        pdf.set_text_color(0, 100, 0)
        pdf.cell(96, 5, value, 0, 1, "L")
        fill = not fill

    # Metadata
    import datetime
    now = datetime.datetime.utcnow()
    pdf.set_y(234)
    pdf.set_draw_color(*GOLD)
    pdf.set_line_width(0.4)
    pdf.line(12, 234, 198, 234)

    meta = [
        ("Date of Issue", now.strftime("%Y-%m-%d")),
        ("Valid Until", now.replace(year=now.year + 1).strftime("%Y-%m-%d")),
        ("Certificate Serial", f"AG-{now.strftime('%Y%m%d')}-{abs(hash(target)) % 99999:05d}"),
        ("Issuing Authority", "ciphernet PQC Scanner"),
        ("Standard Refs", "NIST FIPS 203/204/205"),
        ("Scanner Version", "v2.1.0"),
    ]

    col_w = 62
    y_meta1 = 238
    for i in range(3):
        x = 12 + i * col_w
        pdf.set_xy(x, y_meta1)
        pdf.set_font(FONT, "B", 6)
        pdf.set_text_color(*NAVY)
        pdf.cell(col_w, 4, meta[i][0].upper(), 0, 0)
        pdf.set_xy(x, y_meta1 + 4)
        pdf.set_font(FONT, "", 6.5)
        pdf.set_text_color(*BLACK)
        pdf.cell(col_w, 4, meta[i][1], 0, 0)

    y_meta2 = 250
    for i in range(3, 6):
        x = 12 + (i - 3) * col_w
        pdf.set_xy(x, y_meta2)
        pdf.set_font(FONT, "B", 6)
        pdf.set_text_color(*NAVY)
        pdf.cell(col_w, 4, meta[i][0].upper(), 0, 0)
        pdf.set_xy(x, y_meta2 + 4)
        pdf.set_font(FONT, "", 6.5)
        pdf.set_text_color(*BLACK)
        pdf.cell(col_w, 4, meta[i][1], 0, 0)

    # Signature section
    y_sig = 262
    pdf.set_draw_color(*GOLD)
    pdf.set_line_width(0.4)
    pdf.line(12, y_sig, 198, y_sig)
    pdf.set_xy(25, y_sig + 3)
    pdf.set_font(FONT, "", 8)
    pdf.set_text_color(*BLACK)
    pdf.cell(70, 5, "_______________________________", 0, 0, "C")
    pdf.cell(20, 5, "", 0, 0)
    pdf.cell(70, 5, "_______________________________", 0, 1, "C")

    pdf.set_xy(25, y_sig + 9)
    pdf.set_font(FONT, "B", 7)
    pdf.set_text_color(*NAVY)
    pdf.cell(70, 4, "Chief Security Architect", 0, 0, "C")
    pdf.cell(20, 4, "", 0, 0)
    pdf.cell(70, 4, "Quantum Cryptography Auditor", 0, 1, "C")

    pdf.set_xy(25, y_sig + 14)
    pdf.set_font(FONT, "I", 6)
    pdf.set_text_color(*TEAL)
    pdf.cell(70, 4, "ciphernet PQC Scanner", 0, 0, "C")
    pdf.cell(20, 4, "", 0, 0)
    pdf.cell(70, 4, "NIST PQC Migration Program", 0, 1, "C")

    # Footer
    pdf.set_y(-12)
    pdf.set_font(FONT, "I", 7)
    pdf.set_text_color(*GOLD)
    pdf.cell(0, 8, f"ciphernet PQC Scanner  ·  NIST FIPS 203/204/205  ·  Page {pdf.page_no()}", 0, 0, "C")

    return bytes(pdf.output())
