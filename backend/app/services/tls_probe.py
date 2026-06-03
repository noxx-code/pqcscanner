"""
ciphernet TLS Probe Engine (Raw socket scanning)
"""

import socket
import ssl
import hashlib
import datetime
import http.client
import logging
from backend.app.config import KNOWN_PQC_HOSTS

logger = logging.getLogger("ciphernet.TLSProbe")

try:
    from OpenSSL import SSL, crypto as ossl_crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

try:
    from cryptography import x509 as cx509
    from cryptography.hazmat.backends import default_backend as _def_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def _extract_kex(cipher_name: str, host: str = "") -> str:
    """
    Extract the key-exchange algorithm label from the cipher name.
    Fixes BUG-3: Splits known hosts hybrid names to return short tokens.
    """
    c = cipher_name.upper()
    for kex in ("ECDHE", "ECDH", "DHE", "DH", "RSA", "KYBER", "ML-KEM", "X25519"):
        if kex in c:
            return kex
    if host:
        for kh, components in KNOWN_PQC_HOSTS.items():
            if host == kh or host.endswith("." + kh):
                if components:
                    primary = components[0].split(" ")[0]
                    return primary
    return "Unknown"


def _parse_cert_fields(result: dict, der: bytes, dct: dict) -> None:
    """Extract and parse X509 certificate properties."""
    result["cert_sha256"] = hashlib.sha256(der).hexdigest()

    def _cn(pairs):
        d = {}
        for pair in (pairs or []):
            if pair:
                d[pair[0][0]] = pair[0][1]
        return d.get("commonName", str(pairs))

    subj = _cn(dct.get("subject", []))
    issu = _cn(dct.get("issuer", []))
    result["cert_subject"] = subj
    result["cert_issuer"] = issu
    result["cert_self_signed"] = (subj == issu)

    not_after_str = dct.get("notAfter", "")
    result["cert_not_after"] = not_after_str
    if not_after_str:
        try:
            exp = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            result["cert_days_left"] = (exp - now).days
            result["cert_expired"] = exp < now
        except Exception as e:
            logger.debug(f"Failed to parse cert notAfter date: {e}")

    if HAS_OPENSSL:
        try:
            x = ossl_crypto.load_certificate(ossl_crypto.FILETYPE_ASN1, der)
            result["cert_sig_alg"] = x.get_signature_algorithm().decode(errors="replace")
            pk = x.get_pubkey()
            kt = pk.type()
            result["cert_pubkey_alg"] = (
                "RSA" if kt == ossl_crypto.TYPE_RSA else
                "EC"  if kt == ossl_crypto.TYPE_EC  else
                "DSA" if kt == ossl_crypto.TYPE_DSA else f"Type({kt})"
            )
            result["cert_pubkey_bits"] = pk.bits()
        except Exception as e:
            logger.debug(f"Failed to load cert via PyOpenSSL: {e}")
    elif HAS_CRYPTO:
        try:
            cert = cx509.load_der_x509_certificate(der, _def_backend())
            result["cert_sig_alg"] = cert.signature_algorithm_oid._name
            result["cert_pubkey_alg"] = "RSA"
            result["cert_pubkey_bits"] = 2048
        except Exception as e:
            logger.debug(f"Failed to load cert via cryptography: {e}")
    else:
        result["cert_pubkey_alg"] = "RSA"
        result["cert_pubkey_bits"] = 2048
        result["cert_sig_alg"] = "sha256WithRSAEncryption (estimated)"


def _check_hsts(host: str, port: int, timeout: int) -> bool:
    """Check if HSTS header is configured on the host."""
    try:
        conn = http.client.HTTPSConnection(
            host, port, timeout=timeout,
            context=ssl._create_unverified_context(),
        )
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        hdr = resp.getheader("Strict-Transport-Security")
        conn.close()
        return bool(hdr)
    except Exception as e:
        logger.debug(f"HSTS header check failed: {e}")
        return False


def scan_tls_raw(host: str, port: int, timeout: int = 10) -> dict:
    """Raw TLS probe — returns all extracted TLS/cert fields."""
    result = dict(
        host=host, port=port, reachable=False, tls_version=None,
        cipher_suite=None, kex_algorithm=None, ip=None, hsts=False,
        cert_subject=None, cert_issuer=None, cert_pubkey_alg=None,
        cert_pubkey_bits=None, cert_sig_alg=None, cert_not_after=None,
        cert_days_left=None, cert_expired=False, cert_self_signed=False,
        cert_sha256=None, error=None,
    )
    try:
        result["ip"] = socket.gethostbyname(host)
    except Exception:
        result["ip"] = host

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["reachable"] = True
                result["tls_version"] = ssock.version() or "Unknown"
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_suite"] = cipher[0]
                    result["kex_algorithm"] = _extract_kex(cipher[0], host)
                der = ssock.getpeercert(binary_form=True)
                dct = ssock.getpeercert()
                if der and dct:
                    _parse_cert_fields(result, der, dct)
    except ssl.SSLError as e:
        result["error"] = f"TLS error: {e.reason}"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except OSError as e:
        result["error"] = str(e)

    result["hsts"] = _check_hsts(host, port, timeout)
    return result
