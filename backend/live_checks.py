import os
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

REQUEST_TIMEOUT_SECONDS = 5

SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
SAFE_BROWSING_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

SSL_EXPIRY_WARNING_DAYS = 14

NEW_DOMAIN_THRESHOLD_DAYS = 30


def _hostname_from_url(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return parsed.hostname or ""


@dataclass
class SslCheckResult:
    checked: bool
    is_valid: bool | None
    issuer: str | None
    days_until_expiry: int | None
    expiring_soon: bool | None
    error: str | None


def check_ssl_certificate(url: str) -> SslCheckResult:
    hostname = _hostname_from_url(url)
    if not hostname:
        return SslCheckResult(False, None, None, None, None, "Could not determine hostname from URL")

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()

        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        issuer = issuer_parts.get("organizationName") or issuer_parts.get("commonName")

        expires_at = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_until_expiry = (expires_at - datetime.now(timezone.utc)).days

        return SslCheckResult(
            checked=True,
            is_valid=True,
            issuer=issuer,
            days_until_expiry=days_until_expiry,
            expiring_soon=days_until_expiry < SSL_EXPIRY_WARNING_DAYS,
            error=None,
        )
    except ssl.SSLCertVerificationError as exc:
        return SslCheckResult(True, False, None, None, None, str(exc))
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return SslCheckResult(False, None, None, None, None, f"Connection failed: {exc}")


@dataclass
class SafeBrowsingResult:
    checked: bool
    is_flagged: bool | None
    threat_types: list[str]
    error: str | None


def check_safe_browsing(url: str) -> SafeBrowsingResult:
    if not SAFE_BROWSING_API_KEY:
        return SafeBrowsingResult(False, None, [], "No API key configured (GOOGLE_SAFE_BROWSING_API_KEY)")

    payload = {
        "client": {"clientId": "phishing-detector-demo", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(
            SAFE_BROWSING_ENDPOINT,
            params={"key": SAFE_BROWSING_API_KEY},
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()

        matches = data.get("matches", [])
        threat_types = [m["threatType"] for m in matches]

        return SafeBrowsingResult(
            checked=True,
            is_flagged=len(matches) > 0,
            threat_types=threat_types,
            error=None,
        )
    except requests.RequestException as exc:
        return SafeBrowsingResult(False, None, [], f"Request failed: {exc}")

@dataclass
class DomainAgeResult:
    checked: bool
    creation_date: str | None
    age_days: int | None
    is_new_domain: bool | None
    error: str | None


def check_domain_age(url: str) -> DomainAgeResult:
    hostname = _hostname_from_url(url)
    if not hostname:
        return DomainAgeResult(False, None, None, None, "Could not determine hostname from URL")

    try:
        import whois

        record = whois.whois(hostname)
        creation = record.creation_date

        if isinstance(creation, list):
            creation = creation[0] if creation else None

        if creation is None:
            return DomainAgeResult(False, None, None, None, "Registrar did not return a creation date")

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days

        return DomainAgeResult(
            checked=True,
            creation_date=creation.date().isoformat(),
            age_days=age_days,
            is_new_domain=age_days < NEW_DOMAIN_THRESHOLD_DAYS,
            error=None,
        )
    except Exception as exc:
        return DomainAgeResult(False, None, None, None, f"WHOIS lookup failed: {exc}")

@dataclass
class RedirectResult:
    checked: bool
    redirect_count: int | None
    final_url: str | None
    crosses_domain: bool | None
    error: str | None


def check_redirects(url: str) -> RedirectResult:
    normalized = url if "://" in url else f"http://{url}"
    try:
        response = requests.get(
            normalized,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        start_domain = _hostname_from_url(normalized)
        final_domain = _hostname_from_url(response.url)

        return RedirectResult(
            checked=True,
            redirect_count=len(response.history),
            final_url=response.url,
            crosses_domain=start_domain != final_domain,
            error=None,
        )
    except requests.RequestException as exc:
        return RedirectResult(False, None, None, None, f"Request failed: {exc}")

@dataclass
class SecurityHeadersResult:
    checked: bool
    has_hsts: bool | None
    has_csp: bool | None
    error: str | None


def check_security_headers(url: str) -> SecurityHeadersResult:
    normalized = url if "://" in url else f"http://{url}"
    try:
        response = requests.get(normalized, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=True)
        headers = {k.lower(): v for k, v in response.headers.items()}

        return SecurityHeadersResult(
            checked=True,
            has_hsts="strict-transport-security" in headers,
            has_csp="content-security-policy" in headers,
            error=None,
        )
    except requests.RequestException as exc:
        return SecurityHeadersResult(False, None, None, f"Request failed: {exc}")