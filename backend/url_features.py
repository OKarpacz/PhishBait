import ipaddress
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urlparse

import tldextract

_tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_TLDS = {
    "zip", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga",
    "work", "loan", "men", "date", "review", "stream", "download", "racing",
}

KNOWN_BRANDS = [
    "google", "paypal", "amazon", "apple", "microsoft", "facebook",
    "netflix", "instagram", "outlook", "gmail", "bankofamerica", "chase",
    "wellsfargo", "linkedin", "whatsapp", "allegro", "inpost", "revolut",
    "mbank", "pkobp",
]

TYPOSQUAT_SIMILARITY_THRESHOLD = 0.75

_ALLOWED_URL_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/:?&=%#~+")


@dataclass
class UrlFeatures:
    url: str
    scheme: str
    domain: str
    subdomain: str
    tld: str

    url_length: int
    domain_length: int

    dot_count: int
    hyphen_count: int
    digit_count: int
    special_char_count: int

    has_ip_address: bool
    has_at_symbol: bool
    is_suspicious_tld: bool
    is_https: bool

    typosquat_target: str | None
    typosquat_similarity: float

    subdomain_count: int
    has_path: bool


def _count_special_chars(url: str) -> int:
    return sum(1 for ch in url if ch not in _ALLOWED_URL_CHARS)


def _detect_ip_address(hostname: str) -> bool:
    if not hostname:
        return False
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def _best_typosquat_match(domain: str) -> tuple[str | None, float]:
    if not domain:
        return None, 0.0

    best_brand = None
    best_score = 0.0
    for brand in KNOWN_BRANDS:
        if domain == brand:
            return None, 0.0
        score = SequenceMatcher(None, domain, brand).ratio()
        if score > best_score:
            best_score = score
            best_brand = brand

    if best_score >= TYPOSQUAT_SIMILARITY_THRESHOLD:
        return best_brand, round(best_score, 3)
    return None, 0.0


def extract_features(url: str) -> UrlFeatures:
    had_explicit_scheme = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) is not None
    parse_target = url if had_explicit_scheme else f"http://{url}"

    parsed = urlparse(parse_target)
    hostname = parsed.hostname or ""

    extracted = _tld_extractor(parse_target)
    domain = extracted.domain
    tld = extracted.suffix
    subdomain = extracted.subdomain

    subdomain_parts = [part for part in subdomain.split(".") if part]

    typosquat_target, typosquat_similarity = _best_typosquat_match(domain.lower())

    return UrlFeatures(
        url=url,
        scheme=parsed.scheme,
        domain=domain,
        subdomain=subdomain,
        tld=tld,
        url_length=len(url),
        domain_length=len(hostname),
        dot_count=url.count("."),
        hyphen_count=url.count("-"),
        digit_count=sum(1 for ch in url if ch.isdigit()),
        special_char_count=_count_special_chars(url),
        has_ip_address=_detect_ip_address(hostname),
        has_at_symbol="@" in url,
        is_suspicious_tld=tld.lower() in SUSPICIOUS_TLDS,
        is_https=had_explicit_scheme and parsed.scheme.lower() == "https",
        typosquat_target=typosquat_target,
        typosquat_similarity=typosquat_similarity,
        subdomain_count=len(subdomain_parts),
        has_path=parsed.path not in ("", "/"),
    )