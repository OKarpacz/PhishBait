from url_features import extract_features


def test_basic_https_url():
    f = extract_features("https://www.example.com/login")
    assert f.is_https is True
    assert f.domain == "example"
    assert f.tld == "com"
    assert f.has_ip_address is False
    assert f.has_at_symbol is False


def test_http_not_https():
    f = extract_features("http://example.com/login")
    assert f.is_https is False


def test_no_scheme_defaults_to_not_https():
    f = extract_features("example.com/login")
    assert f.is_https is False


def test_ip_address_instead_of_domain():
    f = extract_features("http://192.168.1.1/admin")
    assert f.has_ip_address is True


def test_domain_name_is_not_flagged_as_ip():
    f = extract_features("http://example.com/admin")
    assert f.has_ip_address is False


def test_at_symbol_detected():
    f = extract_features("http://example.com@evil.com/login")
    assert f.has_at_symbol is True


def test_suspicious_tld_flagged():
    f = extract_features("http://free-prize.zip/claim")
    assert f.is_suspicious_tld is True


def test_common_tld_not_flagged():
    f = extract_features("http://example.com/")
    assert f.is_suspicious_tld is False


def test_multi_level_tld_parsed_correctly():
    f = extract_features("https://mail.google.co.uk/inbox")
    assert f.tld == "co.uk"
    assert f.domain == "google"
    assert f.subdomain == "mail"
    assert f.subdomain_count == 1


def test_no_subdomain_counts_zero():
    f = extract_features("https://example.com/")
    assert f.subdomain_count == 0


def test_multiple_subdomains_counted():
    f = extract_features("https://a.b.c.example.com/")
    assert f.subdomain_count == 3


def test_typosquat_detected_for_similar_domain():
    f = extract_features("http://paypa1.com/verify")
    assert f.typosquat_target == "paypal"
    assert f.typosquat_similarity > 0


def test_exact_brand_match_not_flagged_as_typosquat():
    f = extract_features("http://paypal.com/verify")
    assert f.typosquat_target is None


def test_unrelated_domain_not_flagged_as_typosquat():
    f = extract_features("http://my-personal-blog.com/")
    assert f.typosquat_target is None


def test_character_counts():
    f = extract_features("http://a-b.c-d.com")
    assert f.hyphen_count == 2
    assert f.dot_count == 2


def test_digit_count():
    f = extract_features("http://secure123login456.com")
    assert f.digit_count == 6


def test_url_length_matches_input():
    url = "https://example.com/a/very/long/path?query=1"
    f = extract_features(url)
    assert f.url_length == len(url)