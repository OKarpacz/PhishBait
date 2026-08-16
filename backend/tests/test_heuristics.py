from heuristics import MAX_SCORE, score_url
from url_features import extract_features


def test_clean_url_scores_low():
    features = extract_features("https://example.com/about")
    result = score_url(features)
    assert result.probability < 30
    assert result.signals == []


def test_ip_address_url_scores_high():
    features = extract_features("http://192.168.1.1/login")
    result = score_url(features)
    assert result.probability >= 25
    names = [s.name for s in result.signals]
    assert "IP Address Instead of Domain" in names


def test_typosquat_url_includes_target_in_description():
    features = extract_features("http://paypa1.com/verify")
    result = score_url(features)
    typosquat_signal = next(s for s in result.signals if s.name == "Typosquatting Detected")
    assert "paypal" in typosquat_signal.description


def test_score_never_exceeds_max():
    url = (
        "http://user@192-168-1-1.zip-download-free-prize-claim-now-secure-verify-account.zip/"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    features = extract_features(url)
    result = score_url(features)
    assert result.probability <= MAX_SCORE


def test_https_url_does_not_trigger_no_https_signal():
    features = extract_features("https://example.com/")
    result = score_url(features)
    names = [s.name for s in result.signals]
    assert "No HTTPS" not in names


def test_at_symbol_triggers_signal():
    features = extract_features("http://example.com@evil.com/login")
    result = score_url(features)
    names = [s.name for s in result.signals]
    assert "'@' Symbol in URL" in names