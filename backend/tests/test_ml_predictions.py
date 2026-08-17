import pytest

import ml_predictor
from url_features import extract_features

if not ml_predictor.load_model():
    pytest.skip("No trained ML model found - run the ml/ pipeline first (see ml/README.md).", allow_module_level=True)


def predict(url: str) -> float:
    return ml_predictor.predict_probability(extract_features(url))



@pytest.mark.parametrize("url", [
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
    "https://amazon.com",
    "https://apple.com",
    "https://netflix.com",
    "https://reddit.com",
    "https://spotify.com",
    "https://mozilla.org",
    "https://python.org",
    "https://wikipedia.org",
])
def test_bare_root_domains_are_low_risk(url):
    probability = predict(url)
    assert probability < 30, f"{url} scored {probability}% - expected LOW risk (bare root domain)"



@pytest.mark.parametrize("url", [
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://mail.google.com/mail/u/0",
    "https://docs.python.org/3/",
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/12345",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://support.microsoft.com/en-us/office",
])
def test_deep_legitimate_urls_are_low_risk(url):
    probability = predict(url)
    assert probability < 30, f"{url} scored {probability}% - expected LOW risk"



@pytest.mark.parametrize("url", [
    "http://paypa1-secure-login.zip/verify",
    "http://192.168.1.1@fake-login.com/verify",
    "http://amaz0n-account-verify.tk/signin",
    "http://micros0ft-security-alert.top/confirm",
    "http://appleid-verify-account.xyz/login",
    "http://192.168.0.5/wp-admin/login.php",
    "http://netfl1x-billing-update.click/pay",
    "http://faceb00k-login-secure.gq/auth",
])
def test_obvious_phishing_patterns_are_high_risk(url):
    probability = predict(url)
    assert probability > 70, f"{url} scored {probability}% - expected HIGH risk (unambiguous red flags)"

@pytest.mark.parametrize("url", [
    "https://accounts-google-secure.com/signin",
    "https://paypal.com.verify-account.net/login",
    "https://secure-appleid.com/",
    "https://login-microsoftonline.com/",
])
def test_subtle_phishing_is_informational_only(url, capsys):
    probability = predict(url)
    print(f"\n[info] {url} -> {probability}% (subtle case - not asserted, see docstring)")