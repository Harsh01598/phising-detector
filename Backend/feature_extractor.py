import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features["length_url"] = len(url)
    features["length_hostname"] = len(domain)
    features["ip"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain) else 0

    features["nb_dots"] = url.count(".")
    features["nb_hyphens"] = url.count("-")
    features["nb_at"] = url.count("@")
    features["nb_qm"] = url.count("?")
    features["nb_and"] = url.count("&")
    features["nb_eq"] = url.count("=")
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"] = url.count("~")
    features["nb_percent"] = url.count("%")
    features["nb_slash"] = url.count("/")
    features["nb_star"] = url.count("*")
    features["nb_colon"] = url.count(":")
    features["nb_comma"] = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"] = url.count("$")
    features["nb_space"] = url.count(" ")

    features["nb_www"] = 1 if "www" in domain else 0
    features["nb_com"] = 1 if ".com" in domain else 0
    features["nb_dslash"] = url.count("//")

    features["http_in_path"] = 1 if "http" in path else 0
    features["https_token"] = 1 if "https" in url else 0

    digits = sum(c.isdigit() for c in url)
    features["ratio_digits_url"] = digits / len(url) if len(url) > 0 else 0

    digits_host = sum(c.isdigit() for c in domain)
    features["ratio_digits_host"] = digits_host / len(domain) if len(domain) > 0 else 0

    # FIX: guard against negative value
    features["nb_subdomains"] = max(0, domain.count(".") - 1)

    features["prefix_suffix"] = 1 if "-" in domain else 0

    words = re.split(r"[./\-?=&_]", url)
    words = [w for w in words if w]

    features["length_words_raw"] = len(words)
    features["char_repeat"] = max([words.count(w) for w in set(words)]) if words else 0

    lengths = [len(w) for w in words] if words else [0]
    features["shortest_words_raw"] = min(lengths)
    features["longest_words_raw"] = max(lengths)
    features["avg_words_raw"] = sum(lengths) / len(lengths)

    phishing_keywords = ["login", "verify", "secure", "bank", "update", "account"]
    features["phish_hints"] = sum(1 for k in phishing_keywords if k in url.lower())

    return features