KNOWN_BAD_DOMAINS = set()


def update_intel(domain):
    KNOWN_BAD_DOMAINS.add(domain)


def check_domain(domain):
    if domain in KNOWN_BAD_DOMAINS:
        return 80, [f"Known malicious domain: {domain}"]
    return 0, []