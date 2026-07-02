THREAT_FEED = []


def share_threat(domain, pattern):
    THREAT_FEED.append({
        "domain": domain,
        "pattern": pattern
    })


def check_shared(domain):
    for threat in THREAT_FEED:
        if threat["domain"] == domain:
            return True
    return False