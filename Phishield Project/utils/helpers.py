import tldextract

def get_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

def extract_headers(msg):
    headers = {}
    for key in msg.keys():
        headers[key.lower()] = msg.get(key)
    return headers


