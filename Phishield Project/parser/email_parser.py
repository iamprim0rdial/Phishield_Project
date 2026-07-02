from email import policy
from email.parser import BytesParser

def extract_headers(msg):
    headers = {}
    for key in msg.keys():
        headers[key.lower()] = msg.get(key)
    return headers

def parse_email(raw_email_bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email_bytes)

    parsed_data = {
        "subject": msg["subject"],
        "from": msg["from"],
        "to": msg["to"],
        "body": "",
        "links": [],
        "headers": extract_headers(msg)
    }

    # Body Extraction
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain" or content_type == "text/html":
                try:
                    parsed_data["body"] += part.get_content()
                except:
                    pass
    else:
        parsed_data["body"] = msg.get_content()

    return parsed_data