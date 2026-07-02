import email
from email import policy
from email.parser import BytesParser


def parse_email(raw_email):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)

    body = ""
    html = ""

    # Extract parts safely
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()

            try:
                payload = part.get_payload(decode=True)

                if not payload:
                    continue

                content = payload.decode(errors="ignore")

                if content_type == "text/plain":
                    body += content

                elif content_type == "text/html":
                    html += content

            except Exception:
                continue
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            content = payload.decode(errors="ignore")
            if msg.get_content_type() == "text/html":
                html = content
            else:
                body = content

    return {
        "body": body,
        "html": html,
        "headers": dict(msg.items())
    }