import sys
import email
import json
from email.utils import parseaddr
from core.pipeline import run_pipeline
from reporting.report_builder import build_report
from utils.logger import log_result


def parse_eml_data(raw_bytes):
    """robust way to extract data from mail"""
    msg = email.message_from_bytes(raw_bytes)

    # It's important to convert headers objects for JSON format
    raw_from = msg.get("From", "unknown@domain.com")
    sender_name, sender_addr = parseaddr(str(raw_from))

    subject = str(msg.get("Subject", "No Subject"))

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode(errors='ignore')
                except:
                    pass
                break
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors='ignore')
        except:
            body = str(msg.get_payload())

    return {
        "from": sender_addr if sender_addr else str(raw_from),
        "subject": subject,
        "body": body
    }


def main():
    print("--- PHISHIELD TERMINAL INTERFACE ---")
    target_file = sys.argv[1] if len(sys.argv) > 1 else "sample.eml"

    try:
        with open(target_file, "rb") as f:
            raw_email_bytes = f.read()
    except FileNotFoundError:
        print(f"Error: {target_file} not found.")
        return

    # 1. Dynamic Parsing with String Conversion Fix
    email_meta = parse_eml_data(raw_email_bytes)

    # 2. Execute Pipeline
    result = run_pipeline(raw_email_bytes, user="unknown", metadata=email_meta)

    # 3. Save Sanitized Preview (CDR)
    if result.get("safe_body"):
        try:
            with open("last_scan_preview.html", "w", encoding="utf-8") as f:
                f.write(result["safe_body"])
        except Exception as e:
            print(f"[!] Preview save failed: {e}")

    # 4. Reporting & Logging
    build_report(result, email_meta)
    log_result(result, email_meta)


if __name__ == "__main__":
    main()