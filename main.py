import sys
import email
from email.utils import parseaddr
from core.pipeline import run_pipeline
from reporting.report_builder import build_report
from utils.logger import log_result


def parse_eml_data(raw_bytes: bytes) -> dict:
    """
    Robustly extracts metadata, text, and hidden HTML payloads from raw email bytes.
    Loops through all body elements to prevent link-hiding evasion tactics.
    """
    msg = email.message_from_bytes(raw_bytes)

    # Clean extracted headers safely
    raw_from = msg.get("From", "unknown@domain.com")
    sender_name, sender_addr = parseaddr(str(raw_from))
    subject = str(msg.get("Subject", "No Subject"))

    # Accumulate all visible textual parts across the entire payload architecture
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            # Capture both plain text and HTML layouts to scan for links comprehensively
            if content_type in ["text/plain", "text/html"]:
                try:
                    # 'replace' handles bad characters safely without breaking string format
                    part_text = part.get_payload(decode=True).decode(errors='replace')
                    body_parts.append(part_text)
                except Exception as e:
                    print(f"EXCEPTION: {e}")
                # REMOVED 'break' HERE: Loop must keep hunting through remaining structures
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors='replace')
            body_parts.append(body)
        except Exception as e:
            print(f"EXCEPTION: {e}")
            body_parts.append(str(msg.get_payload()))

    # Combine all parts into a single body text string for parsing links
    full_body_content = "\n".join(body_parts)

    return {
        "from": sender_addr if sender_addr else str(raw_from),
        "subject": subject,
        "body": full_body_content
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

    # 1. Dynamic Parsing with multi-part aggregation fix
    email_meta = parse_eml_data(raw_email_bytes)

    # 2. Execute Pipeline (Optionally pass your shared async browser_pool here)
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
