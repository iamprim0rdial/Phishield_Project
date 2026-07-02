from parser.email_parser import parse_email
from analyzer.link_extractor import extract_links
from sandbox.sandbox_hook import run_sandbox
from analyzer.ai_fusion import analyze_with_context, analyze_email_advanced, generate_email_report
from detection.header_checks import check_authentication
from detection.intel_engine import analyze_intel
from detection.rules import (
    detect_suspicious_content,
    detect_link_mismatch,
    detect_lookalike_domain,
    detect_suspicious_tld
)
import asyncio
from concurrent.futures import ThreadPoolExecutor


async def process_link(link, ai_outputs):
    url = link['href']

    # 🔹 Sandbox async
    result = await run_sandbox(url)
    html = result["html"]
    text = result["text"]

    # 🔹 AI-Fusion threaded (CPU-heavy)
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as pool:
        ai_result = await loop.run_in_executor(pool, analyze_with_context, url, url, text)

    ai_outputs[url] = [(("yes" in str(ai_result).lower()), ai_result)]
    return url


async def run_all_links(links):
    ai_outputs = {}
    tasks = [process_link(link, ai_outputs) for link in links]
    await asyncio.gather(*tasks)
    return ai_outputs


def run_pipeline(raw_email_bytes):
    print("[*] Parsing email...")
    data = parse_email(raw_email_bytes)

    print("[*] Extracting links...")
    links = extract_links(data["body"])
    data["links"] = links

    print("[*] Running detection...")
    score = 0
    findings = []

    # Keyword detection
    s, f = detect_suspicious_content(data["body"])
    score += s
    findings.extend(f)

    # Link mismatch
    s, f = detect_link_mismatch(links)
    score += s
    findings.extend(f)

    # Lookalike domain
    s, f = detect_lookalike_domain(links)
    score += s
    findings.extend(f)

    # Suspicious TLD
    s, f = detect_suspicious_tld(links)
    score += s
    findings.extend(f)

    # Header authentication
    s, f = check_authentication(data["headers"])
    score += s
    findings.extend(f)

    print("[*] Sending links to sandbox and AI-Fusion in parallel...")

    ai_outputs = asyncio.run(run_all_links(links))

    # 🧠 Intel engine still sequential (can also be parallelized if needed)
    for link in ai_outputs.keys():
        s, f = analyze_intel(link)
        score += s
        findings.extend(f)

    # Advanced scoring & report
    email_links = [{"href": l, "text": l} for l in ai_outputs.keys()]
    advanced_result = analyze_email_advanced(email_links, ai_outputs=ai_outputs)
    report_text = generate_email_report(advanced_result, {
        "from": data["from"], "subject": data["subject"], "date": data.get("date")
    })

    print("\n=== RESULT ===")
    print(report_text)


if __name__ == "__main__":
    with open("sample.eml", "rb") as f:
        raw_email = f.read()
    run_pipeline(raw_email)