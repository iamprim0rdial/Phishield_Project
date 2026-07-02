def build_report(result, email_meta):
    """
    Prints a clean, formatted security assessment to the console.
    """
    score = result.get("score", 0)
    verdict = result.get("verdict", "UNKNOWN")
    findings = result.get("findings", [])
    ai_analysis = result.get("ai_analysis", [])

    # Color/Emoji Logic
    border_char = "="
    color_icon = "✅"
    if verdict == "MALICIOUS":
        color_icon = "🚨"
    elif verdict == "SUSPICIOUS":
        color_icon = "⚠️"

    print(f"\n{border_char * 60}")
    print(f"🛡️  PHISHIELD SECURITY REPORT | {color_icon} {verdict}")
    print(f"{border_char * 60}")

    # Section 1: Header Info
    print(f"📧 FROM:    {email_meta.get('from', 'Unknown')}")
    print(f"📌 SUBJECT: {email_meta.get('subject', 'No Subject')}")
    print(f"📊 RISK:    {score}/100 (Confidence: {result.get('confidence', 'N/A')})")

    # Section 2: Technical Summary
    print(f"\n🔍 ANALYSIS SUMMARY:")
    print(f" • Total Links Found: {len(result.get('links', []))}")
    print(f" • Unique Findings:   {len(findings)}")

    # Section 3: Grouped Findings
    if findings:
        print(f"\n⚠️  CRITICAL INDICATORS:")
        # We deduplicate findings one last time for the UI
        for f in sorted(list(set(findings))):
            # Indent and clean up the string
            print(f"  [!] {f}")

    # Section 4: AI Insights
    if ai_analysis:
        print(f"\n🤖 AI FUSION INSIGHTS:")
        for analysis in ai_analysis:
            # The pipeline usually returns "URL -> Verdict: Reason"
            print(f"  • {analysis}")

    # Section 5: Mitigation Action
    print(f"\n🛡️  ACTION:")
    if verdict == "MALICIOUS":
        print("  >>> [BLOCK] This email has been quarantined. External links disabled.")
    elif verdict == "SUSPICIOUS":
        print("  >>> [WARN] User warned. Link rewrite active.")
    else:
        print("  >>> [PASS] No immediate threat detected.")

    print(f"{border_char * 60}\n")