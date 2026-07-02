import logging
import json
import os
from datetime import datetime

# Set up professional logging format
logger = logging.getLogger("PhiShield")
logger.setLevel(logging.INFO)

# Ensure logs directory exists
if not os.path.exists("logs"):
    os.makedirs("logs")

def log_result(result, email_meta):
    """
    Logs a detailed security event in JSON format for SIEM ingestion.
    """
    log_entry = {
        "event_time": datetime.now().isoformat(),
        "severity": "CRITICAL" if result.get('score', 0) >= 80 else "INFO",
        "actor": email_meta.get("from", "unknown"),
        "subject": email_meta.get("subject", "n/a"),
        "telemetry": {
            "score": result.get("score"),
            "verdict": result.get("verdict"),
            "threats": result.get("findings", []),
            "confidence": result.get("confidence")
        },
        "action_taken": "QUARANTINED" if result.get("quarantine") else "DELIVERED"
    }

    # Write to file
    with open("logs/security_events.json", "a") as f:
        f.write(json.dumps(log_entry) + "\n")

    # Also print a summary to console for the dev
    print(f"   [LOG] Event recorded for {log_entry['actor']} | Verdict: {log_entry['telemetry']['verdict']}")