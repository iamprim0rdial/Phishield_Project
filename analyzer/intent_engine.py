def detect_intent(text):
    text = text.lower()

    intents = []

    if "login" in text or "password" in text:
        intents.append("Credential Harvesting")

    if "bank" in text or "payment" in text:
        intents.append("Financial Fraud")

    if "allow access" in text or "permission" in text:
        intents.append("OAuth Abuse")

    if "download" in text or "attachment" in text:
        intents.append("Malware Delivery")

    if not intents:
        intents.append("Unknown")

    return intents