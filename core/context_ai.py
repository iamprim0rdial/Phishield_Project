import time
import re
from urllib.parse import urlparse


class ContextualAI:

    def __init__(self, data):
        self.data = data

    # ---------------------------
    # Main Analysis
    # ---------------------------
    def analyze(self):

        start = time.time()

        identity_result = self.check_identity()
        intent_result = self.check_intent()
        link_result = self.check_links()

        result = self.fuse(
            identity_result,
            intent_result,
            link_result
        )

        result["analysis_time"] = round(time.time() - start, 4)

        return result

    # ---------------------------
    # Identity Analysis
    # ---------------------------
    def check_identity(self):

        sender = self.data.get("from", "").lower()

        risk = 0
        findings = []

        if any(domain in sender for domain in [
            "@gmail.com",
            "@yahoo.com",
            "@outlook.com"
        ]):
            risk += 30
            findings.append("External Freemail")

        return {
            "risk": risk,
            "findings": findings
        }

    # ---------------------------
    # Intent Analysis
    # ---------------------------
    def check_intent(self):

        text = (
            self.data.get("subject", "") +
            " " +
            self.data.get("body", "")
        ).lower()

        risk = 0
        intents = []

        credential_patterns = [
            r"\blogin\b",
            r"\blog in\b",
            r"\bsign in\b",
            r"\bsign-in\b",
            r"\bpassword\b",
            r"\bverify\b",
            r"\bverification\b",
            r"\bconfirm\b",
            r"\bconfirmation\b",
            r"\baccount\b",
            r"\bupdate your account\b",
            r"\breset\b",
            r"\breset password\b",
            r"\bunlock\b",
            r"\bunlock account\b",
            r"\bsecurity check\b",
            r"\bsecurity alert\b",
            r"\bsecurity verification\b",
            r"\bauthenticate\b",
            r"\bauthentication\b",
            r"\bvalidate\b",
            r"\bidentity verification\b",
            r"\bconfirm identity\b",
            r"\bverify identity\b",
            r"\bcredential\b",
            r"\baccess your account\b",
            r"\baccount suspended\b",
            r"\baccount locked\b",
            r"\breactivate\b",
            r"\bclick here to login\b",
            r"\benter your password\b",
            r"\benter your username\b",
            r"\blogin to continue\b",
            r"\bsecure your account\b",
            r"\bupdate payment\b",
            r"\bpayment verification\b",
            r"\bbank account\b",
            r"\bcredit card\b",
            r"\bdebit card\b",
            r"\bssn\b",
            r"\bsocial security\b",
            r"\bone[- ]?time password\b",
            r"\botp\b",
            r"\bmfa\b",
            r"\b2fa\b"
        ]

        urgency_patterns = [
            r"\burgent\b",
            r"\burgently\b",
            r"\bimmediately\b",
            r"\bas soon as possible\b",
            r"\baction required\b",
            r"\bimmediate action\b",
            r"\bact now\b",
            r"\brespond now\b",
            r"\bfinal warning\b",
            r"\blast warning\b",
            r"\bimportant notice\b",
            r"\bcritical\b",
            r"\bhigh priority\b",
            r"\btime sensitive\b",
            r"\bwithin \d+ hours\b",
            r"\bwithin \d+ days\b",
            r"\b24 hours\b",
            r"\b48 hours\b",
            r"\bdeadline\b",
            r"\bexpires today\b",
            r"\bexpired\b",
            r"\bexpiring soon\b",
            r"\bavoid suspension\b",
            r"\baccount will be suspended\b",
            r"\baccount will be closed\b",
            r"\bservice interruption\b",
            r"\bfailure to comply\b",
            r"\bdo not ignore\b",
            r"\battention required\b",
            r"\brequired immediately\b",
            r"\byour account is at risk\b",
            r"\bunauthorized activity\b",
            r"\bsuspicious activity\b",
            r"\bsecurity breach\b"
        ]

        for pattern in credential_patterns:
            if re.search(pattern, text):
                risk += 15
                intents.append("Credential Harvesting")

        for pattern in urgency_patterns:
            if re.search(pattern, text):
                risk += 10
                intents.append("Urgency")

        return {
            "risk": risk,
            "intents": list(set(intents))
        }

    # ---------------------------
    # Link Analysis
    # ---------------------------
    def check_links(self):

        risk = 0
        flagged = []

        suspicious_tlds = (
            ".xyz",
            ".top",
            ".icu",
            ".click",
            ".zip",
            ".gq"
        )

        for link in self.data.get("links", []):

            domain = urlparse(link).netloc.lower()

            if domain.endswith(suspicious_tlds):
                risk += 40
                flagged.append(domain)

            if "@" in link:
                risk += 30
                flagged.append("URL contains @ symbol")

            if len(domain) > 35:
                risk += 20
                flagged.append("Very long domain")

        return {
            "risk": min(risk, 100),
            "flagged": list(set(flagged))
        }

    # ---------------------------
    # Final Decision
    # ---------------------------
    def fuse(self, id_r, in_r, ln_r):

        score = (
            id_r["risk"] * 0.30 +
            in_r["risk"] * 0.30 +
            ln_r["risk"] * 0.40
        )

        findings = (
            id_r["findings"] +
            in_r["intents"] +
            ln_r["flagged"]
        )

        if score >= 75:
            verdict = "PHISHING 🚨"
        elif score >= 45:
            verdict = "SUSPICIOUS ⚠️"
        else:
            verdict = "SAFE ✅"

        return {
            "verdict": verdict,
            "score": round(score, 2),
            "findings": list(set(findings))
        }


