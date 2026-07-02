import asyncio
import time
import re
from urllib.parse import urlparse

KNOWN_BAD_DOMAINS = {"malicious-site.net", "verify-microsoft.top"}
USER_DB = {}


class ContextualAI:
    def __init__(self, data):
        self.data = data
        self.whitelist = {"admin@yourcompany.com"}

    async def analyze(self):
        # Parallel Execution
        results = await asyncio.gather(
            self.check_identity(),
            self.check_intent(),
            self.check_links()
        )

        id_r, in_r, ln_r = results
        ai_verdict, ai_reason = "Safe", "N/A"

        # AI Fusion Trigger: Only if suspicious or has links
        if id_r['risk'] > 30 or ln_r['risk'] > 20:
            from analyzer.ai_fusion import analyze_with_context_async
            url = self.data.get("links", [""])[0]
            if url:
                ai_verdict, ai_reason = await analyze_with_context_async(url, self.data['body'], self.data['subject'])

        return self.fuse(id_r, in_r, ln_r, ai_verdict, ai_reason)

    async def check_identity(self):
        sender = self.data['from'].lower()
        risk = 40 if any(f in sender for f in ["@gmail", "@yahoo", "@outlook"]) else 0
        return {"risk": risk, "findings": ["External Freemail"] if risk else []}

    async def check_intent(self):
        text = f"{self.data['subject']} {self.data['body']}".lower()
        intents = []
        risk = 0
        if any(k in text for k in ["login", "password", "verify"]):
            intents.append("Credential Harvesting");
            risk += 40
        if any(k in text for k in ["urgent", "immediately", "action required"]):
            intents.append("Urgency");
            risk += 30
        return {"risk": risk, "intents": intents}

    async def check_links(self):
        risk = 0
        flagged = []
        for link in self.data.get("links", []):
            dom = urlparse(link).netloc.lower()
            if dom in KNOWN_BAD_DOMAINS or any(x in dom for x in [".top", ".xyz", ".icu"]):
                risk = 80;
                flagged.append(dom)
        return {"risk": risk, "flagged": flagged}

    def fuse(self, id_r, in_r, ln_r, ai_v, ai_re):
        score = (id_r['risk'] * 0.3) + (in_r['risk'] * 0.3) + (ln_r['risk'] * 0.4)

        # Multipliers
        if ai_v == "Phishing": score = max(score, 85)
        if ln_r['risk'] >= 80: score = max(score, 90)

        findings = id_r['findings'] + in_r['intents'] + ln_r['flagged'] + [ai_re]
        verdict = "PHISHING 🚨" if score >= 75 else "SUSPICIOUS ⚠️" if score >= 45 else "SAFE ✅"
        return {"verdict": verdict, "score": round(score, 2), "findings": list(set(findings))}