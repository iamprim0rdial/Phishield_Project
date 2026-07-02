OVERRIDE_LOG = []


def request_override(user, email_id, reason):
    entry = {
        "user": user,
        "email_id": email_id,
        "reason": reason,
        "status": "pending"
    }

    OVERRIDE_LOG.append(entry)
    return "Override requested"


def approve_override(email_id):
    for entry in OVERRIDE_LOG:
        if entry["email_id"] == email_id:
            entry["status"] = "approved"
            return True

    return False