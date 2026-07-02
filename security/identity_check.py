INTERNAL_USERS = [
    "hr@company.com",
    "finance@company.com"
]


def verify_internal_sender(sender):
    if sender in INTERNAL_USERS:
        return True
    return False