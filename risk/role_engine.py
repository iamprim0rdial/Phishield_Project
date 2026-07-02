ROLE_RULES = {
    "HR": "sensitive",
    "Finance": "critical",
    "Dev": "internal"
}


def get_role_risk(role):
    if role == "Finance":
        return 30
    elif role == "HR":
        return 20
    return 10