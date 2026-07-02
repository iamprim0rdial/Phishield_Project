def generate_confirmation(sender, summary):
    return f"""
    ⚠️ Verification Required

    Sender: {sender}

    Message Summary:
    {summary}

    👉 Did you send this exact message?
    """