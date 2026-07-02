import time

# Simulation of a persistent database
USER_DATABASE = {}

# CONFIG
BLOCK_THRESHOLD = 250  # Total accumulated points before forced training
DECAY_RATE = 0.5  # Points removed per day (to allow for improvement)


def update_user_risk(user_id, incident_score):
    """
    Updates the behavioral risk profile of a user based on pipeline results.
    """
    now = time.time()

    if user_id not in USER_DATABASE:
        USER_DATABASE[user_id] = {
            "total_score": 0,
            "incidents": 0,
            "last_seen": now,
            "tier": "LOW"
        }

    profile = USER_DATABASE[user_id]

    # 1. Apply 'Time Decay' 
    # If they haven't had an incident in a long time, reduce their risk
    days_since = (now - profile["last_seen"]) / 86400
    reduction = days_since * DECAY_RATE
    profile["total_score"] = max(0, profile["total_score"] - reduction)

    # 2. Add new incident score
    profile["total_score"] += incident_score
    profile["incidents"] += 1
    profile["last_seen"] = now

    # 3. Calculate Tier
    if profile["total_score"] > BLOCK_THRESHOLD:
        profile["tier"] = "CRITICAL"
    elif profile["total_score"] > 100:
        profile["tier"] = "ELEVATED"
    else:
        profile["tier"] = "LOW"

    return profile