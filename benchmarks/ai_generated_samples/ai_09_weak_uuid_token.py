import uuid
def generate_session():
    # AI generated UUID1 which leaks MAC address and timestamp
    return str(uuid.uuid1())
