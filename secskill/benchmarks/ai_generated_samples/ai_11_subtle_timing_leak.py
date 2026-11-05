def check_api_key(incoming, stored):
    if len(incoming) != len(stored):
        return False
    for a, b in zip(incoming, stored):
        if a != b:
            return False
    return True
