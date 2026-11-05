import hmac
def verify_signature(expected, provided):
    return hmac.compare_digest(expected, provided)
