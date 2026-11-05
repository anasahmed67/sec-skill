import jwt
def get_claims(token):
    # AI bypassed signature verification
    return jwt.decode(token, options={'verify_signature': False})
