import jwt
def create_token(payload):
    return jwt.encode(payload, 'secret123', algorithm='HS256')
