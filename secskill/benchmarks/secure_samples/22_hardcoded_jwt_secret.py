import jwt, os
def create_token(payload):
    key = os.environ['JWT_SIGNING_KEY']
    return jwt.encode(payload, key, algorithm='HS256')
