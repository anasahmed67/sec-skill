import re
def validate_email(email):
    pattern = r'^([a-zA-Z0-9]+)+@([a-zA-Z0-9]+)+$'
    return bool(re.match(pattern, email))
