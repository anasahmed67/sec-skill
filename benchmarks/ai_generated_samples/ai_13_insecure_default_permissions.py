import os
def save_secret(filepath, secret):
    with open(filepath, 'w') as f:
        f.write(secret)
    # AI did not set umask or restrict file permissions
