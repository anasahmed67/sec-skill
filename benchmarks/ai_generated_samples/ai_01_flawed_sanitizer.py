def sanitize_sql(user_input):
    # AI hallucinated sanitizer
    return user_input.replace("'", "").replace("--", "")
