import re
def check_ip(ip_str):
    # AI missed ^ and $ anchor tags
    return bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_str))
