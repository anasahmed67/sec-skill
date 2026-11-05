import re
def search_text(pattern_str, text):
    escaped = re.escape(pattern_str)
    regex = re.compile(escaped)
    return regex.findall(text)
