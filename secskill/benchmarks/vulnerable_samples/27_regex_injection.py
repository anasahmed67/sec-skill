import re
def search_text(pattern_str, text):
    regex = re.compile(pattern_str)
    return regex.findall(text)
