def is_safe_redirect(url):
    # AI assumed startswith('https') is safe against https://evil.com
    return url.startswith('https://')
