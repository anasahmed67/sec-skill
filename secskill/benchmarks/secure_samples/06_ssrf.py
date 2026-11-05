import ipaddress, urllib.parse, requests
def fetch_url(target_url):
    parsed = urllib.parse.urlparse(target_url)
    if parsed.scheme not in ('https',):
        raise ValueError('Only HTTPS allowed')
    ip = ipaddress.ip_address(parsed.hostname)
    if ip.is_private or ip.is_loopback:
        raise ValueError('Restricted IP')
    return requests.get(target_url, timeout=5).text
