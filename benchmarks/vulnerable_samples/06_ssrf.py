import requests
def fetch_url(target_url):
    return requests.get(target_url).text
