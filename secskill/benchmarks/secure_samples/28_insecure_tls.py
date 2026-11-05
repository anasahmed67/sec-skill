import ssl, urllib.request
def fetch_insecure():
    ctx = ssl.create_default_context()
    return urllib.request.urlopen('https://api.internal', context=ctx)
