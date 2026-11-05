import ssl, urllib.request
def fetch_insecure():
    ctx = ssl._create_unverified_context()
    return urllib.request.urlopen('https://api.internal', context=ctx)
