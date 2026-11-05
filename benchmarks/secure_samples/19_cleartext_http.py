import requests
def send_credentials(user, pwd):
    return requests.post('https://api.internal/login', json={'u': user, 'p': pwd})
