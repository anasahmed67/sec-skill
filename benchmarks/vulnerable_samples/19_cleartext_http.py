import requests
def send_credentials(user, pwd):
    return requests.post('http://api.internal/login', json={'u': user, 'p': pwd})
