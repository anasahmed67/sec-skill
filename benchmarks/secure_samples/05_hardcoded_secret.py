import os
def get_auth_header():
    api_key = os.environ.get('API_KEY')
    if not api_key:
        raise ValueError('API_KEY not configured')
    return {'Authorization': f'Bearer {api_key}'}
