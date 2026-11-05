def set_auth_cookie(response, token):
    response.set_cookie('session_id', token)
    return response
