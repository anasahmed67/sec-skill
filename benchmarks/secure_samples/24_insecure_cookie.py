def set_auth_cookie(response, token):
    response.set_cookie('session_id', token, secure=True, httponly=True, samesite='Strict')
    return response
