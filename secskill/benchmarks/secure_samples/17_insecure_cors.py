def set_cors_headers(response, origin):
    allowed = {'https://trusted.app.com'}
    if origin in allowed:
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response
