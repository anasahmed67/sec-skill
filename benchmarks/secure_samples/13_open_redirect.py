from flask import Flask, request, redirect, abort
from urllib.parse import urlparse
app = Flask(__name__)
@app.route('/redirect')
def redir():
    target = request.args.get('next')
    parsed = urlparse(target)
    if parsed.netloc != '' and parsed.netloc != 'mysite.com':
        abort(400)
    return redirect(target)
