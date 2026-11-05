from flask import Flask, request
app = Flask(__name__)
@app.route('/login', methods=['POST'])
def login():
    # AI forgot brute force / rate limiting protection
    return authenticate(request.form['user'], request.form['pass'])
