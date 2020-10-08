from flask import Flask, request, render_template, redirect, session
from flask_pymongo import PyMongo
from hashlib import sha256
from datetime import datetime
from cfg import config
from utils import get_random_string


app = Flask(__name__)
app.config["MONGO_URI"] = config["mongo_uri"]
mongo = PyMongo(app)
app.secret_key = b'j@ck@ss!!4sure!'

@app.route('/')
def show_index():
    if not 'userToken' in session:
        session['error'] = 'You must login to access this page.'
        return redirect('/login')

    # validate user login
    token_document = mongo.db.user_tokens.find_one({
        'sessionHash': session['userToken'],
    })

    if token_document is None:
        session.pop('userToken', None)
        session['error'] = 'You must login again to access this page.'
        return redirect('/login')

    return render_template('files.html')

@app.route('/login')
def show_login():
    signupSuccess = ''
    if 'signupSuccess' in session:
        signupSuccess = session['signupSuccess']
        session.pop('signupSuccess', None)

    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)
    return render_template('login.html', signupSuccess=signupSuccess, error=error)


@app.route('/check_login', methods=['POST'])
def check_login():
    try:
        email = request.form['email']
    except KeyError:
        email = ''
    try:
        passoword = request.form['password']
    except KeyError:
        passoword = ''

    # check if email is blank
    if not len(email) > 0:
        session['error'] = 'Email is required'
        return redirect('/login')

    # check if password is blank
    if not len(passoword) > 0:
        session['error'] = 'Password is required'
        return redirect('/login')

    # find email in database
    user_document = mongo.db.users.find_one({ "email": email})
    if user_document is None:
        session['error'] = 'No account exists with this email address'
        return redirect('/login')

    # verify the password hash matches with original
    passoword_hash = sha256(passoword.encode('utf-8')).hexdigest()
    if user_document['password'] != passoword_hash:
        session['error'] = 'Password is wrong'
        return redirect('/login')

    # Generate token and save in session
    random_string = get_random_string()
    randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()
    token_object = mongo.db.user_tokens.insert_one({
        'userId': user_document['_id'],
        'sessionHash': randomSessionHash,
        'createdAT': datetime.utcnow(),
    })
    session['userToken'] = randomSessionHash

    return redirect('/')


@app.route('/signup')
def show_signup():
    error = ''
    if 'error' in session:
        error = session['error']
        session.pop('error', None)
    return render_template('signup.html', error=error)

@app.route('/handle_signup', methods=['POST'])
def handle_signup():
    try:
        email = request.form['email']
    except KeyError:
        email = ''
    try:
        passoword = request.form['password']
    except KeyError:
        passoword = ''

    # check if email is blank
    if not len(email) > 0:
        session['error'] = 'Email is required'
        return redirect('/signup')

    # check if email is invalid
    if not '@' in email or not '.' in email:
        session['error'] = 'Email is Invalid'
        return redirect('/signup')

    # check is passoword is blank
    if not len(passoword) > 0:
        session['error'] = 'Password is required'
        return redirect('/signup')

    # check if email already exists
    matching_user_count = mongo.db.users.count_documents({ "email": email})
    if matching_user_count > 0:
        session['error'] = 'Email already exists'
        return redirect('/signup')

    passoword = sha256(passoword.encode('utf-8')).hexdigest()
    # create user records in database
    result = mongo.db.users.insert_one({
        'email': email,
        'password': passoword,
        'name': '',
        'lastLoginDate': None,
        'createdAt': datetime.utcnow(),
        'updatedAt': datetime.utcnow(),
    })

    # redirect to login page
    session['signupSuccess'] = 'Your user account is ready. You can login now'
    return redirect('/login')

@app.route('/logout')
def logout_user():
    session.pop('userToken', None)
    session['signupSuccess'] = 'You are now logged out.'
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)