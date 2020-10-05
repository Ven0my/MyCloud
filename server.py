from flask import Flask, request, render_template
from flask_pymongo import PyMongo
from cfg import config

app = Flask(__name__)
app.config["MONGO_URI"] = config["mongo_uri"]
mongo = PyMongo(app)

@app.route('/')
def show_index():
    user_documents = mongo.db.users.find({})
    print(user_documents)
    for doc in user_documents:
        print(doc)
    return 'This is my home page'

@app.route('/login')
def show_login():
    return render_template('login.html')

@app.route('/check_login', methods=['POST'])
def check_login():
    email = request.form['email5']
    password = request.form['password5']

    return 'email:' +email + 'password:' +password

@app.route('/signup')
def show_signup():
    return 'this is my signup page'

if __name__ == '__main__':
    app.run(debug=True)