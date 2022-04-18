from flask_app import app
from flask import render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
from flask_app.models.user_model import User

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/dashboard')
    return render_template("index.html")

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    print(session['user_id'])
    logged_in_user = User.get_by_id({'id':session['user_id']})
    return render_template('dashboard.html', user = logged_in_user)

@app.route('/user/login', methods=['POST'])
def user_login():
    if not User.login(request.form):
        return redirect('/')
    return redirect('/')

@app.route('/logout')
def logout():
    del session['user_id']
    return redirect ('/')

@app.route('/register/user', methods=['POST'])
def register():
    if not User.is_valid_registration(request.form):
        return redirect('/')
    # validate the form here ...
    # create the hash
    pw_hash = bcrypt.generate_password_hash(request.form['password'])
    print(pw_hash)
    # put the pw_hash into the data dictionary
    data = {
        **request.form,
        "password" : pw_hash
    }
    # Call the save @classmethod on User
    user_id = User.save(data)
    # store user id into session
    session['user_id'] = user_id
    return redirect("/login")

@app.route('/login', methods=['POST'])
def is_valid_login():

    user_in_db = User.get_by_email(request.form)  # user is not registered in the db
    if not user_in_db:
        flash("Invalid Email or Password", 'login')
        return redirect("/")
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        # if we get False after checking the password
        flash("Invalid Email or Password", 'login')
        return redirect('/')
# if the passwords matched, we set the user_id into session
    
    session['user_id'] = user_in_db.id
# never render on a post!!!
    return redirect("/dashboard")
