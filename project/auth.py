from flask import Blueprint, render_template, redirect, request
from werkzeug.security import generate_password_hash, check_password_hash
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
	return render_template('login.html')

@auth.route('/signup')
def signup():
	email = request.form.get('email')
	name = request.form.get('name')
	password = request.form.get('password')

	# if this returns a user, then the email already exists in db
	user = user.query.filter_by(email=email).first()

	# if a user if sound, we want to redirect back to signup page so user can try again
	if user:
		return redirect(url_for('auth.signup'))

	# create a new user with the form data. Hash the password so the plaintext cersion is not visible
	new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

	# add the user to the database
	db.session.add(new_user)
	db.session.commit()
	return redirect(url_for('auth.login'))

@auth.route('/logout')
def logout():
	return 'Logout'
