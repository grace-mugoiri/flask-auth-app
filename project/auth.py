from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=["POST"])
def login_post():
	email = request.form.get('email')
	password = request.form.get('password')
	remember = True if request.form.get('remember') else False

	user = User.query.filter_by(email=email).first()

	# check if the user actually exists
	# take the user supplied password, hash it,
	# and compare it to the hashed password
	# in the database
	if not user or not check_password_hash(user.password, password):
		flash('Please check your login details and try again')
		return redirect(url_for('auth.login'))

	# if pass, then user has correct credentials
	login_user(user, remember=remember)
	return redirect(url_for('main.profile'))


@auth.route('/signup', methods=["POST"])
def signup_post():
	email = request.form.get('email')
	name = request.form.get('name')
	password = request.form.get('password')

	# if this returns a user, then the email already exists in db
	user = User.query.filter_by(email=email).first()

	# if a user if sound, we want to redirect back to signup page so user can try again
	if user:
		flash('Email address already exists')
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
