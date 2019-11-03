from flask import render_template, url_for, flash, redirect, request
from flask_a2 import app, db, bcrypt
from flask_a2.forms import RegistrationForm, LoginForm
from flask_a2.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required


posts = [
    {
        'author': 'Julio Nunez',
        'title': 'Blog Post 1',
        'content': 'First post content',
        'date_posted': 'November 1, 2019'
    },
    {
        'author': 'Julio Nunez',
        'title': 'Blog Post 2',
        'content': 'Second post content',
        'date_posted': 'November 1, 2019'
    }
]


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.pword.data).decode('utf-8')
        user = User(uname=form.uname.data, mfa=form.mfa.data, pword=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Success: Account created for {form.uname.data}!', 'success')
        return redirect(url_for('home'))
    if request.method == 'POST' and not form.validate():
        flash('Please review the options below and fill/correct any information as needed.', 'danger')
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(uname=form.uname.data).first()
        mfa = User.query.filter_by(mfa=form.mfa.data).first()
        if user and mfa and bcrypt.check_password_hash(user.pword, form.pword.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash(f'Success: Welcome, {form.uname.data}!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        elif not user:
            flash(f'Incorrect: The user, {form.uname.data}, does not exist!', 'danger')
        elif not mfa:
            flash(f'Incorrect 2fa credential used.', 'danger')
        else:
            flash('Incorrect: Login Unsuccessful. Please check your credentials.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')
