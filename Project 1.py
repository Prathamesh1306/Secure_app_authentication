from flask import Flask, render_template, request, session, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, Email
from flask_wtf.csrf import CSRFProtect, generate_csrf
import mysql.connector
import random
import string
import secrets
import bcrypt

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
csrf = CSRFProtect(app)


# MySQL connection
conn = mysql.connector.connect(host='localhost', user='root', password='Your_password', database='database_as')
cursor = conn.cursor()

# CAPTCHA generation
def generateCaptcha(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

# Flask-WTF Forms
class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    captcha = StringField('CAPTCHA', validators=[InputRequired(), Length(min=6, max=6)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    fname = StringField('First Name', validators=[InputRequired()])
    lname = StringField('Last Name', validators=[InputRequired()])
    contact = StringField('Contact', validators=[InputRequired(), Length(min=10, max=10)])
    email = EmailField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=8)])
    submit = SubmitField('Sign up')

@app.route('/')
def index():
    form = LoginForm()
    session['captcha'] = generateCaptcha(6)
    return render_template('login.html', form=form, captcha=session['captcha'])

@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        try:
            email = form.email.data
            password = form.password.data
            entered_captcha = form.captcha.data

            if entered_captcha != session.get('captcha'):
                return 'CAPTCHA does not match. Please try again.'

            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode(), user[5].encode()):
                session['user_id'] = user[0]
                session.pop('captcha', None)
                return redirect(url_for('secured_area'))
            else:
                return 'Login failed. Invalid credentials.'
        except Exception as e:
            return f'Login error: {e}'
    return 'Invalid form data.'

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST' and form.validate_on_submit():
        try:
            first_name = form.fname.data
            last_name = form.lname.data
            contact = form.contact.data
            email = form.email.data
            password = bcrypt.hashpw(form.password.data.encode(), bcrypt.gensalt())

            cursor.execute("INSERT INTO users (first_name, last_name, contact, email, password) VALUES (%s, %s, %s, %s, %s)",
                           (first_name, last_name, contact, email, password.decode()))
            conn.commit()

            return redirect(url_for('index'))
        except Exception as e:
            return f'Registration failed: {e}'
    return render_template('register.html', form=form)

@app.route('/logout',methods=['POST'])
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/secured_area')
def secured_area():
    if 'user_id' in session:
        return render_template('vishwakrama.html')
    return redirect(url_for('index'))

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
