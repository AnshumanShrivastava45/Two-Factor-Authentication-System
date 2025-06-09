from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import bcrypt
import pyotp
import os
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from email_validator import validate_email, EmailNotValidError
import smtplib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'anshajshrivastava02@gmail.com'
app.config['MAIL_PASSWORD'] = 'mype decv gkox bhmc'

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    otp_secret = db.Column(db.String(16), nullable=False)

with app.app_context():
    db.create_all()

# Custom password validator
def password_complexity(form, field):
    password = field.data
    if len(password) < 6:
        raise ValidationError('Password must be at least 6 characters long.')
    if not any(char.isupper() for char in password):
        raise ValidationError('Password must contain at least one uppercase letter.')
    if not any(char.islower() for char in password):
        raise ValidationError('Password must contain at least one lowercase letter.')
    if not any(char in "!@#$%^&*()-_=+[]{}|;:',.<>?/`~" for char in password):
        raise ValidationError('Password must contain at least one special character.')

# Forms
class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    phone = StringField('Phone Number', validators=[DataRequired(), Length(10)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(), password_complexity, EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('Enter OTP', validators=[DataRequired(), Length(6)])
    submit = SubmitField('Verify OTP')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(), password_complexity, EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm New Password')
    submit = SubmitField('Reset Password')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(), password_complexity, EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm New Password')
    submit = SubmitField('Update Password')

# Routes
@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        otp_secret = pyotp.random_base32()
        new_user = User(
            name=form.name.data,
            phone=form.phone.data,
            email=form.email.data,
            password=hashed_password,
            otp_secret=otp_secret
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password):
            session['user_id'] = user.id
            send_otp(user)
            return redirect(url_for('verify'))
        flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html', form=form)


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    form = OTPForm()
    if form.validate_on_submit():
        user = User.query.get(session['user_id'])
        totp = pyotp.TOTP(user.otp_secret)
        if totp.verify(form.otp.data, valid_window=1):
            flash('Login successful!', 'success')
            return redirect('/dashboard')
        flash('Invalid OTP. Please try again.', 'danger')
    return render_template('verify.html', form=form)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender='anshajshrivastava02@gmail.com', recipients=[email])
            msg.body = f'Click the link to reset your password: {reset_link}'
            mail.send(msg)
            flash('A password reset link has been sent to your email.', 'success')
        else:
            flash('No account with that email found.', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=150)
    except (SignatureExpired, BadSignature):
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
            user.password = hashed_password
            db.session.commit()
            flash('Your password has been reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html', form=form)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm()
    user = User.query.get(session['user_id'])
    if form.validate_on_submit():
        if not bcrypt.checkpw(form.current_password.data.encode('utf-8'), user.password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))
        hashed_password = bcrypt.hashpw(form.new_password.data.encode('utf-8'), bcrypt.gensalt())
        user.password = hashed_password
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html', form=form)

@app.route('/logout')
def logout():
    session.clear()  # Clear session data
    flash('You have been logged out.', 'info')
    return render_template('base.html')


def send_otp(user):
    totp = pyotp.TOTP(user.otp_secret)
    otp = totp.now()
    msg = Message('Your OTP Code', sender='anshajshrivastava02@gmail.com', recipients=[user.email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)


if __name__ == '__main__':
    app.run(debug=True)

