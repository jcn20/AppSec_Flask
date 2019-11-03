from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_a2.models import User


class RegistrationForm(FlaskForm):
    uname = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    mfa = StringField('Phone', validators=[DataRequired(), Length(min=11, max=11)])
    pword = PasswordField('Password', validators=[DataRequired()])
    confirm_pword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('pword')])
    submit = SubmitField('Sign Up')

    def validate_uname(self, uname):

        user = User.query.filter_by(uname=uname.data).first()
        if user:
            raise ValidationError('Failure: That username is already taken.')

    def validate_mfa(self, mfa):

        user = User.query.filter_by(mfa=mfa.data).first()
        if user:
            raise ValidationError('Failure: That number is already used for another account.')


class LoginForm(FlaskForm):
    uname = StringField('Username', validators=[DataRequired(), Length(min=5, max=20)])
    mfa = StringField('Phone Number', validators=[DataRequired(), Length(min=11, max=11)])
    pword = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

    def validate_creds(self, uname, mfa):

        user = User.query.filter_by(uname=uname.data, mfa=mfa.data).first()
        if not user:
            raise ValidationError('Failure: That username does not exist.')
        elif not mfa:
            raise ValidationError('Failure: Your 2fa is incorrect.')
        else:
            pass
