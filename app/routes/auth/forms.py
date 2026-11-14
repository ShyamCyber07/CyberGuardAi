from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from app.models.user import User

class RegistrationForm(FlaskForm):
    """Form for registering a new user account."""
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Invalid email address format.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Confirm password is required."),
        EqualTo('password', message="Passwords must match.")
    ])
    role = SelectField('Security Role', choices=[
        ('analyst', 'Security Analyst'),
        ('admin', 'Administrator'),
        ('auditor', 'Compliance Auditor')
    ], default='analyst', validators=[DataRequired()])
    submit = SubmitField('Create Account')

    def validate_email(self, email):
        """Ensure the email is not already registered."""
        user = User.query.filter_by(email=email.data.lower().strip()).first()
        if user:
            raise ValidationError('Email address is already registered.')


class LoginForm(FlaskForm):
    """Form for logging into the dashboard."""
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Invalid email address format.")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required.")
    ])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Access Dashboard')


class ForgotPasswordForm(FlaskForm):
    """Form for requesting a password reset email."""
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Invalid email address format.")
    ])
    submit = SubmitField('Request Password Reset')


class ResetPasswordForm(FlaskForm):
    """Form for entering a new password after a reset request."""
    password = PasswordField('New Password', validators=[
        DataRequired(message="Password is required."),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Confirm password is required."),
        EqualTo('password', message="Passwords must match.")
    ])
    submit = SubmitField('Update Password')


class ChangePasswordForm(FlaskForm):
    """Form for changing user password from the profile page."""
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message="Current password is required.")
    ])
    new_password = PasswordField('New Password', validators=[
        DataRequired(message="New password is required."),
        Length(min=8, message="Password must be at least 8 characters long.")
    ])
    confirm_new_password = PasswordField('Confirm New Password', validators=[
        DataRequired(message="Confirm new password is required."),
        EqualTo('new_password', message="Passwords must match.")
    ])
    submit = SubmitField('Change Password')


class UpdateProfileForm(FlaskForm):
    """Form for updating email and user profile details."""
    email = StringField('Email Address', validators=[
        DataRequired(message="Email is required."),
        Email(message="Invalid email address format.")
    ])
    submit = SubmitField('Update Profile')

    def __init__(self, original_email, *args, **kwargs):
        super(UpdateProfileForm, self).__init__(*args, **kwargs)
        self.original_email = original_email

    def validate_email(self, email):
        """Ensure the email is not already taken by another user."""
        if email.data.lower().strip() != self.original_email.lower().strip():
            user = User.query.filter_by(email=email.data.lower().strip()).first()
            if user:
                raise ValidationError('Email address is already in use by another account.')
