from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, BooleanField, HiddenField, SubmitField
from wtforms.validators import DataRequired, NumberRange, Length, Optional

class PasswordCheckForm(FlaskForm):
    """Form to capture target passwords for real-time strength audits."""
    password = StringField('Target Password', validators=[
        DataRequired(message="Please input a password to analyze.")
    ])
    submit = SubmitField('Analyze Strength')


class PasswordGeneratorForm(FlaskForm):
    """Form to capture options and flags for secure random password generations."""
    length = IntegerField('Password Length', default=16, validators=[
        DataRequired(message="Length is required."),
        NumberRange(min=8, max=64, message="Length must be between 8 and 64 characters.")
    ])
    use_upper = BooleanField('Include Uppercase (A-Z)', default=True)
    use_lower = BooleanField('Include Lowercase (a-z)', default=True)
    use_digits = BooleanField('Include Numbers (0-9)', default=True)
    use_symbols = BooleanField('Include Special Symbols (!@#$)', default=True)
    
    # Vault Save Options
    save_to_vault = BooleanField('Save generated password to vault storage', default=False)
    label = StringField('Credential Label (optional)', validators=[
        Optional(),
        Length(max=100, message="Label must be under 100 characters.")
    ])
    
    # Hidden helper field to preserve generated string across form submissions
    generated_password_val = HiddenField('Generated Value')
    submit = SubmitField('Generate Credentials')
