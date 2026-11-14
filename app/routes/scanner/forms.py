import ipaddress
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL, ValidationError

class ScanForm(FlaskForm):
    """Form to capture and validate target scanning URLs."""
    target_url = StringField('Target URL', validators=[
        DataRequired(message="Target URL is required."),
        URL(require_tld=True, message="Invalid URL format. Please include protocol (e.g. https://example.com).")
    ])
    submit = SubmitField('Analyze Target')


class NetworkScanForm(FlaskForm):
    """Form to capture and validate target IP addresses for network audits."""
    ip_address = StringField('Target IP Address', validators=[
        DataRequired(message="IP Address is required.")
    ])
    submit = SubmitField('Audit Network Node')

    def validate_ip_address(self, field):
        """Validate if the string is a valid IPv4 or IPv6 address."""
        ip = field.data.strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValidationError("Invalid IP format. Must be a valid IPv4 or IPv6 address (e.g. 192.168.1.1).")
