import ipaddress
import re
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField
from wtforms.validators import DataRequired, ValidationError

# Regex to validate hostname structures (RFC 1123) with subdomains
HOSTNAME_REGEX = re.compile(
    r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])'
    r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9]))+$'
)

class NetworkScanForm(FlaskForm):
    """Form to capture and validate target IP addresses or hostnames for network audits."""
    ip_address = StringField('Target Host / IP Address', validators=[
        DataRequired(message="Target Host IP Address is required.")
    ])
    scan_profile = SelectField('Scan Profile / Scope', choices=[
        ('Quick Scan', 'Quick Scan (Ports 80, 443)'),
        ('Service Detection', 'Comprehensive (Deep Port & Version Audit)')
    ], default='Quick Scan', validators=[DataRequired()])
    scanner_mode = SelectField('Scanner Mode', choices=[
        ('REAL_NMAP', 'Real Nmap Scanner'),
        ('MOCK', 'Simulated / Demonstration Mode')
    ], default='REAL_NMAP', validators=[DataRequired()])
    submit = SubmitField('Initiate Network Assessment')

    def validate_ip_address(self, field):
        """Ensure input is either a valid IP address or compliant DNS hostname."""
        target = field.data.strip()
        
        # 1. Attempt IP address parsing
        try:
            ipaddress.ip_address(target)
            return  # Valid IP
        except ValueError:
            pass  # Not a valid IP, proceed to hostname check

        # 2. Check local loopback hostname or general compliance
        if target.lower() == 'localhost':
            return
            
        # 3. Check DNS hostname format
        if not HOSTNAME_REGEX.match(target):
            raise ValidationError(
                "Invalid target format. Must be a valid IPv4, IPv6 address, or hostname (e.g., 192.168.1.1 or scanme.nmap.org)."
            )
