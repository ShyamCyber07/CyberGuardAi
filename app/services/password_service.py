import math
import secrets
import string
import base64
import hashlib
from cryptography.fernet import Fernet

class PasswordService:
    """Service layer representing password strength auditing, generation, and vault encryption."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate password Shannon Entropy bits based on character pool size."""
        if not password:
            return 0.0

        length = len(password)
        pool = 0

        # Detect active character set segments
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation or c.isspace() for c in password)

        if has_lower:
            pool += 26
        if has_upper:
            pool += 26
        if has_digit:
            pool += 10
        if has_symbol:
            pool += 32  # Standard ascii symbol count

        if pool == 0:
            return 0.0

        entropy = length * math.log2(pool)
        return round(entropy, 1)

    @staticmethod
    def analyze_password(password: str) -> dict:
        """Analyze strength metrics, character subsets presence, and build suggestions."""
        length = len(password)
        
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_digit = any(c in string.digits for c in password)
        # Check standard punctuation or spaces
        has_symbol = any(c in string.punctuation or c.isspace() for c in password)

        entropy = PasswordService.calculate_entropy(password)
        
        # Categorize overall strength using entropy bits ranges
        if length == 0:
            strength = "Empty"
            badge = "secondary"
        elif entropy < 36:
            strength = "Very Weak"
            badge = "danger"
        elif entropy < 60:
            strength = "Weak"
            badge = "warning"
        elif entropy < 80:
            strength = "Medium"
            badge = "info"
        elif entropy < 120:
            strength = "Strong"
            badge = "success"
        else:
            strength = "Excellent"
            badge = "emerald"

        # Generate action suggestions
        suggestions = []
        if length < 12:
            suggestions.append("Increase total length to 12 or more characters.")
        if not has_upper:
            suggestions.append("Add uppercase letters (A-Z).")
        if not has_lower:
            suggestions.append("Add lowercase letters (a-z).")
        if not has_digit:
            suggestions.append("Add numerical digits (0-9).")
        if not has_symbol:
            suggestions.append("Add special symbols or punctuation (e.g. !, @, #, $, %).")

        return {
            'length': length,
            'has_lower': has_lower,
            'has_upper': has_upper,
            'has_digit': has_digit,
            'has_symbol': has_symbol,
            'entropy': entropy,
            'strength': strength,
            'badge': badge,
            'suggestions': suggestions
        }

    @staticmethod
    def generate_password(length: int = 16, use_upper: bool = True, use_lower: bool = True,
                          use_digits: bool = True, use_symbols: bool = True) -> str:
        """Generate a cryptographically secure random password based on scope selections."""
        char_pools = []
        mandatory_chars = []

        if use_lower:
            char_pools.append(string.ascii_lowercase)
            mandatory_chars.append(secrets.choice(string.ascii_lowercase))
        if use_upper:
            char_pools.append(string.ascii_uppercase)
            mandatory_chars.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            char_pools.append(string.digits)
            mandatory_chars.append(secrets.choice(string.digits))
        if use_symbols:
            char_pools.append(string.punctuation)
            mandatory_chars.append(secrets.choice(string.punctuation))

        # Fallback if no sets selected
        if not char_pools:
            char_pools.append(string.ascii_lowercase)
            mandatory_chars.append(secrets.choice(string.ascii_lowercase))

        combined_pool = "".join(char_pools)
        
        # Calculate remaining length to fill
        remaining_len = max(0, length - len(mandatory_chars))
        fill_chars = [secrets.choice(combined_pool) for _ in range(remaining_len)]

        # Shuffle the character array to mix the mandatory characters securely
        result_chars = mandatory_chars + fill_chars
        secrets.SystemRandom().shuffle(result_chars)

        return "".join(result_chars)

    @staticmethod
    def encrypt_vault_password(plaintext: str, secret_key: str) -> str:
        """Encrypt vault secrets symmetrically using the authenticated Fernet service."""
        return PasswordEncryptionService.encrypt(plaintext, secret_key)

    @staticmethod
    def decrypt_vault_password(ciphertext: str, secret_key: str, version: int = 2) -> str:
        """Decrypt vault secrets symmetrically using the authenticated Fernet service or legacy XOR."""
        return PasswordEncryptionService.decrypt(ciphertext, secret_key, version)

    @staticmethod
    def decrypt_legacy_xor(ciphertext: str, secret_key: str) -> str:
        """Decrypt vault secrets symmetrically using base64 XOR decryption fallback."""
        try:
            key_bytes = secret_key.encode('utf-8')
            cipher_bytes = base64.urlsafe_b64decode(ciphertext.encode('utf-8'))
            decrypted = bytearray()
            for i, b in enumerate(cipher_bytes):
                decrypted.append(b ^ key_bytes[i % len(key_bytes)])
            return decrypted.decode('utf-8')
        except Exception:
            return "Decryption Error"


class PasswordEncryptionService:
    """Symmetric authenticated encryption service using cryptography.fernet.Fernet."""

    @staticmethod
    def derive_fernet_key(secret_key: str) -> bytes:
        """Derive a deterministic 32-byte Fernet key from the application secret key using SHA-256."""
        if not secret_key:
            raise ValueError("Secret key must not be empty.")
        # Produce 32-byte digest
        digest = hashlib.sha256(secret_key.encode('utf-8')).digest()
        # Encode urlsafe base64 (produces a 44-byte key required by Fernet)
        return base64.urlsafe_b64encode(digest)

    @staticmethod
    def encrypt(plaintext: str, secret_key: str) -> str:
        """Encrypt plaintext securely using derived Fernet key."""
        if not plaintext:
            return ""
        fernet_key = PasswordEncryptionService.derive_fernet_key(secret_key)
        f = Fernet(fernet_key)
        encrypted_bytes = f.encrypt(plaintext.encode('utf-8'))
        return encrypted_bytes.decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str, secret_key: str, version: int = 2) -> str:
        """Decrypt ciphertext securely using derived Fernet key or legacy XOR if version is 1."""
        if not ciphertext:
            return ""
        if version == 1:
            # Fallback to legacy XOR decryption
            return PasswordService.decrypt_legacy_xor(ciphertext, secret_key)
        
        try:
            fernet_key = PasswordEncryptionService.derive_fernet_key(secret_key)
            f = Fernet(fernet_key)
            decrypted_bytes = f.decrypt(ciphertext.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
        except Exception:
            return "Decryption Error"
