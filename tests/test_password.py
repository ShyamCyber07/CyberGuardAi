from app.services.password_service import PasswordService
from app.models.saved_password import SavedPassword

def test_shannon_entropy_bounds():
    """Test Shannon entropy algorithm bounds for predictability."""
    # "aaaaaaa" uses lowercase pool (26), length 7: 7 * log2(26) = 32.9
    assert PasswordService.calculate_entropy("aaaaaaa") == 32.9
    
    # Diverse strings have high entropy
    entropy_high = PasswordService.calculate_entropy("P@ssw0rd123!Safe")
    print(f"Entropy: {entropy_high}")
    assert entropy_high > 60.0


def test_password_strength_categories():
    """Test password strength categorizations and suggestions."""
    # Test weak password
    analysis_weak = PasswordService.analyze_password("123456")
    assert analysis_weak['strength'] == "Very Weak"
    assert len(analysis_weak['suggestions']) > 0

    # Test strong password
    analysis_strong = PasswordService.analyze_password("C0mplex_P@ss_2026!")
    assert analysis_strong['strength'] == "Strong"
    assert len(analysis_strong['suggestions']) == 0


def test_secure_password_generator():
    """Test password generator parameters (length, constraints)."""
    # 16 characters
    pwd = PasswordService.generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True)
    assert len(pwd) == 16
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" for c in pwd)


def test_fernet_key_derivation():
    """Test deterministic Fernet key derivation from app SECRET_KEY."""
    from app.services.password_service import PasswordEncryptionService
    key1 = PasswordEncryptionService.derive_fernet_key("my-secret-key")
    key2 = PasswordEncryptionService.derive_fernet_key("my-secret-key")
    # Must be deterministic
    assert key1 == key2
    # Must be base64 urlsafe valid Fernet key (44 bytes long)
    assert len(key1) == 44


def test_fernet_encryption_utility():
    """Test standard symmetric Fernet authenticated encryption utility."""
    plaintext = "SensitiveSecretVaultData123!"
    key = "TestSecretEncryptionKey"
    
    # Encrypt (Version 2 is default)
    ciphertext = PasswordService.encrypt_vault_password(plaintext, key)
    assert ciphertext != plaintext
    
    # Decrypt (Version 2 is default)
    decrypted = PasswordService.decrypt_vault_password(ciphertext, key, version=2)
    assert decrypted == plaintext


def test_fernet_random_iv():
    """Verify same plaintext produces different ciphertexts due to Fernet IV randomness."""
    plaintext = "IdenticalPlaintextData"
    key = "TestSecretEncryptionKey"
    c1 = PasswordService.encrypt_vault_password(plaintext, key)
    c2 = PasswordService.encrypt_vault_password(plaintext, key)
    assert c1 != c2


def test_encryption_failures_and_tampering():
    """Verify wrong-key, tampering, and malformed inputs fail safely."""
    plaintext = "SensitiveSecretVaultData123!"
    key = "CorrectKey123"
    wrong_key = "WrongKey123"
    
    ciphertext = PasswordService.encrypt_vault_password(plaintext, key)
    
    # 1. Wrong key fails safely
    dec_wrong = PasswordService.decrypt_vault_password(ciphertext, wrong_key, version=2)
    assert dec_wrong == "Decryption Error"
    
    # 2. Tampered ciphertext fails safely
    # Modify a character in the ciphertext to simulate tampering
    tampered = ciphertext[:-4] + "AAAA"
    dec_tampered = PasswordService.decrypt_vault_password(tampered, key, version=2)
    assert dec_tampered == "Decryption Error"
    
    # 3. Malformed/Empty inputs
    assert PasswordService.decrypt_vault_password("", key, version=2) == ""
    assert PasswordService.decrypt_vault_password("invalid_base64_string_!!!", key, version=2) == "Decryption Error"


def test_legacy_xor_compatibility():
    """Verify that legacy XOR data (Version 1) can still be successfully decrypted."""
    import base64
    plaintext = "LegacySecretData123"
    key = "SecretKey"
    
    # Manually generate legacy XOR ciphertext using legacy XOR logic
    key_bytes = key.encode('utf-8')
    pt_bytes = plaintext.encode('utf-8')
    encrypted = bytearray()
    for i, b in enumerate(pt_bytes):
        encrypted.append(b ^ key_bytes[i % len(key_bytes)])
    legacy_ciphertext = base64.urlsafe_b64encode(encrypted).decode('utf-8')
    assert legacy_ciphertext != plaintext
    
    # Decrypt using version=1 route
    dec_legacy = PasswordService.decrypt_vault_password(legacy_ciphertext, key, version=1)
    assert dec_legacy == plaintext


def test_password_vault_integration(app, db, test_users):
    """Test password vault credentials storage and retrieval."""
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(test_users['user'].id)
        sess['_fresh'] = True

    # Add credentials to vault
    res_add = client.post('/password-security/', data={
        'form_type': 'generate',
        'action': 'save',
        'length': 16,
        'use_upper': True,
        'use_lower': True,
        'use_digits': True,
        'use_symbols': True,
        'generated_password_val': 'SecureVaultPassword123!',
        'label': 'Test Service'
    }, follow_redirects=True)
    assert res_add.status_code == 200
    assert b"Secure password saved to vault registry" in res_add.data

    # Verify credentials stored and encrypted in database
    vault_item = SavedPassword.query.filter_by(label='Test Service').first()
    assert vault_item is not None
    assert vault_item.encrypted_password != 'SecureVaultPassword123!'  # Must be encrypted
