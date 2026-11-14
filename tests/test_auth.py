from app.models.user import User

def test_user_registration(client, db):
    """Test standard user account registration endpoint."""
    # Test valid registration
    res = client.post('/auth/register', data={
        'email': 'new_dev@test.com',
        'password': 'SecureNewDevPassword123!',
        'confirm_password': 'SecureNewDevPassword123!',
        'role': 'analyst'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Account created successfully" in res.data

    # Verify user exists in database
    user = User.query.filter_by(email='new_dev@test.com').first()
    assert user is not None
    assert user.role == 'analyst'

    # Test duplicate registration rejection
    res_dup = client.post('/auth/register', data={
        'email': 'new_dev@test.com',
        'password': 'SecureNewDevPassword123!',
        'confirm_password': 'SecureNewDevPassword123!',
        'role': 'analyst'
    })
    # Form validation fails due to duplicate email
    assert res_dup.status_code == 200
    assert b"Email address is already registered." in res_dup.data


def test_user_login_logout(app, test_users):
    """Test user login authentication and session termination endpoints."""
    client = app.test_client()
    # Successful login
    res_login = client.post('/auth/login', data={
        'email': 'user@test.com',
        'password': 'UserPass123!'
    }, follow_redirects=True)
    assert res_login.status_code == 200
    assert b"Successfully accessed CyberGuard AI" in res_login.data

    # Logout
    res_logout = client.get('/auth/logout', follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"Sign In" in res_logout.data


def test_login_invalid_credentials(app, test_users):
    """Test login rejection for incorrect credentials."""
    client = app.test_client()
    res = client.post('/auth/login', data={
        'email': 'user@test.com',
        'password': 'WrongPassword123!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b"Login unsuccessful." in res.data


def test_profile_access_restricted(app):
    """Test profile route is protected by login_required."""
    client = app.test_client()
    res = client.get('/auth/profile')
    assert res.status_code == 302
    assert 'login' in res.headers['Location']


def test_forgot_password_timed_tokens(app, db, test_users):
    """Test timed serializer token generation and verification roundtrip."""
    with app.app_context():
        user = test_users['user']
        from app.routes.auth.routes import generate_reset_token, verify_reset_token
        token = generate_reset_token(user)
        assert token is not None
        
        # Verify correct extraction
        verified_user = verify_reset_token(token)
        assert verified_user is not None
        assert verified_user.email == user.email


def test_forgot_password_token_expiration(app, db, test_users):
    """Test serializer token rejection after expiration timeframe."""
    import time
    with app.app_context():
        user = test_users['user']
        from app.routes.auth.routes import generate_reset_token, verify_reset_token
        token = generate_reset_token(user)
        
        # Verify immediately
        assert verify_reset_token(token, expiration=10) == user
        
        # Verify after expiration time window (simulated using expiration=0)
        assert verify_reset_token(token, expiration=-1) is None


def test_forgot_password_token_invalidation_on_change(app, db, test_users):
    """Test that updating user password hash invalidates pre-existing reset tokens."""
    with app.app_context():
        # Query user in the active context to ensure it is bound to the current session
        user = User.query.filter_by(email="user@test.com").first()
        from app.routes.auth.routes import generate_reset_token, verify_reset_token
        token = generate_reset_token(user)
        
        # Invalidate by altering password
        user.set_password("NewSecurePassword123!")
        db.session.commit()
        
        # Verify token is now rejected (stored_hash in token doesn't match current user hash)
        assert verify_reset_token(token) is None
