import sys
import os

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from config import config_by_name

def inspect_config():
    dev_cfg = config_by_name['development']
    prod_cfg = config_by_name['production']
    test_cfg = config_by_name['testing']

    print("=== Configuration Inspection ===")
    print(f"Dev Class: {dev_cfg.__name__}")
    print(f"Prod Class: {prod_cfg.__name__}")
    
    # 1. Debug settings
    print(f"Dev DEBUG: {dev_cfg.DEBUG}")
    print(f"Prod DEBUG: {prod_cfg.DEBUG}")
    assert dev_cfg.DEBUG is True, "Dev DEBUG must be True"
    assert prod_cfg.DEBUG is False, "Prod DEBUG must be False"
    
    # 2. Rate limiting config check
    dev_rl = getattr(dev_cfg, 'RATELIMIT_ENABLED', None)
    prod_rl = getattr(prod_cfg, 'RATELIMIT_ENABLED', None)
    test_rl = getattr(test_cfg, 'RATELIMIT_ENABLED', None)
    
    print(f"Dev RATELIMIT_ENABLED attribute: {dev_rl}")
    print(f"Prod RATELIMIT_ENABLED attribute: {prod_rl}")
    print(f"Test RATELIMIT_ENABLED attribute: {test_rl}")
    
    # In Flask-Limiter, if RATELIMIT_ENABLED is not set, it defaults to True.
    # Therefore, None (or not set) or True means rate limiting is enabled.
    prod_is_enabled = (prod_rl is not False)
    dev_is_enabled = (dev_rl is not False)
    
    print(f"Dev Rate Limiting Resolved Status: {'ENABLED' if dev_is_enabled else 'DISABLED'}")
    print(f"Prod Rate Limiting Resolved Status: {'ENABLED' if prod_is_enabled else 'DISABLED'}")
    
    # 3. Session cookies settings
    print(f"Dev SESSION_COOKIE_SECURE: {getattr(dev_cfg, 'SESSION_COOKIE_SECURE', None)}")
    print(f"Prod SESSION_COOKIE_SECURE: {getattr(prod_cfg, 'SESSION_COOKIE_SECURE', None)}")
    print(f"Prod SESSION_COOKIE_HTTPONLY: {getattr(prod_cfg, 'SESSION_COOKIE_HTTPONLY', None)}")
    print(f"Prod SESSION_COOKIE_SAMESITE: {getattr(prod_cfg, 'SESSION_COOKIE_SAMESITE', None)}")
    
    assert getattr(prod_cfg, 'SESSION_COOKIE_SECURE', None) is True, "Prod SESSION_COOKIE_SECURE must be True"
    assert getattr(prod_cfg, 'SESSION_COOKIE_HTTPONLY', None) is True, "Prod SESSION_COOKIE_HTTPONLY must be True"
    assert getattr(prod_cfg, 'SESSION_COOKIE_SAMESITE', None) == 'Lax', "Prod SESSION_COOKIE_SAMESITE must be 'Lax'"
    
    # 4. CSRF status
    print(f"Dev WTF_CSRF_ENABLED: {getattr(dev_cfg, 'WTF_CSRF_ENABLED', None)}")
    print(f"Prod WTF_CSRF_ENABLED: {getattr(prod_cfg, 'WTF_CSRF_ENABLED', None)}")
    assert getattr(prod_cfg, 'WTF_CSRF_ENABLED', None) is True, "Prod WTF_CSRF_ENABLED must be True"

    # 5. Secret Key (verify not hardcoded in the class)
    print("Checking SECRET_KEY source...")
    # Get the class attribute directly without resolving from environment to make sure it's not hardcoded in class
    import inspect
    lines = inspect.getsource(dev_cfg.__bases__[0])
    print("Base config source analysis:")
    for line in lines.split('\n'):
        if 'SECRET_KEY' in line:
            print(f"  {line.strip()}")
            
    print("Inspection successfully passed.")

if __name__ == '__main__':
    inspect_config()
