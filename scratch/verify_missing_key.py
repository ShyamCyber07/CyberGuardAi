import os
import sys
import json

# Ensure workspace is in python path
sys.path.append(r"c:\Users\praja\Desktop\CyberGuardAi")

from app import create_app
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan, ScanResult
from app.services.ai_service import AIAnalysisService, MissingAPIKeyError
from app.services.ai_assistant_service import AIAssistantService, MissingAPIKeyError as AssistantMissingAPIKeyError

app = create_app('testing')
app.config['WTF_CSRF_ENABLED'] = False
app.config['TESTING'] = True

# Explicitly ensure GEMINI_API_KEY is not in the environment
if "GEMINI_API_KEY" in os.environ:
    del os.environ["GEMINI_API_KEY"]

print("==================================================")
print("VERIFYING MISSING GEMINI_API_KEY BEHAVIOR")
print("==================================================")

# Check dynamically
detected_status = "CONFIGURED" if os.environ.get("GEMINI_API_KEY") else "MISSING"
print(f"GEMINI_API_KEY: {detected_status}")
if detected_status == "MISSING":
    print("GEMINI_API_KEY is not configured. Add your Gemini API key to .env and restart the application.")

# 1. Verify AIAnalysisService.analyze_scan raises MissingAPIKeyError
try:
    print("\n[Test 1] Invoking AIAnalysisService.analyze_scan without API key...")
    payload = {
        "target": "example.com",
        "scan_type": "website",
        "findings": []
    }
    AIAnalysisService.analyze_scan(payload)
    print("FAIL: AIAnalysisService did not raise MissingAPIKeyError.")
except MissingAPIKeyError as e:
    print(f"SUCCESS: Caught expected MissingAPIKeyError: {e}")
except Exception as e:
    print(f"FAIL: Caught unexpected exception: {type(e).__name__}: {e}")

# 2. Verify AIAssistantService.ask_question raises MissingAPIKeyError
with app.app_context():
    # Setup test user and scan in temp test DB
    db.create_all()
    user = User.query.filter_by(email="test@example.com").first()
    if not user:
        user = User(email="test@example.com", role="analyst")
        user.set_password("TestPass123!")
        db.session.add(user)
        db.session.commit()
    
    scan = Scan.query.filter_by(target_destination="example.com").first()
    if not scan:
        scan = Scan(target_type="website", target_destination="example.com", user_id=user.id, status="completed")
        db.session.add(scan)
        db.session.commit()

    try:
        print("\n[Test 2] Invoking AIAssistantService.ask_question without API key...")
        AIAssistantService.ask_question(
            user_id=user.id,
            scan_type="website",
            scan_uuid=scan.uuid,
            user_question="What is this scan about?"
        )
        print("FAIL: AIAssistantService did not raise MissingAPIKeyError.")
    except AssistantMissingAPIKeyError as e:
        print(f"SUCCESS: Caught expected AssistantMissingAPIKeyError: {e}")
    except Exception as e:
        print(f"FAIL: Caught unexpected exception: {type(e).__name__}: {e}")

    # 3. Test HTTP Client Route response behavior
    print("\n[Test 3] Requesting assistant/ask HTTP route without API key...")
    client = app.test_client()
    with client.session_transaction() as sess:
        sess['_user_id'] = str(user.id)
        sess['_fresh'] = True

    response = client.post('/assistant/ask', json={
        "scan_uuid": scan.uuid,
        "scan_type": "website",
        "question": "Explain scanner results."
    })
    print(f"HTTP Response Status: {response.status_code}")
    print(f"HTTP Response Body: {response.get_data(as_text=True).strip()}")
    assert response.status_code == 500
    assert "GEMINI_API_KEY" in response.get_data(as_text=True)
    print("SUCCESS: HTTP route returned 500 containing GEMINI_API_KEY message without tracebacks.")

print("\nAll missing key fallback checks passed successfully!")
print("==================================================")
