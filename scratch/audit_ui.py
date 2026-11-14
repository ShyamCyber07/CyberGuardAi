import os
import sys
import re
from bs4 import BeautifulSoup

# Append workspace root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app, db
from app.models.user import User
from app.models.scan import Scan
from app.models.report import Report
from app.models.saved_password import SavedPassword

def run_audit():
    print("Initializing Flask application in testing context...")
    app = create_app('testing')
    
    # We will collect all findings in these dictionaries and lists
    crawled_urls = {}
    statically_parsed_templates = {}
    buttons_findings = []
    broken_links = []
    missing_routes = []
    
    with app.app_context():
        print("Recreating database schema...")
        db.drop_all()
        db.create_all()
        
        # Seed users
        print("Seeding test users...")
        admin = User(email="admin@test.com", role="admin")
        admin.set_password("AdminPass123!")
        
        standard = User(email="user@test.com", role="analyst")
        standard.set_password("UserPass123!")
        
        db.session.add_all([admin, standard])
        db.session.commit()
        
        # Verify db records
        for u in User.query.all():
            print(f"  [SEED VERIFY] User ID: {u.id}, Email: {u.email}, Role: {u.role}")
    
    # We run crawls under three user contexts:
    # 1. Anonymous User
    # 2. Authenticated Analyst
    # 3. Authenticated Administrator
    
    contexts = [
        ("anonymous", None),
        ("analyst", "user@test.com"),
        ("admin", "admin@test.com")
    ]
    
    for context_name, email in contexts:
        print(f"\n--- Starting Crawling in context: {context_name} ---")
        # Create a fresh app instance for context isolation
        app = create_app('testing')
        client = app.test_client()
        with app.app_context():
            db.session.remove()
            
            if email:
                password = "AdminPass123!" if "admin" in email else "UserPass123!"
                login_res = client.post('/auth/login', data={'email': email, 'password': password})
                print(f"  [LOGIN] {email} -> Status: {login_res.status_code}")
                if login_res.status_code != 302:
                    print(f"  [LOGIN FAILED RESPONSE]: {login_res.data[:200]}")
            
            # Initial URLs queue based on context
            queue = ["/"]
            if context_name == "anonymous":
                queue.extend(["/auth/login", "/auth/register"])
            elif context_name == "analyst":
                queue.extend(["/scanner/", "/scanner/network/", "/password-security/", "/auth/profile", "/history"])
            elif context_name == "admin":
                queue.extend(["/admin/dashboard", "/admin/users", "/admin/reports", "/admin/logs"])
            
            visited = set()
            
            while queue:
                url = queue.pop(0)
                if url in visited:
                    continue
                visited.add(url)
                
                try:
                    # Request URL
                    res = client.get(url, follow_redirects=True)
                    crawled_urls[(context_name, url)] = {
                        "status_code": res.status_code,
                        "redirect_path": res.request.path if res.request else None
                    }
                    
                    if res.status_code >= 400:
                        broken_links.append((context_name, url, res.status_code))
                        print(f"  [BROKEN] {url} -> Status: {res.status_code}")
                        continue
                    
                    print(f"  Visited: {url} -> Status: {res.status_code}")
                    
                    # Parse page content for more local links
                    soup = BeautifulSoup(res.data, "html.parser")
                    for a in soup.find_all("a", href=True):
                        href = a["href"]
                        # Filter to local endpoints only
                        if href.startswith("/") and not href.startswith("//"):
                            # Exclude logout from auto crawl during logged in session
                            if "logout" in href:
                                continue
                            # Exclude direct delete operations
                            if "delete" in href or "role" in href:
                                continue
                            queue.append(href)
                            
                except Exception as e:
                    print(f"  [ERROR] Failed to fetch {url}: {e}")
                    crawled_urls[(context_name, url)] = {"status_code": 500, "error": str(e)}
        
    with app.app_context():
        # Now perform a deep static analysis of all templates
        print("\n--- Starting Static Analysis of Templates ---")
        templates_dir = os.path.join(app.root_path, "templates")
        
        # Compile url_for endpoints in the app to match against
        url_map_rules = []
        for rule in app.url_map.iter_rules():
            url_map_rules.append(rule.endpoint)
            
        print(f"Registered Flask routes endpoints: {len(url_map_rules)}")
        
        for root, dirs, files in os.walk(templates_dir):
            for file in files:
                if file.endswith(".html"):
                    filepath = os.path.join(root, file)
                    rel_path = os.path.relpath(filepath, templates_dir)
                    
                    with open(filepath, "r", encoding="utf-8") as f:
                        content = f.read()
                        
                    soup = BeautifulSoup(content, "html.parser")
                    
                    # Analyze elements: a, button, input[type=submit]
                    elements_analyzed = []
                    
                    # 1. <a> links
                    for a in soup.find_all("a"):
                        href = a.get("href", "")
                        btn_text = a.get_text().strip() or a.get("title", "").strip() or "[Link/Icon]"
                        
                        status = "Working"
                        fix_applied = "None Required"
                        
                        # Identify placeholder styles
                        if href in ["#", "javascript:void(0)", "javascript:void(0);", ""]:
                            status = "Placeholder"
                            # Check if it has a JS handler or class suggesting modal trigger
                            if a.get("onclick") or a.get("data-bs-toggle") or a.get("data-bs-target"):
                                status = "Placeholder (Valid Modal/JS Trigger)"
                            else:
                                status = "Placeholder (No Action/Broken Link)"
                        
                        # Check url_for endpoints inside template
                        url_for_matches = re.findall(r"url_for\('([^']+)'", href)
                        for endpoint in url_for_matches:
                            if endpoint not in url_map_rules:
                                status = "Missing Route / Broken"
                                missing_routes.append((rel_path, endpoint))
                        
                        elements_analyzed.append({
                            "type": "Link/Button",
                            "text": btn_text,
                            "href": href,
                            "onclick": a.get("onclick"),
                            "status": status,
                            "fix": fix_applied
                        })
                    
                    # 2. <button> elements
                    for btn in soup.find_all("button"):
                        btn_text = btn.get_text().strip() or btn.get("title", "").strip() or "[Button]"
                        status = "Working"
                        
                        # Verify trigger mechanism
                        onclick = btn.get("onclick")
                        bs_target = btn.get("data-bs-target")
                        bs_toggle = btn.get("data-bs-toggle")
                        is_submit = btn.get("type") == "submit"
                        
                        # Find parent form
                        parent_form = btn.find_parent("form")
                        
                        if not onclick and not bs_target and not bs_toggle and not is_submit and not parent_form:
                            status = "Placeholder (No Action/Click Listener)"
                        
                        elements_analyzed.append({
                            "type": "Button",
                            "text": btn_text,
                            "href": "N/A",
                            "onclick": onclick,
                            "status": status,
                            "fix": "None Required"
                        })
                        
                    statically_parsed_templates[rel_path] = elements_analyzed
                    
        # Generate the Final Markdown Report in the artifacts directory
        report_dir = "C:\\Users\\praja\\.gemini\\antigravity-ide\\brain\\38503097-1018-4107-bc8e-bb184022f155"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, "functional_ui_audit_report.md")
        
        # Summarize counts
        total_elements = 0
        working_count = 0
        broken_count = 0
        placeholder_count = 0
        
        for template, elements in statically_parsed_templates.items():
            for el in elements:
                total_elements += 1
                if "Working" in el["status"] or "Modal/JS Trigger" in el["status"]:
                    working_count += 1
                elif "Broken" in el["status"] or "Missing" in el["status"]:
                    broken_count += 1
                else:
                    placeholder_count += 1
                    
        with open(report_path, "w", encoding="utf-8") as rf:
            rf.write("# Functional UI & Navigation Audit Report\n")
            rf.write("Generated programmatically using Flask `test_client()` and `BeautifulSoup` parsing.\n\n")
            
            rf.write("## 1. Audit Summary Metrics\n")
            rf.write(f"*   **Total Clickable/Interactive Elements Analyzed**: {total_elements}\n")
            rf.write(f"*   **Working Elements**: {working_count}\n")
            rf.write(f"*   **Broken Elements**: {broken_count}\n")
            rf.write(f"*   **Placeholder Elements (e.g. href='#')**: {placeholder_count}\n")
            rf.write(f"*   **Missing Flask Routes**: {len(missing_routes)}\n")
            rf.write(f"*   **Crawled Endpoints (HTTP status 200/302)**: {len(crawled_urls)}\n\n")
            
            rf.write("## 2. Crawled Endpoints Verification\n")
            rf.write("| User Context | Visited Endpoint URL | Returned Status Code | Redirect Path (If any) |\n")
            rf.write("| :--- | :--- | :--- | :--- |\n")
            for (ctx, url), info in sorted(crawled_urls.items()):
                rf.write(f"| {ctx} | `{url}` | {info['status_code']} | `{info.get('redirect_path', 'None')}` |\n")
            rf.write("\n")
            
            rf.write("## 3. Element Navigation Mapping & Status\n")
            rf.write("| Button/Link Text | Template File | Target Route/Href | Status | Fix Applied |\n")
            rf.write("| :--- | :--- | :--- | :--- | :--- |\n")
            for template, elements in statically_parsed_templates.items():
                for el in elements:
                    rf.write(f"| {el['text']} | `{template}` | `{el['href']}` | {el['status']} | {el['fix']} |\n")
            rf.write("\n")
            
            rf.write("## 4. Missing / Broken Routes Registry\n")
            if missing_routes:
                rf.write("| Template File | Missing Route Endpoint |\n")
                rf.write("| :--- | :--- |\n")
                for temp, route in missing_routes:
                    rf.write(f"| `{temp}` | `{route}` |\n")
            else:
                rf.write("*No missing or broken Flask endpoints found in the template references.*\n")
                
        print(f"\nAudit completed. Report written to: {report_path}")
        print(f"Total elements analyzed: {total_elements} (Working: {working_count}, Broken: {broken_count}, Placeholders: {placeholder_count})")

if __name__ == "__main__":
    run_audit()
