import os
import json
import requests
from app.models.scan import Scan
from app.models.network_scan import NetworkScan

class PromptBuilder:
    """Utility class to compile structured and secure prompts for Gemini AI."""

    @staticmethod
    def build_prompt_for_website_scan(scan: Scan) -> str:
        findings_summary = []
        for result in scan.results:
            findings_summary.append(
                f"- Name: {result.vulnerability_name}\n"
                f"  Severity: {result.severity.upper()}\n"
                f"  Description: {result.description}\n"
                f"  Remediation: {result.remediation}"
            )
        
        findings_str = "\n".join(findings_summary) if findings_summary else "No vulnerabilities detected."

        prompt = f"""You are an expert defensive cybersecurity assistant.
Your task is to analyze and explain the security scanner results for the website target: {scan.target_destination}.

Here are the scan results:
{findings_str}

CRITICAL RULES:
1. Under no circumstances may you invent, suggest, or assume other vulnerabilities exist. ONLY explain the vulnerabilities listed above.
2. If there are no vulnerabilities, confirm that the site is well-secured.
3. Respond strictly in valid JSON format. Do not wrap the JSON in markdown code blocks or text. Return only the JSON object.

JSON Response Schema:
{{
  "executive_summary": "High-level summary of the security posture of the audited site.",
  "technical_summary": "Technical review explaining the mechanics of the identified weaknesses.",
  "recommendations": [
    {{
      "vulnerability": "Name of the vulnerability from the list",
      "remediation": "Step-by-step resolution advice"
    }}
  ],
  "risk_priorities": [
    {{
      "vulnerability": "Name of the vulnerability",
      "priority": "High / Medium / Low / Info",
      "rationale": "Rationale explaining why this is prioritized."
    }}
  ]
}}
"""
        return prompt

    @staticmethod
    def build_prompt_for_network_scan(scan: NetworkScan) -> str:
        findings_summary = []
        for result in scan.results:
            findings_summary.append(
                f"- Port: {result.port}/{result.protocol}\n"
                f"  Service: {result.service_name} (Version: {result.service_version if result.service_version else 'Unknown'})\n"
                f"  State: {result.state}\n"
                f"  Severity: {result.severity.upper()}\n"
                f"  Remediation: {result.remediation}"
            )
            
        findings_str = "\n".join(findings_summary) if findings_summary else "No open ports or services detected."

        prompt = f"""You are an expert defensive cybersecurity assistant.
Your task is to analyze and explain the network scanner port results for target host IP: {scan.ip_address}.

Here are the scan results:
{findings_str}

CRITICAL RULES:
1. Under no circumstances may you invent, suggest, or assume other open ports or vulnerabilities exist. ONLY explain the findings listed above.
2. Respond strictly in valid JSON format. Do not wrap the JSON in markdown code blocks or text. Return only the JSON object.

JSON Response Schema:
{{
  "executive_summary": "High-level summary of the security posture of the target host IP node.",
  "technical_summary": "Technical explanation of the services running and their risks.",
  "recommendations": [
    {{
      "vulnerability": "Service / Port probed",
      "remediation": "Step-by-step action to secure the service"
    }}
  ],
  "risk_priorities": [
    {{
      "vulnerability": "Service / Port",
      "priority": "High / Medium / Low / Info",
      "rationale": "Rationale explaining the risk priority assignment."
    }}
  ]
}}
"""
        return prompt


class LocalHeuristicFallback:
    """Fallback generator providing structured mock responses when Gemini API is offline."""

    @staticmethod
    def explain_website_scan(scan: Scan) -> str:
        recs = []
        priorities = []
        
        for r in scan.results:
            recs.append({
                "vulnerability": r.vulnerability_name,
                "remediation": r.remediation
            })
            priorities.append({
                "vulnerability": r.vulnerability_name,
                "priority": r.severity.capitalize(),
                "rationale": f"Calculated based on standard OWASP risk severity mappings for {r.vulnerability_name}."
            })
            
        if not recs:
            recs.append({"vulnerability": "None", "remediation": "No actions required."})
            priorities.append({"vulnerability": "None", "priority": "Info", "rationale": "Safe state."})

        data = {
            "executive_summary": f"Offline Report: Scan for {scan.target_destination} analyzed. Overall vulnerability count: {len(scan.results)}.",
            "technical_summary": "Local heuristics review. Missing security headers limit transport confidentiality and client-side code execution controls.",
            "recommendations": recs,
            "risk_priorities": priorities
        }
        return json.dumps(data)

    @staticmethod
    def explain_network_scan(scan: NetworkScan) -> str:
        recs = []
        priorities = []
        
        for r in scan.results:
            recs.append({
                "vulnerability": f"Port {r.port}/{r.protocol} ({r.service_name})",
                "remediation": r.remediation
            })
            priorities.append({
                "vulnerability": f"Port {r.port}/{r.protocol} ({r.service_name})",
                "priority": r.severity.capitalize(),
                "rationale": f"Service active state probed on port {r.port}."
            })
            
        if not recs:
            recs.append({"vulnerability": "None", "remediation": "No actions required."})
            priorities.append({"vulnerability": "None", "priority": "Info", "rationale": "No open ports."})

        data = {
            "executive_summary": f"Offline Report: Network scan for host {scan.ip_address} compiled. Detected {len(scan.results)} open port listeners.",
            "technical_summary": "Local port security review. Active server services present endpoints that should be firewall-restricted.",
            "recommendations": recs,
            "risk_priorities": priorities
        }
        return json.dumps(data)


class GeminiService:
    """Service class executing calls to the Gemini generative language REST API."""

    @staticmethod
    def explain_scan(scan_obj) -> dict:
        """Call Gemini API or fall back to local heuristics if offline, returning structured JSON dictionary."""
        api_key = os.getenv('GEMINI_API_KEY')
        is_offline = not api_key
        
        # Identify scan type (Website Scan vs Network Scan)
        is_network = isinstance(scan_obj, NetworkScan)
        
        # 1. Compile target prompt
        if is_network:
            prompt = PromptBuilder.build_prompt_for_network_scan(scan_obj)
        else:
            prompt = PromptBuilder.build_prompt_for_website_scan(scan_obj)

        raw_json_resp = None
        model_used = "local-heuristic-model"

        # 2. Run REST call if API key exists
        if not is_offline:
            try:
                # Use Configured Gemini API endpoint
                model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
                payload = {
                    "contents": [
                        {
                            "parts": [
                                {"text": prompt}
                            ]
                        }
                    ],
                    "generationConfig": {
                        "responseMimeType": "application/json"
                    }
                }
                headers = {"Content-Type": "application/json"}
                
                response = requests.post(url, json=payload, headers=headers, timeout=12.0)
                
                if response.status_code == 200:
                    model_used = model
                    resp_data = response.json()
                    
                    # Extract generation output text
                    candidates = resp_data.get('candidates', [])
                    if candidates:
                        parts = candidates[0].get('content', {}).get('parts', [])
                        if parts:
                            raw_json_resp = parts[0].get('text', '').strip()
                
            except Exception:
                # Log error silently and fallback
                pass

        # 3. Apply Local Heuristics Fallback if call failed or was skipped
        if not raw_json_resp:
            model_used = "local-heuristic-fallback"
            if is_network:
                raw_json_resp = LocalHeuristicFallback.explain_network_scan(scan_obj)
            else:
                raw_json_resp = LocalHeuristicFallback.explain_website_scan(scan_obj)

        # 4. Deserialize response text safely
        try:
            parsed_data = json.loads(raw_json_resp)
        except Exception:
            # Emergency fallback if model returned invalid json
            if is_network:
                parsed_data = json.loads(LocalHeuristicFallback.explain_network_scan(scan_obj))
            else:
                parsed_data = json.loads(LocalHeuristicFallback.explain_website_scan(scan_obj))

        return {
            'prompt': prompt,
            'response_data': parsed_data,
            'model_used': model_used
        }
