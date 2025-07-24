from typing import Dict, Any
from langchain_core.tools import tool
from langchain_anthropic import ChatAnthropic
import json
import subprocess
from .common import log_progress
from config import get_model_config, get_security_config
from reports.report_manager import report_manager

@tool
def analyze_security_response(response: str, endpoint: str = "Unknown") -> Dict[str, Any]:
    """Analyzes a response for security issues."""
    log_progress("Analyzing response for security vulnerabilities...")
    
    try:
        model_config = get_model_config()
        llm = ChatAnthropic(
            temperature=model_config["temperature"],
            model=model_config["name"],
            max_tokens=model_config["max_tokens"]
        )
        
        analysis_prompt = """
        Analyze this HTTP response for SPECIFIC security vulnerabilities:
        ```
        """ + response + """
        ```

        Focus on SPECIFIC findings, not general categories. For example:
        - Instead of "Missing Security Headers", specify "Missing X-Frame-Options header allows clickjacking"
        - Instead of "Sensitive Data Exposure", specify "Database connection string exposed in error message"
        - Instead of "PII Disclosure", specify "User email addresses visible in JSON response without authorization"

        Look for:
        1. Specific sensitive data in response body (actual values, not categories)
        2. Exact missing security headers and their impact
        3. Detailed error messages revealing system information
        4. Specific authentication/authorization bypasses
        5. Exact server version disclosures or stack traces
        6. Precise timing attack vectors or information leakage

        If no SPECIFIC vulnerability is found, return "No specific vulnerabilities detected".

        Return ONLY a valid JSON object with these exact keys (no markdown, no extra text):
        {
            "vulnerability": "specific vulnerability description",
            "severity": "Critical",
            "evidence": "exact text from response",
            "recommendations": ["specific fix 1", "specific fix 2"]
        }

        IMPORTANT: Response must be valid JSON only. No explanations, no markdown, no code blocks."""
        
        response_content = llm.invoke(analysis_prompt).content
        
        # Clean the response content
        if "```json" in response_content:
            response_content = response_content.split("```json")[1].split("```")[0]
        elif "```" in response_content:
            response_content = response_content.split("```")[1].split("```")[0]
            
        response_content = response_content.strip()
        
        # Additional cleaning for common JSON issues
        response_content = response_content.replace('\n', ' ').replace('\r', '')
        
        try:
            analysis = json.loads(response_content)
        except json.JSONDecodeError as e:
            log_progress(f"JSON parsing failed: {str(e)}")
            log_progress(f"Raw response: {response_content[:200]}...")
            # Fallback analysis
            analysis = {
                "vulnerability": "JSON parsing error in analysis",
                "severity": "Low",
                "evidence": f"Parser error: {str(e)}",
                "recommendations": ["Fix analysis response format"]
            }
        
        vulnerability = analysis.get('vulnerability', '')
        if vulnerability and vulnerability != "No specific vulnerabilities detected":
            log_progress("Specific Vulnerability Found:")
            log_progress(f"  ⚠️  {vulnerability}")
            log_progress(f"  🔍 Severity: {analysis.get('severity', 'Unknown')}")
            if analysis.get('evidence'):
                log_progress(f"  📝 Evidence: {analysis['evidence'][:100]}...")
            
            vuln_data = {
                'endpoint': endpoint,
                'vulnerability': vulnerability,
                'severity': analysis.get('severity', 'Medium'),
                'description': vulnerability,
                'evidence': analysis.get('evidence', ''),
                'recommendations': analysis.get('recommendations', [])
            }
            report_manager.add_vulnerability(vuln_data)
        else:
            log_progress("No specific vulnerabilities detected in this response.")
        
        return analysis
    except Exception as e:
        log_progress(f"❌ Error analyzing response: {str(e)}")
        return {"error": str(e)}

@tool
def execute_security_test(endpoint: str, base_url: str, requirements: Dict[str, Any]) -> str:
    """
    Uses LLM to craft and execute security tests based on analyzed requirements.
    """
    log_progress(f"Starting security test execution for {endpoint}")
    log_progress(f"Base URL: {base_url}")
    log_progress(f"Requirements: {json.dumps(requirements, indent=2)}")
    
    try:
        model_config = get_model_config()
        llm = ChatAnthropic(
            temperature=model_config["temperature"],
            model=model_config["name"],
            max_tokens=model_config["max_tokens"]
        )
        
        # Ask LLM to craft the test request
        craft_prompt = f"""
        Based on these requirements for endpoint {endpoint}:
        {json.dumps(requirements, indent=2)}

        Craft a curl command that would test this endpoint. Consider:
        1. If authentication is required
        2. Any specific header values found
        3. Any secrets or tokens discovered
        4. The most likely vulnerabilities

        Format the response as a JSON object with:
        - method: HTTP method to use
        - headers: dictionary of headers to include
        - notes: why you chose these test values

        DO NOT include the actual curl command in your response."""
        
        test_config = json.loads(llm.invoke(craft_prompt).content)
        log_progress(f"Test configuration generated: {json.dumps(test_config, indent=2)}")
        
        # Build and execute curl command
        url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        cmd = ['curl', '-i', '-s', '-X', test_config['method']]
        
        for key, value in test_config['headers'].items():
            cmd.extend(['-H', f'{key}: {value}'])
        
        cmd.append(url)
        
        log_progress(f"Executing curl command: {' '.join(cmd)}")
        security_config = get_security_config()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=security_config["max_curl_timeout"])
        
        if result.stdout:
            log_progress(f"Response received - Status: {result.stdout.split()[1] if ' ' in result.stdout else 'unknown'}")
            log_progress(f"Response: {result.stdout}")
        else:
            log_progress("No response received from the server")
            
        if result.stderr:
            log_progress(f"Errors during execution: {result.stderr}")
        
        return result.stdout
        
    except Exception as e:
        log_progress(f"❌ Test failed: {str(e)}")
        return f"Error: {str(e)}" 