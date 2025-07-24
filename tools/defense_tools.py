from typing import Dict, Any, List
from langchain_core.tools import tool
from langchain_anthropic import ChatAnthropic
import json
import sys
from .security_kb_tool import init_security_tool
from .common import log_progress
from config import get_model_config
from reports.report_manager import report_manager

# Configure terminal to use UTF-8 encoding to support emojis
try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    # For older Python versions
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)

@tool
def analyze_logs(log_content: str) -> Dict[str, Any]:
    """
    Analyzes application logs to identify potential security attacks.
    
    Args:
        log_content: String containing application logs
        
    Returns:
        Dictionary containing identified attack patterns and details
    """
    log_progress("Analyzing application logs for attack patterns...", prefix="🛡️")
    
    try:
        model_config = get_model_config()
        llm = ChatAnthropic(
            temperature=model_config["temperature"],
            model=model_config["name"],
            max_tokens=model_config["max_tokens"]
        )
        
        analysis_prompt = f"""
        Analyze these application logs for potential security attacks:
        ```
        {log_content}
        ```
        
        You MUST respond with ONLY a valid JSON object in this exact format:
        {{
            "attack_type": "string describing the attack type (e.g., SQL Injection, XSS, Brute Force)",
            "target": "string describing the target endpoint or resource",
            "indicators": ["list", "of", "attack", "indicators"],
            "vulnerability": "string describing the vulnerability being exploited", 
            "evidence": ["relevant", "log", "entries"]
        }}
        
        Do NOT include any text before or after the JSON. Do NOT wrap in markdown code blocks.
        If no attack is detected, use "No Attack Detected" for attack_type and "N/A" for other fields.
        """
        
        response = llm.invoke(analysis_prompt)
        print("=" * 50)
        log_progress(f"Analysis: {response.content}")
        print("=" * 50)
        
        # Clean the response content to extract JSON
        response_content = response.content.strip()
        if "```json" in response_content:
            response_content = response_content.split("```json")[1].split("```")[0]
        elif "```" in response_content:
            response_content = response_content.split("```")[1].split("```")[0]
        
        response_content = response_content.strip()
        
        try:
            analysis = json.loads(response_content)
        except json.JSONDecodeError as json_error:
            log_progress(f"❌ JSON parsing failed: {json_error}")
            log_progress(f"Raw response: {response_content}")
            # Return a default structure if JSON parsing fails
            return {
                "attack_type": "Parse Error",
                "target": "Unknown", 
                "indicators": ["JSON parsing failed"],
                "vulnerability": "Analysis failed",
                "evidence": [response_content[:200] + "..."],
                "error": f"JSON parsing failed: {json_error}"
            }
        
        # Validate that all required keys exist
        required_keys = ['attack_type', 'target', 'vulnerability', 'indicators', 'evidence']
        for key in required_keys:
            if key not in analysis:
                analysis[key] = "Not specified"
        
        log_progress(f"Identified {analysis['attack_type']} attack targeting {analysis['target']}", prefix="🛡️")
        print("=" * 50)
        
        return analysis
        
    except Exception as e:
        log_progress(f"❌ Error analyzing logs: {str(e)}")
        return {"error": str(e)}

@tool
def identify_security_controls(attack_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Determines appropriate security controls based on attack analysis.
    
    Args:
        attack_analysis: Dictionary containing attack analysis details
        
    Returns:
        Dictionary containing recommended security controls
    """
    # Check if attack_analysis contains an error
    if 'error' in attack_analysis:
        log_progress(f"❌ Cannot identify controls - previous analysis failed: {attack_analysis['error']}")
        return {"error": "Attack analysis failed, cannot identify security controls"}
    
    # Check for parse errors
    if attack_analysis.get('attack_type') == 'Parse Error':
        log_progress(f"❌ Cannot identify controls - analysis parsing failed")
        return {"error": "Attack analysis parsing failed, cannot identify security controls"}
    
    # Check if required keys exist and have valid values
    required_keys = ['attack_type', 'target', 'vulnerability']
    missing_keys = [key for key in required_keys if key not in attack_analysis or attack_analysis[key] == "Not specified"]
    if missing_keys:
        log_progress(f"❌ Missing or invalid attack analysis data: {missing_keys}")
        return {"error": f"Missing or invalid attack analysis data: {missing_keys}"}
    
    log_progress(f"Identifying security controls for {attack_analysis['attack_type']} attack...", prefix="🛡️")
    
    try:
        security_kb = init_security_tool()
        if not security_kb:
            raise ValueError("Failed to initialize security knowledge base")
        
        query = f"""
        How to protect against {attack_analysis['attack_type']} attacks 
        targeting {attack_analysis['target']} where {attack_analysis['vulnerability']} 
        is being exploited?
        """

        log_progress(f"Query: {query}")
        print("=" * 50)
        
        # Query knowledge base
        controls = security_kb.invoke({"query": query})
        
        if 'results' not in controls:
            raise ValueError("Security controls query returned invalid response")
            
        log_progress(f"Found {len(controls['results'])} relevant security controls")
        log_progress(f"Controls: {controls['results']}")
        print("=" * 50)

        return {
            "attack_analysis": attack_analysis,
            "security_controls": controls['results']
        }
        
    except Exception as e:
        log_progress(f"❌ Error identifying controls: {str(e)}")
        return {"error": str(e)}
@tool
def generate_recommendations(security_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generates specific recommendations for implementing security controls.
    
    Args:
        security_info: Dictionary containing attack analysis and security controls
        
    Returns:
        Dictionary containing implementation recommendations
    """
    log_progress("Generating security control recommendations...", prefix="🛡️")
    
    # Check if security_info contains an error
    if 'error' in security_info:
        log_progress(f"❌ Cannot generate recommendations - previous step failed: {security_info['error']}")
        return {"error": "Security controls identification failed, cannot generate recommendations"}
    
    # Check if required keys exist
    required_keys = ['attack_analysis', 'security_controls']
    missing_keys = [key for key in required_keys if key not in security_info]
    if missing_keys:
        log_progress(f"❌ Missing required security info: {missing_keys}")
        return {"error": f"Missing required security info: {missing_keys}"}
    
    try:
        model_config = get_model_config()
        llm = ChatAnthropic(
            temperature=model_config["temperature"],
            model=model_config["name"],
            max_tokens=model_config["max_tokens"]
        )
        
        recommendations_prompt = f"""
        Based on this security information:
        Attack Analysis: {json.dumps(security_info['attack_analysis'], indent=2)}
        Security Controls: {json.dumps(security_info['security_controls'], indent=2)}
        
        Generate specific recommendations for implementing security controls to prevent this attack.
        
        Include:
        1. Prioritized list of actions to take
        2. Any Configuration changes that might be needed
        
        Format your response as a JSON object with these keys:
        - immediate_actions: list of high-priority actions
        - configuration_changes: required configuration updates
        """
        
        log_progress(f"Generating recommendations for {security_info['attack_analysis']['attack_type']} attack...", prefix="🛡️")
        log_progress(f"Recommendations Prompt: {recommendations_prompt}")
        print("=" * 50)
        response = llm.invoke(recommendations_prompt)
        
        # Clean the response content to extract JSON
        response_content = response.content.strip()
        if "```json" in response_content:
            response_content = response_content.split("```json")[1].split("```")[0]
        elif "```" in response_content:
            response_content = response_content.split("```")[1].split("```")[0]
        
        response_content = response_content.strip()
        recommendations = json.loads(response_content)
        
        log_progress(f"Generated Recommendations: {recommendations}")
        print("=" * 50)
        
        # Add to report manager
        if 'immediate_actions' in recommendations:
            for action in recommendations.get('immediate_actions', []):
                # Ensure action is a string
                if isinstance(action, dict):
                    action_str = str(action)
                elif isinstance(action, list):
                    action_str = ', '.join(str(a) for a in action)
                else:
                    action_str = str(action) if action else 'Unknown Action'
                
                # Ensure target is a string
                target_info = security_info.get('attack_analysis', {}).get('target', 'System')
                if isinstance(target_info, dict):
                    target_str = str(target_info)
                elif isinstance(target_info, list):
                    target_str = ', '.join(str(t) for t in target_info)
                else:
                    target_str = str(target_info) if target_info else 'System'
                
                defense_data = {
                    'action_type': 'Immediate Action',
                    'description': action_str,
                    'target': target_str,
                    'effectiveness': 'High'
                }
                report_manager.add_defense_action(defense_data)
        
        return recommendations
        
    except Exception as e:
        log_progress(f"❌ Error generating recommendations: {str(e)}")
        return {"error": str(e)}