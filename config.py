"""
CyDefender Configuration
Central configuration for all models, settings, and paths
"""
import os
import sys
from typing import Dict, Any
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure terminal to use UTF-8 encoding to support emojis
try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    # For older Python versions
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)

# =============================================================================
# MODEL CONFIGURATION
# =============================================================================

# Primary LLM Model (Claude 3.5 Sonnet - good balance of capability and cost)
MODEL_CONFIG = {
    "name": "claude-3-5-sonnet-20241022",
    "temperature": 0,
    "max_tokens": 4000,
    "fallback_model": "claude-3-5-sonnet-20241022"
}

# Embeddings Model (Hugging Face sentence transformers)
EMBEDDINGS_CONFIG = {
    "model_name": "sentence-transformers/all-MiniLM-L6-v2",
    "chunk_size": 800,
    "chunk_overlap": 100
}

# =============================================================================
# DASHBOARD CONFIGURATION
# =============================================================================

DASHBOARD_CONFIG = {
    "auto_refresh_seconds": 10,
    "max_threats_display": 10,
    "max_rag_queries_display": 8,
    "max_recommendations_display": 5,
    "page_title": "CyDefender Security Dashboard",
    "page_icon": "🛡️"
}

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

LOGGING_CONFIG = {
    "log_directory": "app_logs",
    "max_log_entries": 50,
    "log_level": "INFO",
    "log_file": "app_logs/app.log",
    "rag_queries_file": "app_logs/rag_queries.json"
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

SECURITY_CONFIG = {
    "max_curl_timeout": 10,
    "max_agent_iterations": 100,
    "recursion_limit": 50,
    "request_timeout": 30
}

# =============================================================================
# PATH CONFIGURATION
# =============================================================================

PATHS_CONFIG = {
    "security_docs": "./security_docs",
    "security_kb": "./security_kb",
    "tools_dir": "./tools",
    "agents_dir": "./agents"
}

# =============================================================================
# API CONFIGURATION
# =============================================================================

API_CONFIG = {
    "base_url": "http://localhost:5000",
    "js_endpoint": "/main.js",
    "default_headers": {
        "User-Agent": "CyDefender Security Scanner",
        "Accept": "application/json"
    }
}

# =============================================================================
# THREAT DETECTION PATTERNS
# =============================================================================

THREAT_PATTERNS = {
    'SQL Injection': {
        'pattern': r"(SELECT.*FROM.*WHERE.*OR.*=.*=|UNION.*SELECT|DROP.*TABLE|INSERT.*INTO)",
        'score_base': 8.5,
        'level': 'CRITICAL'
    },
    'XSS Attack': {
        'pattern': r"<script.*>.*</script>|javascript:|onclick=|onerror=",
        'score_base': 9.0,
        'level': 'CRITICAL'
    },
    'Path Traversal': {
        'pattern': r"\.\./|\.\.\\\|/etc/passwd|/etc/shadow",
        'score_base': 7.5,
        'level': 'HIGH'
    },
    'Brute Force': {
        'pattern': r"Failed login attempt",
        'score_base': 6.0,
        'level': 'MEDIUM'
    },
    'DDoS Attack': {
        'pattern': r"DDoS.*detected|requests/second",
        'score_base': 9.5,
        'level': 'CRITICAL'
    },
    'Unauthorized Access': {
        'pattern': r"Unauthorized.*attempt|Access.*denied|hardcoded key",
        'score_base': 7.0,
        'level': 'HIGH'
    }
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_model_config() -> Dict[str, Any]:
    """Get the current model configuration"""
    return MODEL_CONFIG.copy()

def get_embeddings_config() -> Dict[str, Any]:
    """Get the embeddings configuration"""
    return EMBEDDINGS_CONFIG.copy()

def get_dashboard_config() -> Dict[str, Any]:
    """Get the dashboard configuration"""
    return DASHBOARD_CONFIG.copy()

def get_logging_config() -> Dict[str, Any]:
    """Get the logging configuration"""
    return LOGGING_CONFIG.copy()

def get_security_config() -> Dict[str, Any]:
    """Get the security configuration"""
    return SECURITY_CONFIG.copy()

def get_paths_config() -> Dict[str, Any]:
    """Get the paths configuration"""
    return PATHS_CONFIG.copy()

def get_api_config() -> Dict[str, Any]:
    """Get the API configuration"""
    return API_CONFIG.copy()

def get_threat_patterns() -> Dict[str, Any]:
    """Get the threat detection patterns"""
    return THREAT_PATTERNS.copy()

def get_full_config() -> Dict[str, Any]:
    """Get all configuration settings"""
    return {
        "model": get_model_config(),
        "embeddings": get_embeddings_config(),
        "dashboard": get_dashboard_config(),
        "logging": get_logging_config(),
        "security": get_security_config(),
        "paths": get_paths_config(),
        "api": get_api_config(),
        "threat_patterns": get_threat_patterns()
    }

def update_model(model_name: str, temperature: float = 0):
    """Update the model configuration"""
    global MODEL_CONFIG
    MODEL_CONFIG["name"] = model_name
    MODEL_CONFIG["temperature"] = temperature
    print(f"✅ Updated model to: {model_name}")

def update_dashboard_refresh(seconds: int):
    """Update dashboard refresh rate"""
    global DASHBOARD_CONFIG
    DASHBOARD_CONFIG["auto_refresh_seconds"] = seconds
    print(f"✅ Updated dashboard refresh to: {seconds} seconds")

# =============================================================================
# ENVIRONMENT VARIABLES (Optional overrides)
# =============================================================================

# Override with environment variables if they exist
if os.getenv("CLAUDE_MODEL"):
    MODEL_CONFIG["name"] = os.getenv("CLAUDE_MODEL")

if os.getenv("DASHBOARD_REFRESH"):
    DASHBOARD_CONFIG["auto_refresh_seconds"] = int(os.getenv("DASHBOARD_REFRESH"))

if os.getenv("LOG_LEVEL"):
    LOGGING_CONFIG["log_level"] = os.getenv("LOG_LEVEL")

if os.getenv("BASE_URL"):
    API_CONFIG["base_url"] = os.getenv("BASE_URL")

# =============================================================================
# VALIDATION
# =============================================================================

def validate_config():
    """Validate configuration settings"""
    errors = []
    
    # Check required directories exist
    required_dirs = [LOGGING_CONFIG["log_directory"], PATHS_CONFIG["security_docs"]]
    for dir_path in required_dirs:
        if not os.path.exists(dir_path):
            try:
                os.makedirs(dir_path)
                print(f"✅ Created directory: {dir_path}")
            except Exception as e:
                errors.append(f"Cannot create directory {dir_path}: {e}")
    
    # Check model name is valid
    valid_models = [
        "claude-3-5-sonnet-20241022",
        "claude-3-5-sonnet-20250106",
        "claude-sonnet-4-20250514"
    ]
    if MODEL_CONFIG["name"] not in valid_models:
        errors.append(f"Invalid model name: {MODEL_CONFIG['name']}")
    
    if errors:
        print("❌ Configuration validation failed:")
        for error in errors:
            print(f"  - {error}")
        return False
    
    print("✅ Configuration validation passed")
    return True

# Validate configuration on import
if __name__ == "__main__":
    validate_config()
    print("\n📋 Current Configuration:")
    import json
    print(json.dumps(get_full_config(), indent=2))