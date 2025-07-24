import streamlit as st
import pandas as pd
import json
import time
import re
import random
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import os
from config import get_dashboard_config, get_logging_config, get_threat_patterns

# Try to import RAG logger, create dummy if not available
try:
    from rag_query_logger import rag_logger, simulate_rag_queries
    RAG_LOGGER_AVAILABLE = True
except ImportError:
    RAG_LOGGER_AVAILABLE = False
    class DummyRAGLogger:
        def get_recent_queries(self, limit=10):
            return []
    rag_logger = DummyRAGLogger()
    def simulate_rag_queries():
        pass

# Configure page from config
dashboard_config = get_dashboard_config()
st.set_page_config(
    page_title=dashboard_config["page_title"],
    page_icon=dashboard_config["page_icon"],
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Clean, modern CSS styling
st.markdown("""
<style>
    /* Global reset and base styling */
    .main .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
        max-width: 100%;
        padding-left: 1rem;
        padding-right: 1rem;
    }
    
    /* Hide Streamlit branding */
    header[data-testid="stHeader"] {
        display: none;
    }
    
    .stAppToolbar {
        display: none;
    }
    
    /* Dashboard header */
    .dashboard-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1.5rem;
        text-align: center;
        border-radius: 12px;
        margin-bottom: 1rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    .dashboard-header h1 {
        margin: 0;
        font-size: 2.2rem;
        font-weight: 700;
        color: white;
    }
    
    /* Panel styling */
    .panel {
        background: white;
        border-radius: 12px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border: 1px solid #e0e0e0;
        height: 500px;
        overflow-y: auto;
    }
    
    /* Panel headers */
    .panel-header {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #f0f0f0;
        margin-bottom: 0.75rem;
    }
    
    .panel-header .icon {
        font-size: 1.5rem;
    }
    
    .panel-header .title {
        font-size: 1.1rem;
        font-weight: 700;
        color: #2c3e50;
        margin: 0;
    }
    
    /* Threat panel specific styling */
    .threat-panel .panel-header {
        border-bottom-color: #e74c3c;
    }
    
    .threat-panel .icon {
        color: #e74c3c;
    }
    
    /* RAG panel specific styling */
    .rag-panel .panel-header {
        border-bottom-color: #3498db;
    }
    
    .rag-panel .icon {
        color: #3498db;
    }
    
    /* Recommendations panel specific styling */
    .recommendations-panel .panel-header {
        border-bottom-color: #2ecc71;
    }
    
    .recommendations-panel .icon {
        color: #2ecc71;
    }
    
    /* Content cards */
    .content-card {
        background: #f8f9fa;
        border: 1px solid #e9ecef;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
        transition: all 0.2s ease;
    }
    
    .content-card:hover {
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        transform: translateY(-1px);
    }
    
    .content-card h3 {
        color: #2c3e50;
        font-size: 1rem;
        font-weight: 600;
        margin: 0 0 0.5rem 0;
    }
    
    .content-card p {
        color: #5a6c7d;
        font-size: 0.9rem;
        margin: 0.3rem 0;
    }
    
    .content-card .metric {
        font-weight: 600;
        color: #2c3e50;
    }
    
    /* Threat level indicators */
    .threat-critical {
        border-left: 4px solid #e74c3c;
        background: #fdf2f2;
    }
    
    .threat-high {
        border-left: 4px solid #f39c12;
        background: #fef9e7;
    }
    
    .threat-medium {
        border-left: 4px solid #f1c40f;
        background: #fffbf0;
    }
    
    /* MITRE badges */
    .mitre-badge {
        display: inline-block;
        background: #3498db;
        color: white;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: 500;
        margin: 0.1rem 0.2rem 0.1rem 0;
    }
    
    /* Action list styling */
    .action-list {
        list-style: none;
        padding: 0;
        margin: 0.5rem 0;
    }
    
    .action-list li {
        padding: 0.3rem 0;
        border-bottom: 1px solid #ecf0f1;
    }
    
    .action-list li:last-child {
        border-bottom: none;
    }
    
    .action-list li::before {
        content: "→";
        color: #2ecc71;
        font-weight: bold;
        margin-right: 0.5rem;
    }
    
    /* Priority indicators */
    .priority-critical {
        color: #e74c3c;
        font-weight: 700;
    }
    
    .priority-high {
        color: #f39c12;
        font-weight: 700;
    }
    
    .priority-medium {
        color: #f1c40f;
        font-weight: 700;
    }
    
    /* Empty state */
    .empty-state {
        text-align: center;
        padding: 2rem;
        color: #7f8c8d;
    }
    
    .empty-state .icon {
        font-size: 3rem;
        margin-bottom: 1rem;
        display: block;
    }
    
    /* Unified panel styling */
    .unified-panel {
        background: white;
        border-radius: 8px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        border: 1px solid #e0e0e0;
        margin-bottom: 1rem;
        overflow: hidden;
    }
    
    /* Responsive design */
    @media (max-width: 768px) {
        .dashboard-header h1 {
            font-size: 1.8rem;
        }
        
        .panel {
            height: auto;
            min-height: 400px;
        }
    }
</style>
""", unsafe_allow_html=True)

class ThreatDetector:
    def __init__(self):
        self.threat_patterns = get_threat_patterns()
    
    def generate_sample_threats(self) -> List[Dict]:
        """Generate sample threats for demonstration"""
        sample_threats = [
            {
                'threat_type': 'SQL Injection',
                'score': 8.5,
                'ip': '10.0.0.5',
                'timestamp': '10:34:00',
                'level': 'CRITICAL',
                'message': 'SELECT * FROM users WHERE id = 1 OR 1=1'
            },
            {
                'threat_type': 'XSS Attack',
                'score': 9.0,
                'ip': '127.0.0.1',
                'timestamp': '10:32:15',
                'level': 'CRITICAL',
                'message': '<script>alert("XSS")</script>'
            },
            {
                'threat_type': 'Brute Force',
                'score': 6.0,
                'ip': '192.168.1.100',
                'timestamp': '10:30:45',
                'level': 'MEDIUM',
                'message': 'Failed login attempt #45'
            }
        ]
        return sample_threats
    
    def parse_log_entry(self, line: str) -> Dict:
        """Parse a single log entry and extract threat information"""
        try:
            if line.startswith('['):
                timestamp_end = line.find(']')
                if timestamp_end != -1:
                    timestamp_str = line[1:timestamp_end]
                    rest_of_log = line[timestamp_end + 1:].strip()
                    
                    level_match = re.search(r'(INFO|WARNING|ERROR)', rest_of_log)
                    level = level_match.group(1) if level_match else 'INFO'
                    
                    json_start = rest_of_log.find('{')
                    if json_start != -1:
                        json_str = rest_of_log[json_start:]
                        try:
                            json_data = json.loads(json_str)
                            return {
                                'timestamp': timestamp_str,
                                'level': level,
                                'message': json_data.get('details', ''),
                                'ip': json_data.get('ip', ''),
                                'path': json_data.get('path', ''),
                                'raw': line
                            }
                        except json.JSONDecodeError:
                            pass
            
            parts = line.split(' - ', 2)
            if len(parts) >= 3:
                timestamp = parts[0]
                level = parts[1]
                message = parts[2]
                
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
                ip = ip_match.group(1) if ip_match else ''
                
                return {
                    'timestamp': timestamp,
                    'level': level,
                    'message': message,
                    'ip': ip,
                    'path': '',
                    'raw': line
                }
        except Exception:
            pass
        
        return None
    
    def analyze_threat(self, log_entry: Dict) -> Dict:
        """Analyze a log entry for threats"""
        if not log_entry:
            return None
            
        message = log_entry.get('message', '')
        
        for threat_type, config in self.threat_patterns.items():
            if re.search(config['pattern'], message, re.IGNORECASE):
                score = config['score_base']
                
                if log_entry.get('level') == 'ERROR':
                    score += 0.5
                elif log_entry.get('level') == 'WARNING':
                    score += 0.2
                
                score = min(score, 10.0)
                
                return {
                    'threat_type': threat_type,
                    'score': score,
                    'timestamp': log_entry.get('timestamp', ''),
                    'ip': log_entry.get('ip', ''),
                    'message': message,
                    'level': log_entry.get('level', ''),
                    'path': log_entry.get('path', ''),
                    'threat_level': config['level']
                }
        
        return None

def load_recent_threats(log_file: str = None, max_entries: int = None) -> List[Dict]:
    """Load recent threats from log file"""
    logging_config = get_logging_config()
    if log_file is None:
        log_file = logging_config["log_file"]
    if max_entries is None:
        max_entries = logging_config["max_log_entries"]
    
    detector = ThreatDetector()
    threats = []
    
    try:
        if os.path.exists(log_file):
            encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
            lines = []
            
            for encoding in encodings:
                try:
                    with open(log_file, 'r', encoding=encoding, errors='ignore') as f:
                        lines = f.readlines()
                    break
                except UnicodeDecodeError:
                    continue
            
            if lines:
                recent_lines = lines[-max_entries:]
                
                for line in recent_lines:
                    line = line.strip()
                    if line:
                        log_entry = detector.parse_log_entry(line)
                        threat = detector.analyze_threat(log_entry)
                        if threat:
                            threats.append(threat)
    except Exception as e:
        print(f"Error reading log file: {e}")
    
    return threats

def load_recent_rag_queries(limit: int = 10) -> List[Dict]:
    """Load recent RAG queries"""
    sample_queries = [
        {
            "timestamp": "10:34:00",
            "query": "How to stop SQL injection attacks?",
            "query_type": "threat_response",
            "response": {
                "confidence": 0.88,
                "mitre_techniques": ["T1190"],
                "documents_retrieved": 4
            }
        },
        {
            "timestamp": "10:32:00",
            "query": "XSS response procedures",
            "query_type": "incident_response",
            "response": {
                "confidence": 0.92,
                "mitre_techniques": ["T1059"],
                "documents_retrieved": 5
            }
        },
        {
            "timestamp": "10:30:00",
            "query": "MITRE ATT&CK T1110 techniques",
            "query_type": "mitre_lookup",
            "response": {
                "confidence": 0.95,
                "mitre_techniques": ["T1110"],
                "documents_retrieved": 3
            }
        }
    ]
    
    try:
        if RAG_LOGGER_AVAILABLE:
            queries = rag_logger.get_recent_queries(limit)
            if queries:
                return queries
    except Exception:
        pass
    
    return sample_queries

def generate_recommendations(threats: List[Dict], rag_queries: List[Dict]) -> List[Dict]:
    """Generate smart recommendations"""
    recommendations = []
    
    # Generate recommendations based on threats
    for threat in threats:
        if threat['threat_type'] == 'SQL Injection':
            recommendations.append({
                'title': 'SQL Injection Response',
                'priority': 'CRITICAL',
                'actions': [
                    f"Block IP {threat['ip']}",
                    'Check database logs',
                    'Review SQL queries',
                    'Update WAF rules'
                ],
                'mitre_techniques': ['T1190'],
                'time_estimate': '30-60 min'
            })
        
        elif threat['threat_type'] == 'XSS Attack':
            recommendations.append({
                'title': 'XSS Response',
                'priority': 'CRITICAL',
                'actions': [
                    'Enable CSP headers',
                    'Sanitize inputs',
                    'Review web pages',
                    'Update security policies'
                ],
                'mitre_techniques': ['T1059'],
                'time_estimate': '20-40 min'
            })
        
        elif threat['threat_type'] == 'Brute Force':
            recommendations.append({
                'title': 'Brute Force Prevention',
                'priority': 'MEDIUM',
                'actions': [
                    'Enable account lockout',
                    'Implement rate limiting',
                    'Review auth logs',
                    'Consider MFA'
                ],
                'mitre_techniques': ['T1110'],
                'time_estimate': '15-30 min'
            })
    
    # Add general recommendations if no specific threats
    if not recommendations:
        recommendations.append({
            'title': 'System Health Check',
            'priority': 'LOW',
            'actions': [
                'Review security logs',
                'Update signatures',
                'Test incident response',
                'Security training'
            ],
            'mitre_techniques': [],
            'time_estimate': '30+ min'
        })
    
    return recommendations

def render_threat_panel():
    """Render the threat detection panel using Streamlit native components"""
    # Load REAL threats from app.log, not sample data
    threats = load_recent_threats()
    
    # If no real threats, show sample data
    if not threats:
        detector = ThreatDetector()
        threats = detector.generate_sample_threats()
    
    # Create unified panel using Streamlit's container with custom CSS
    with st.container():
        # Panel header
        st.markdown('<div class="unified-panel threat-panel">', unsafe_allow_html=True)
        st.markdown("""
        <div style="
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            color: white;
            padding: 1rem;
            border-radius: 8px 8px 0 0;
            margin: 0;
            text-align: center;
            font-weight: bold;
            font-size: 1.1rem;
        ">
            🔴 THREATS DETECTED
        </div>
        """, unsafe_allow_html=True)
        
        # Content area
        for threat in threats:
            level_colors = {
                'critical': '#e74c3c',
                'high': '#f39c12', 
                'medium': '#f1c40f'
            }
            color = level_colors.get(threat['level'].lower(), '#95a5a6')
            
            st.markdown(f"""
            <div style="
                background: white;
                border-left: 4px solid {color};
                padding: 1rem;
                margin: 0;
                border-bottom: 1px solid #ecf0f1;
            ">
                <h4 style="margin: 0 0 0.5rem 0; color: #2c3e50;">{threat['threat_type']}</h4>
                <p style="margin: 0.2rem 0; color: #5a6c7d; font-size: 0.9rem;">
                    <strong>Score:</strong> {threat['score']}/10 | 
                    <strong>IP:</strong> {threat['ip']} | 
                    <strong>Time:</strong> {threat['timestamp']}
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

def render_rag_panel():
    """Render the RAG intelligence panel using Streamlit native components"""
    queries = load_recent_rag_queries()
    
    # Create unified panel using Streamlit's container with custom CSS
    with st.container():
        # Panel header
        st.markdown('<div class="unified-panel rag-panel">', unsafe_allow_html=True)
        st.markdown("""
        <div style="
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
            color: white;
            padding: 1rem;
            border-radius: 8px 8px 0 0;
            margin: 0;
            text-align: center;
            font-weight: bold;
            font-size: 1.1rem;
        ">
            🧠 RAG BRAIN THINKING
        </div>
        """, unsafe_allow_html=True)
        
        # Content area
        for query in queries:
            response = query.get('response', {})
            confidence = response.get('confidence', 0)
            docs_found = response.get('documents_retrieved', 0)
            
            mitre_badges = ""
            for technique in response.get('mitre_techniques', []):
                mitre_badges += f'<span style="background: #3498db; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; margin-right: 0.3rem;">{technique}</span>'
            
            st.markdown(f"""
            <div style="
                background: white;
                border-left: 4px solid #3498db;
                padding: 1rem;
                margin: 0;
                border-bottom: 1px solid #ecf0f1;
            ">
                <h4 style="margin: 0 0 0.5rem 0; color: #2c3e50;">Query: "{query['query'][:30]}..."</h4>
                <p style="margin: 0.2rem 0; color: #5a6c7d; font-size: 0.9rem;">
                    <strong>Found:</strong> {docs_found} docs | 
                    <strong>Confidence:</strong> {confidence:.0%}
                </p>
                <p style="margin: 0.5rem 0 0 0;">
                    <strong>MITRE:</strong> {mitre_badges if mitre_badges else 'None'}
                </p>
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

def render_recommendations_panel():
    """Render the recommendations panel using Streamlit native components"""
    # Load REAL threats from app.log
    threats = load_recent_threats()
    
    # If no real threats, show sample data
    if not threats:
        detector = ThreatDetector()
        threats = detector.generate_sample_threats()
    
    queries = load_recent_rag_queries()
    recommendations = generate_recommendations(threats, queries)
    
    # Create unified panel using Streamlit's container with custom CSS
    with st.container():
        # Panel header
        st.markdown('<div class="unified-panel recommendations-panel">', unsafe_allow_html=True)
        st.markdown("""
        <div style="
            background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%);
            color: white;
            padding: 1rem;
            border-radius: 8px 8px 0 0;
            margin: 0;
            text-align: center;
            font-weight: bold;
            font-size: 1.1rem;
        ">
            📋 RECOMMENDATIONS GENERATED
        </div>
        """, unsafe_allow_html=True)
        
        # Content area
        for i, rec in enumerate(recommendations[:3], 1):
            priority_colors = {
                'critical': '#e74c3c',
                'high': '#f39c12',
                'medium': '#f1c40f',
                'low': '#95a5a6'
            }
            color = priority_colors.get(rec['priority'].lower(), '#95a5a6')
            
            actions_html = "<ul style='margin: 0.5rem 0; padding-left: 1.2rem;'>"
            for action in rec['actions']:
                actions_html += f"<li style='margin: 0.2rem 0; color: #5a6c7d;'>{action}</li>"
            actions_html += "</ul>"
            
            mitre_badges = ""
            for technique in rec.get('mitre_techniques', []):
                mitre_badges += f'<span style="background: #2ecc71; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; margin-right: 0.3rem;">{technique}</span>'
            
            st.markdown(f"""
            <div style="
                background: white;
                border-left: 4px solid {color};
                padding: 1rem;
                margin: 0;
                border-bottom: 1px solid #ecf0f1;
            ">
                <h4 style="margin: 0 0 0.5rem 0; color: #2c3e50;">{i}. {rec['title']}</h4>
                {actions_html}
                <p style="margin: 0.2rem 0; color: #5a6c7d; font-size: 0.9rem;">
                    <strong>Est. Time:</strong> {rec['time_estimate']}
                </p>
                {f"<p style='margin: 0.5rem 0 0 0;'><strong>MITRE:</strong> {mitre_badges}</p>" if mitre_badges else ""}
            </div>
            """, unsafe_allow_html=True)
        
        st.markdown('</div>', unsafe_allow_html=True)

def main():
    """Main dashboard function"""
    # Dashboard header
    st.markdown("""
    <div class="dashboard-header">
        <h1>🛡️ CyDefender Dashboard</h1>
    </div>
    """, unsafe_allow_html=True)
    
    # Three column layout
    col1, col2, col3 = st.columns([1, 1, 1], gap="small")
    
    with col1:
        render_threat_panel()
    
    with col2:
        render_rag_panel()
    
    with col3:
        render_recommendations_panel()
    
    # Auto-refresh using config
    dashboard_config = get_dashboard_config()
    if 'last_refresh' not in st.session_state:
        st.session_state.last_refresh = time.time()
    
    if time.time() - st.session_state.last_refresh > dashboard_config["auto_refresh_seconds"]:
        st.session_state.last_refresh = time.time()
        st.rerun()

if __name__ == "__main__":
    main()