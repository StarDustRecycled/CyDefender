"""
Security Report Manager
Handles collection and generation of security reports for CyDefender
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import html


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability"""
    endpoint: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: List[str]
    recommendations: List[str]
    discovered_at: str
    mitre_techniques: List[str] = None


@dataclass
class DefenseAction:
    """Represents a defensive action taken"""
    action_type: str
    description: str
    target: str
    effectiveness: str
    implemented_at: str
    mitre_techniques: List[str] = None


@dataclass
class SecurityEvent:
    """Represents a security event in the timeline"""
    timestamp: str
    event_type: str  # 'attack', 'defense', 'detection'
    description: str
    severity: str
    source: str  # 'hack_agent', 'defense_agent', 'log_analysis'


class SecurityReportManager:
    """
    Central manager for collecting security data and generating reports
    """
    
    def __init__(self, reports_dir: str = "reports"):
        self.reports_dir = reports_dir
        self.session_file = os.path.join(reports_dir, "current_session.json")
        
        # Ensure reports directory exists
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Try to load existing session data
        if os.path.exists(self.session_file):
            self._load_session()
        else:
            # Initialize fresh session
            self.vulnerabilities: List[Vulnerability] = []
            self.defense_actions: List[DefenseAction] = []
            self.security_events: List[SecurityEvent] = []
            self.session_start = datetime.now().isoformat()
    
    def add_vulnerability(self, vuln_data: Dict[str, Any]) -> None:
        """Add a discovered vulnerability"""
        vuln = Vulnerability(
            endpoint=vuln_data.get('endpoint', 'Unknown'),
            vulnerability_type=vuln_data.get('vulnerability', 'Unknown'),
            severity=vuln_data.get('severity', 'Medium'),
            description=vuln_data.get('description', ''),
            evidence=vuln_data.get('evidence', []),
            recommendations=vuln_data.get('recommendations', []),
            discovered_at=datetime.now().isoformat(),
            mitre_techniques=vuln_data.get('mitre_techniques', [])
        )
        self.vulnerabilities.append(vuln)
        
        # Add to timeline
        self.add_security_event(
            event_type="attack",
            description=f"Vulnerability discovered: {vuln.vulnerability_type} in {vuln.endpoint}",
            severity=vuln.severity,
            source="hack_agent"
        )
        
        # Auto-save session
        self._save_session()
    
    def add_defense_action(self, defense_data: Dict[str, Any]) -> None:
        """Add a defensive action"""
        defense = DefenseAction(
            action_type=defense_data.get('action_type', 'Unknown'),
            description=defense_data.get('description', ''),
            target=defense_data.get('target', ''),
            effectiveness=defense_data.get('effectiveness', 'Unknown'),
            implemented_at=datetime.now().isoformat(),
            mitre_techniques=defense_data.get('mitre_techniques', [])
        )
        self.defense_actions.append(defense)
        
        # Add to timeline
        self.add_security_event(
            event_type="defense",
            description=f"Defense implemented: {defense.description}",
            severity="Info",
            source="defense_agent"
        )
        
        # Auto-save session
        self._save_session()
    
    def add_security_event(self, event_type: str, description: str, 
                          severity: str, source: str) -> None:
        """Add a security event to the timeline"""
        event = SecurityEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            description=description,
            severity=severity,
            source=source
        )
        self.security_events.append(event)
        
        # Auto-save session (but avoid recursive saves from add_security_event calls)
        if not hasattr(self, '_saving'):
            self._saving = True
            self._save_session()
            del self._saving
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for the report"""
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "total_defenses": len(self.defense_actions),
            "severity_breakdown": severity_counts,
            "session_duration": (datetime.now() - datetime.fromisoformat(self.session_start)).total_seconds(),
            "unique_endpoints_tested": len(set(v.endpoint for v in self.vulnerabilities if v.endpoint != 'Unknown'))
        }
    
    def generate_json_report(self, filename: Optional[str] = None) -> str:
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "session_start": self.session_start,
            "summary": self.get_summary_stats(),
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "defense_actions": [asdict(d) for d in self.defense_actions],
            "timeline": [asdict(e) for e in sorted(self.security_events, 
                                                 key=lambda x: x.timestamp)]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return filepath
    
    def generate_html_report(self, filename: Optional[str] = None) -> str:
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"
        
        filepath = os.path.join(self.reports_dir, filename)
        
        stats = self.get_summary_stats()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyDefender Security Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 2.5em; }}
        .header .subtitle {{ opacity: 0.9; margin-top: 10px; }}
        .content {{ padding: 30px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .stat-label {{ color: #666; margin-top: 5px; }}
        .section {{ margin-bottom: 40px; }}
        .section h2 {{ color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .vuln-card {{ background: #fff; border-left: 4px solid #e74c3c; padding: 20px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .vuln-card.critical {{ border-left-color: #c0392b; }}
        .vuln-card.high {{ border-left-color: #e74c3c; }}
        .vuln-card.medium {{ border-left-color: #f39c12; }}
        .vuln-card.low {{ border-left-color: #27ae60; }}
        .defense-card {{ background: #fff; border-left: 4px solid #27ae60; padding: 20px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .severity {{ display: inline-block; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; }}
        .severity.critical {{ background: #c0392b; color: white; }}
        .severity.high {{ background: #e74c3c; color: white; }}
        .severity.medium {{ background: #f39c12; color: white; }}
        .severity.low {{ background: #27ae60; color: white; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        .recommendations {{ background: #e8f4fd; padding: 15px; border-radius: 5px; margin-top: 10px; }}
        .recommendations ul {{ margin: 0; }}
        .footer {{ text-align: center; padding: 20px; color: #666; border-top: 1px solid #eee; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CyDefender Security Report</h1>
            <div class="subtitle">Generated on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}</div>
        </div>
        
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{stats['total_vulnerabilities']}</div>
                    <div class="stat-label">Vulnerabilities Found</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['total_defenses']}</div>
                    <div class="stat-label">Defense Actions Recommended</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{stats['unique_endpoints_tested']}</div>
                    <div class="stat-label">Endpoints Tested</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.security_events)}</div>
                    <div class="stat-label">Security Events</div>
                </div>
            </div>
"""
        
        # Vulnerabilities section
        if self.vulnerabilities:
            html_content += """
            <div class="section">
                <h2>🔍 Vulnerabilities Discovered</h2>
"""
            for vuln in self.vulnerabilities:
                severity_class = vuln.severity.lower()
                html_content += f"""
                <div class="vuln-card {severity_class}">
                    <h3>{html.escape(vuln.vulnerability_type)} <span class="severity {severity_class}">{vuln.severity}</span></h3>
                    <p><strong>Endpoint:</strong> {html.escape(vuln.endpoint)}</p>
                    <p><strong>Description:</strong> {html.escape(vuln.description)}</p>
                    <div class="timestamp">Discovered: {datetime.fromisoformat(vuln.discovered_at).strftime('%Y-%m-%d %H:%M:%S')}</div>
                    
                    {f'<div class="recommendations"><h4>🛠️ Recommendations:</h4><ul>' + ''.join([f'<li>{html.escape(rec)}</li>' for rec in vuln.recommendations]) + '</ul></div>' if vuln.recommendations else ''}
                </div>
"""
            html_content += "            </div>\n"
        
        # Defense actions section
        if self.defense_actions:
            html_content += """
            <div class="section">
                <h2>🛡️ Defense Actions Recommended</h2>
"""
            for defense in self.defense_actions:
                html_content += f"""
                <div class="defense-card">
                    <h3>{html.escape(defense.action_type)}</h3>
                    <p><strong>Target:</strong> {html.escape(defense.target)}</p>
                    <p><strong>Description:</strong> {html.escape(defense.description)}</p>
                    <p><strong>Effectiveness:</strong> {html.escape(defense.effectiveness)}</p>
                    <div class="timestamp">Implemented: {datetime.fromisoformat(defense.implemented_at).strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
"""
            html_content += "            </div>\n"
        
        # Timeline section
        if self.security_events:
            html_content += """
            <div class="section">
                <h2>📅 Security Timeline</h2>
                <div style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; border-radius: 5px; padding: 15px;">
"""
            for event in sorted(self.security_events, key=lambda x: x.timestamp, reverse=True):
                event_icon = "🔴" if event.event_type == "attack" else "🛡️" if event.event_type == "defense" else "🔍"
                html_content += f"""
                    <div style="padding: 10px; border-bottom: 1px solid #eee; display: flex; align-items: center;">
                        <span style="margin-right: 10px; font-size: 1.2em;">{event_icon}</span>
                        <div style="flex: 1;">
                            <strong>{html.escape(event.description)}</strong>
                            <div class="timestamp">{datetime.fromisoformat(event.timestamp).strftime('%Y-%m-%d %H:%M:%S')} - {html.escape(event.source)}</div>
                        </div>
                        <span class="severity {event.severity.lower()}" style="margin-left: 10px;">{event.severity}</span>
                    </div>
"""
            html_content += """
                </div>
            </div>
"""
        
        html_content += f"""
        </div>
        
        <div class="footer">
            <p>Report generated by CyDefender Security Analysis System</p>
            <p>Session Duration: {stats['session_duration']:.0f} seconds</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filepath
    
    def generate_all_reports(self) -> Dict[str, str]:
        """Generate all report formats"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        reports = {
            'json': self.generate_json_report(f"security_report_{timestamp}.json"),
            'html': self.generate_html_report(f"security_report_{timestamp}.html")
        }
        
        return reports
    
    def _save_session(self) -> None:
        """Save current session data to file"""
        try:
            session_data = {
                "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
                "defense_actions": [asdict(d) for d in self.defense_actions],
                "security_events": [asdict(e) for e in self.security_events],
                "session_start": self.session_start
            }
            with open(self.session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save session data: {e}")
    
    def _load_session(self) -> None:
        """Load session data from file"""
        try:
            with open(self.session_file, 'r', encoding='utf-8') as f:
                session_data = json.load(f)
            
            # Reconstruct objects from saved data
            self.vulnerabilities = [
                Vulnerability(**v) for v in session_data.get("vulnerabilities", [])
            ]
            self.defense_actions = [
                DefenseAction(**d) for d in session_data.get("defense_actions", [])
            ]
            self.security_events = [
                SecurityEvent(**e) for e in session_data.get("security_events", [])
            ]
            self.session_start = session_data.get("session_start", datetime.now().isoformat())
            
        except Exception as e:
            print(f"Warning: Could not load session data: {e}")
            # Initialize fresh if loading fails
            self.vulnerabilities = []
            self.defense_actions = []
            self.security_events = []
            self.session_start = datetime.now().isoformat()
    
    def clear_data(self) -> None:
        """Clear all collected data and start fresh session"""
        self.vulnerabilities.clear()
        self.defense_actions.clear()
        self.security_events.clear()
        self.session_start = datetime.now().isoformat()
        
        # Remove session file
        if os.path.exists(self.session_file):
            os.remove(self.session_file)


# Global report manager instance
report_manager = SecurityReportManager()