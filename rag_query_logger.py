import json
import time
from datetime import datetime
from typing import Dict, List, Any
import os
from pathlib import Path

class RAGQueryLogger:
    def __init__(self, log_file: str = "app_logs/rag_queries.json"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(exist_ok=True)
        
        # Initialize log file if it doesn't exist
        if not self.log_file.exists():
            with open(self.log_file, 'w') as f:
                json.dump([], f)
    
    def log_query(self, query: str, query_type: str = "general", context: Dict = None):
        """Log a RAG query with timestamp and metadata"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "query_type": query_type,
            "context": context or {},
            "id": f"q_{int(time.time() * 1000)}"
        }
        
        # Read existing logs
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
        except:
            logs = []
        
        # Add new log entry
        logs.append(log_entry)
        
        # Keep only last 100 entries
        logs = logs[-100:]
        
        # Write back to file
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        return log_entry["id"]
    
    def log_response(self, query_id: str, results: List[Dict], confidence: float, mitre_techniques: List[str]):
        """Log the response for a query"""
        response_entry = {
            "timestamp": datetime.now().isoformat(),
            "query_id": query_id,
            "results_count": len(results),
            "confidence": confidence,
            "mitre_techniques": mitre_techniques,
            "documents_retrieved": [
                {
                    "title": r.get("metadata", {}).get("title", "Unknown"),
                    "doc_type": r.get("doc_type", "unknown"),
                    "relevance_score": r.get("relevance_score", 0.0),
                    "category": r.get("metadata", {}).get("category", "unknown")
                }
                for r in results
            ]
        }
        
        # Read existing logs
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
        except:
            logs = []
        
        # Find and update the query entry
        for log in logs:
            if log.get("id") == query_id:
                log["response"] = response_entry
                break
        
        # Write back to file
        with open(self.log_file, 'w') as f:
            json.dump(logs, f, indent=2)
    
    def get_recent_queries(self, limit: int = 20) -> List[Dict]:
        """Get recent RAG queries"""
        try:
            with open(self.log_file, 'r') as f:
                logs = json.load(f)
            return logs[-limit:]
        except:
            return []

# Global logger instance
rag_logger = RAGQueryLogger()

def simulate_rag_queries():
    """Simulate RAG queries for demo purposes"""
    sample_queries = [
        {
            "query": "SQL injection response procedures",
            "query_type": "incident_response",
            "context": {"threat_detected": "SQL Injection", "severity": "high"}
        },
        {
            "query": "MITRE ATT&CK T1059 command line execution",
            "query_type": "mitre_lookup",
            "context": {"technique": "T1059", "tactic": "execution"}
        },
        {
            "query": "web application attack patterns",
            "query_type": "threat_intelligence",
            "context": {"attack_type": "web_application", "pattern": "injection"}
        },
        {
            "query": "malware incident response playbook",
            "query_type": "incident_response",
            "context": {"incident_type": "malware", "priority": "critical"}
        },
        {
            "query": "PowerShell execution detection methods",
            "query_type": "detection",
            "context": {"tool": "PowerShell", "detection_type": "execution"}
        }
    ]
    
    import random
    
    # Add some sample queries with responses
    for sample in sample_queries:
        query_id = rag_logger.log_query(
            sample["query"],
            sample["query_type"],
            sample["context"]
        )
        
        # Simulate response
        sample_results = [
            {
                "metadata": {
                    "title": f"Security_Doc_{random.randint(1,10)}",
                    "category": sample["query_type"]
                },
                "doc_type": sample["query_type"],
                "relevance_score": random.uniform(0.7, 0.95),
                "mitre_techniques": [f"T{random.randint(1000,1999)}"]
            }
            for _ in range(random.randint(2,5))
        ]
        
        rag_logger.log_response(
            query_id,
            sample_results,
            random.uniform(0.8, 0.95),
            [f"T{random.randint(1000,1999)}" for _ in range(random.randint(1,3))]
        )
    
    print("Sample RAG queries created for demo")

if __name__ == "__main__":
    simulate_rag_queries()