#!/usr/bin/env python3
"""
Test the complete CyDefender flow with enhanced RAG system
Shows how log files → defense agent → RAG → security recommendations
"""

import os
import sys
from pathlib import Path
from agents.defense_agent import create_defensive_agent
from langchain_core.messages import HumanMessage

def test_complete_flow():
    """Test the complete flow from logs to security recommendations"""
    
    print("=" * 60)
    print("TESTING COMPLETE CYDEFENDER FLOW")
    print("=" * 60)
    
    # Step 1: Create sample attack logs (simulating what offense_agent creates)
    sample_logs = """
2024-01-15 10:30:45 - INFO - 192.168.1.100 - GET /api/v1/profile - 200
2024-01-15 10:31:12 - INFO - 192.168.1.100 - POST /api/v1/login - 200
2024-01-15 10:32:01 - WARN - 192.168.1.100 - GET /api/v1/admin' OR 1=1-- - 500
2024-01-15 10:32:05 - ERROR - 192.168.1.100 - GET /api/v1/admin' UNION SELECT * FROM users-- - 500
2024-01-15 10:32:10 - ERROR - 192.168.1.100 - GET /api/v1/admin'; DROP TABLE users;-- - 500
2024-01-15 10:32:15 - INFO - 192.168.1.100 - GET /api/v1/profile - 200
2024-01-15 10:33:01 - WARN - 192.168.1.100 - POST /api/v1/user-info - 200
2024-01-15 10:33:05 - ERROR - 192.168.1.100 - GET /api/v1/admin/<script>alert('XSS')</script> - 500
2024-01-15 10:33:10 - ERROR - 192.168.1.100 - GET /api/v1/admin/../../etc/passwd - 404
"""
    
    print("\\n1. SAMPLE ATTACK LOGS (Input):")
    print("-" * 40)
    print(sample_logs)
    
    # Step 2: Create defense agent
    print("\\n2. INITIALIZING DEFENSE AGENT...")
    print("-" * 40)
    try:
        agent = create_defensive_agent()
        print("✓ Defense agent created successfully")
        print("✓ Enhanced RAG system loaded")
        
        # Step 3: Analyze logs with defense agent
        print("\\n3. DEFENSE AGENT ANALYZING LOGS...")
        print("-" * 40)
        
        analysis_message = f"""
        Analyze these application logs for security attacks and provide defensive recommendations:
        
        {sample_logs}
        
        Follow these steps:
        1. Use analyze_logs to identify attack patterns
        2. Use identify_security_controls to find relevant security measures
        3. Use generate_recommendations to create specific implementation plans
        """
        
        print("Sending logs to defense agent for analysis...")
        
        # Run the agent
        result = agent.invoke({"messages": [HumanMessage(content=analysis_message)]})
        
        print("\\n4. DEFENSE AGENT RESPONSE:")
        print("-" * 40)
        print(result["messages"][-1].content)
        
    except Exception as e:
        print(f"Error running defense agent: {e}")
        import traceback
        traceback.print_exc()
        
        # Fallback: Show how RAG would respond directly
        print("\\n\\nFALLBACK: Direct RAG System Test")
        print("-" * 40)
        test_rag_direct_queries()

def test_rag_direct_queries():
    """Test RAG system directly with security queries"""
    from rag_setup import SecurityKnowledgeBase
    
    kb = SecurityKnowledgeBase()
    
    # Queries that would come from log analysis
    security_queries = [
        "SQL injection attack response procedures",
        "XSS attack mitigation strategies", 
        "directory traversal attack prevention",
        "web application firewall configuration",
        "incident response for web attacks"
    ]
    
    print("\\nTesting RAG responses to security queries:")
    print("=" * 50)
    
    for i, query in enumerate(security_queries, 1):
        print(f"\\n{i}. Query: {query}")
        print("-" * 30)
        
        results = kb.query_knowledge_base(query, n_results=1)
        if results:
            result = results[0]
            print(f"Document Type: {result['doc_type']}")
            print(f"Source: {result['metadata']['title']}")
            print(f"Response: {result['content'][:200]}...")
            print(f"MITRE Techniques: {result['mitre_techniques']}")
        else:
            print("No results found")

def show_flow_diagram():
    """Show the complete flow diagram"""
    print("\\n" + "=" * 60)
    print("CYDEFENDER FLOW DIAGRAM")
    print("=" * 60)
    
    flow_diagram = """
    
    1. TEST LAB (test_lab.py)
       |
    [Creates vulnerable JavaScript app]
       |
    [Logs requests to app_logs/app.log]
    
    2. OFFENSE AGENT (offense_agent.py)
       |
    [Analyzes JavaScript for vulnerabilities]
       |
    [Attacks endpoints (SQLi, XSS, etc.)]
       |
    [Creates MORE attack logs]
    
    3. DEFENSE AGENT (defense_agent.py)
       |
    [Reads app_logs/app.log]
       |
    [Calls analyze_logs() tool]
       |
    [Identifies: SQL injection, XSS, etc.]
       |
    [Queries Enhanced RAG System]
    
    4. ENHANCED RAG SYSTEM (rag_setup.py)
       |
    [OLD: "Here's how to code securely..."]
    [NEW: "Immediate Response Actions:
           1. Block malicious IPs
           2. Disable affected endpoints  
           3. Check database integrity..."]
       |
    [Returns actionable security recommendations]
    
    5. DEFENSE AGENT RESPONSE
       |
    [Provides specific incident response steps]
    [Includes MITRE ATT&CK mappings]
    [Gives threat intelligence context]
    
    """
    
    print(flow_diagram)

def test_log_based_recommendations():
    """Show how different log patterns trigger different RAG responses"""
    print("\\n" + "=" * 60)
    print("LOG PATTERN -> RAG RECOMMENDATION MAPPING")
    print("=" * 60)
    
    from rag_setup import SecurityKnowledgeBase
    kb = SecurityKnowledgeBase()
    
    log_patterns = [
        {
            "attack": "SQL Injection",
            "log_pattern": "GET /api/admin' OR 1=1--",
            "query": "SQL injection attack response"
        },
        {
            "attack": "XSS Attack", 
            "log_pattern": "GET /api/admin/<script>alert('XSS')</script>",
            "query": "XSS attack mitigation"
        },
        {
            "attack": "Directory Traversal",
            "log_pattern": "GET /api/admin/../../etc/passwd",
            "query": "directory traversal attack prevention"
        },
        {
            "attack": "Malware Detection",
            "log_pattern": "Suspicious process: powershell.exe -enc [base64]",
            "query": "malware incident response"
        }
    ]
    
    for pattern in log_patterns:
        print(f"\\n{pattern['attack']}:")
        print(f"Log Pattern: {pattern['log_pattern']}")
        print("-" * 40)
        
        results = kb.query_knowledge_base(pattern['query'], n_results=1)
        if results:
            result = results[0]
            print(f"RAG Response Type: {result['doc_type']}")
            print(f"Recommendation: {result['content'][:150]}...")
        print()

if __name__ == "__main__":
    print("CYDEFENDER ENHANCED RAG SYSTEM TEST")
    print("Testing complete flow from logs to recommendations")
    
    # Show the flow diagram first
    show_flow_diagram()
    
    # Test log-based recommendations
    test_log_based_recommendations()
    
    # Test complete flow
    test_complete_flow()
    
    print("\\n" + "=" * 60)
    print("SUMMARY: Enhanced RAG System Benefits")
    print("=" * 60)
    print("INPUT: Application log files (app_logs/app.log)")
    print("PROCESS: Defense agent analyzes logs → queries RAG")
    print("OUTPUT: Actionable security recommendations")
    print("\\nOLD: Development security guides")
    print("NEW: Operational incident response procedures")
    print("=" * 60)