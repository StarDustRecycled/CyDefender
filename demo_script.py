#!/usr/bin/env python3
"""
CyDefender Demo Script
This script demonstrates the live threat detection and response capabilities
"""

import time
import json
import logging
from datetime import datetime
from pathlib import Path
import subprocess
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app_logs/app.log'),
        logging.StreamHandler()
    ]
)

def setup_demo_environment():
    """Setup demo environment with sample data"""
    print("🛡️  Setting up CyDefender Demo Environment...")
    
    # Create necessary directories
    Path("app_logs").mkdir(exist_ok=True)
    Path("security_docs").mkdir(exist_ok=True)
    
    # Generate sample threat logs
    sample_threats = [
        "ERROR - SQL Injection attempt detected from IP 192.168.1.100: SELECT * FROM users WHERE id = 1 OR 1=1",
        "WARNING - XSS attack detected: <script>alert('XSS')</script> in user input",
        "ERROR - Brute force attempt: Failed login attempt #15 from 10.0.0.50",
        "ERROR - Path traversal detected: ../../etc/passwd access attempt",
        "WARNING - DDoS attack detected: 1000+ requests/second from 203.0.113.0",
        "ERROR - Unauthorized access attempt with hardcoded key detected"
    ]
    
    # Write sample threats to log file
    with open("app_logs/app.log", "a") as f:
        for threat in sample_threats:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {threat}\n")
    
    print("✅ Demo environment setup complete!")

def simulate_rag_queries():
    """Simulate RAG queries for demo"""
    print("🤖 Simulating RAG Intelligence queries...")
    
    try:
        from rag_query_logger import simulate_rag_queries
        simulate_rag_queries()
        print("✅ RAG queries simulated successfully!")
    except ImportError:
        print("⚠️  RAG query logger not available")

def run_dashboard():
    """Launch the Streamlit dashboard"""
    print("🚀 Launching CyDefender Dashboard...")
    print("📊 Dashboard will be available at: http://localhost:8501")
    print("🔄 The dashboard will auto-refresh every 3 seconds")
    print("\n" + "="*50)
    print("DEMO FEATURES:")
    print("- Panel 1: Live threat detection from log files")
    print("- Panel 2: RAG intelligence engine with query monitoring")
    print("- Panel 3: Smart recommendations based on detected threats")
    print("="*50)
    
    try:
        # Run streamlit dashboard
        subprocess.run([sys.executable, "-m", "streamlit", "run", "dashboard.py", "--server.headless", "true"])
    except KeyboardInterrupt:
        print("\n👋 Demo stopped by user")
    except Exception as e:
        print(f"❌ Error running dashboard: {e}")

def generate_attack_simulation():
    """Generate simulated attack logs for demo"""
    print("⚡ Generating attack simulation...")
    
    attack_logs = [
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR - {'{'}'\"ip\": \"192.168.1.101\", \"path\": \"/admin\", \"details\": \"SQL injection: admin' OR '1'='1-- detected\"{'}'} ",
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] WARNING - {'{'}'\"ip\": \"10.0.0.75\", \"path\": \"/login\", \"details\": \"XSS attempt: <script>document.cookie</script>\"{'}'} ",
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR - {'{'}'\"ip\": \"203.0.113.5\", \"path\": \"/files\", \"details\": \"Path traversal: ../../../etc/passwd\"{'}'} "
    ]
    
    with open("app_logs/app.log", "a") as f:
        for log in attack_logs:
            f.write(log + "\n")
    
    print("✅ Attack simulation logs generated!")

def main():
    """Main demo function"""
    print("🛡️  CyDefender Live Demo")
    print("=" * 40)
    
    # Setup demo environment
    setup_demo_environment()
    
    # Simulate RAG queries
    simulate_rag_queries()
    
    # Generate attack simulation
    generate_attack_simulation()
    
    print("\n🎯 Demo is ready!")
    print("Choose an option:")
    print("1. Run dashboard (recommended)")
    print("2. Generate more attack logs")
    print("3. Exit")
    
    while True:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            run_dashboard()
            break
        elif choice == "2":
            generate_attack_simulation()
            print("More attack logs generated! Check Panel 1 for updates.")
        elif choice == "3":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()