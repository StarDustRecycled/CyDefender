#!/usr/bin/env python3
"""
Simple script to run the CyDefender dashboard
"""
import subprocess
import sys
import os

def run_dashboard():
    """Run the Streamlit dashboard"""
    try:
        # Change to dashboard directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        
        # Run the dashboard
        print("🛡️ Starting CyDefender Dashboard...")
        print("📊 Dashboard will be available at: http://localhost:8501")
        print("🔄 Auto-refresh enabled every 10 seconds")
        print("🚀 Press Ctrl+C to stop")
        
        # Run streamlit
        cmd = [
            sys.executable, "-m", "streamlit", "run", 
            "dashboard.py", 
            "--server.address", "localhost",
            "--server.port", "8501",
            "--server.headless", "true"
        ]
        
        subprocess.run(cmd, check=True)
        
    except KeyboardInterrupt:
        print("\n🛑 Dashboard stopped by user")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running dashboard: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    run_dashboard()