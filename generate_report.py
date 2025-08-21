#!/usr/bin/env python3
"""
CyDefender Report Generator
Standalone script to generate security reports
"""

import os
import argparse
from reports.report_manager import report_manager

def main():
    parser = argparse.ArgumentParser(description='Generate CyDefender Security Reports')
    parser.add_argument('--format', choices=['html', 'json', 'all'], default='all',
                       help='Report format to generate (default: all)')
    parser.add_argument('--output-dir', default='reports',
                       help='Output directory for reports (default: reports)')
    parser.add_argument('--filename', 
                       help='Custom filename prefix (default: security_report_timestamp)')
    
    args = parser.parse_args()
    
    print("🛡️ CyDefender Report Generator")
    print("=" * 50)
    
    # Check if we have any data to report
    if not report_manager.vulnerabilities and not report_manager.defense_actions:
        print("⚠️ No security data found. Run the offense_agent and/or defense_agent first.")
        return
    
    print(f"📊 Found {len(report_manager.vulnerabilities)} vulnerabilities")
    print(f"🛡️ Found {len(report_manager.defense_actions)} defense actions")
    print(f"📅 Found {len(report_manager.security_events)} security events")
    print()
    
    try:
        if args.format == 'all':
            reports = report_manager.generate_all_reports()
            print("📄 Generated Reports:")
            for report_type, filepath in reports.items():
                print(f"  ✅ {report_type.upper()}: {filepath}")
        
        elif args.format == 'html':
            filename = args.filename + '.html' if args.filename else None
            filepath = report_manager.generate_html_report(filename)
            print(f"📄 Generated HTML Report: {filepath}")
        
        elif args.format == 'json':
            filename = args.filename + '.json' if args.filename else None
            filepath = report_manager.generate_json_report(filename)
            print(f"📄 Generated JSON Report: {filepath}")
        
        print("\n✅ Report generation complete!")
        
    except Exception as e:
        print(f"❌ Error generating reports: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())