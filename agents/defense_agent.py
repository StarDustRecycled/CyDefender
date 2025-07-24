from typing import List, Dict, Any
from langchain_core.messages import HumanMessage
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent
from tools.defense_tools import analyze_logs, identify_security_controls, generate_recommendations
from tools.common import log_progress
from config import get_model_config, get_security_config
from reports.report_manager import report_manager

def create_defensive_agent():
    """Creates and returns a ReAct agent for defensive security analysis"""
    tools = [
        analyze_logs,
        identify_security_controls,
        generate_recommendations
    ]
    
    # Load configuration
    model_config = get_model_config()
    security_config = get_security_config()
    
    llm = ChatAnthropic(
        temperature=model_config["temperature"],
        model=model_config["name"],
        max_tokens=model_config["max_tokens"]
    )
    
    llm_with_system = llm.bind(
        system_message="""You are a defensive security agent. Follow these steps PRECISELY:

1. First analyze the logs using analyze_logs to identify attacks
2. For each identified attack:
   a) Use identify_security_controls to find relevant security measures
   b) Use generate_recommendations to create specific implementation plans
   
Remember to focus on actionable defensive measures!"""
    )
    
    return create_react_agent(
        tools=tools,
        model=llm_with_system
    )

def main(log_content: str):
    print("\n🛡️ Starting Defensive Security Analysis 🛡️")
    print("=" * 50)
    
    # Load configuration
    security_config = get_security_config()
    
    agent = create_defensive_agent()
    
    initial_message = HumanMessage(
        content=f"""Analyze these application logs for security threats and recommend defenses:
        
        {log_content}"""
    )
    
    try:
        result = agent.invoke({
            "messages": [initial_message],
            "config": {
                "recursion_limit": security_config["recursion_limit"],
                "max_iterations": security_config["max_agent_iterations"]
            }
        })
        
        # Extract recommendations
        recommendations = []
        for msg in result["messages"]:
            if (hasattr(msg, 'content') and msg.content and 
                isinstance(msg.content, str) and
                ("recommendation" in msg.content.lower() or 
                 "security control" in msg.content.lower())):
                recommendations.append(msg.content)
        
        if recommendations:
            print("\n📝 Security Recommendations:")
            for rec in recommendations:
                print("-" * 50)
                print(rec)
                print()
        
        print("\n" + "=" * 50)
        print("🏁 Defense Analysis Complete!")
        print("=" * 50)
        
        # Always generate reports after defense analysis
        try:
            reports = report_manager.generate_all_reports()
            print("\n📊 Final Security Reports Generated:")
            for report_type, filepath in reports.items():
                print(f"  📄 {report_type.upper()}: {filepath}")
            
            # Show final summary
            print(f"\n📋 Report Summary:")
            print(f"  🔍 Vulnerabilities: {len(report_manager.vulnerabilities)}")
            print(f"  🛡️ Defense Actions: {len(report_manager.defense_actions)}")
            print(f"  📅 Security Events: {len(report_manager.security_events)}")
            
            # Reset for next run
            report_manager.clear_data()
            print(f"\n🔄 Session cleared for next run")
            
        except Exception as e:
            print(f"⚠️ Warning: Could not generate reports: {e}")
        
        return {
            "status": "success",
            "messages": result["messages"],
            "recommendations": recommendations
        }
        
    except Exception as e:
        print(f"\n❌ Error during analysis: {str(e)}")
        return {
            "status": "error",
            "error": str(e),
            "messages": []
        }

if __name__ == "__main__":
    # Read logs from the test lab
    with open("app_logs/app.log", "r") as f:  # Updated path to account for new location
        security_logs = f.read()
        
    # Run defensive analysis
    result = main(security_logs) 