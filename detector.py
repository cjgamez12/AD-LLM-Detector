import anthropic
import json
from datetime import datetime

#Sample Kerbrosating log data (we'll make this dynamic later)
log_data = """
Event ID: 4769
Time: {time}
Description: A Kerberos Service ticket was requested
Account Name: john.smith@CORP.LOCAL
Service Name: MSSQLSvc/dc01.corp.local:1433
Ticket Encryption Type: 0x17
Client Address: 192.168.64.x
""".format(time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

#send to Claude for analysis
client = anthropic.Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[
	{
	    "role": "user",
	    "content": f"""You are a cybersecurity analyst. Analyze This Window 
Security Event log and provide:
1. What attack technique this represents
2. The MITRE ATT&CK technique ID and name
3. Severity level (Low/Medium/High/Critical)
4. What the attacker is trying to do
5. Recomended response actions

Log data:
{log_data}

Provide a clear incident report."""
	}
    ]
)

print("===INCIDENT REPORT ===")
print(message.content[0].text)
