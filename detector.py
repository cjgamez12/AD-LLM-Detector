import anthropic
import json
import sys

input_file = sys.argv[1] if len(sys.argv) > 1 else "roast_4769.json"

with open(input_file) as f:
    data = json.load(f)

event = data[0] if isinstance(data, list) else data

event_id = event.get("EventId")
enc = event.get("TicketEncryptionType")
logon_type = event.get("LogonType")
auth_pkg = event.get("AuthPackage")

# --- DETECTION LOGIC (code decides, not the LLM) ---
if event_id == 4769 and enc == "0x17":
    attack = "Kerberoasting"
    mitre = "T1558.003"
elif event_id == 4768 and enc == "0x17":
    attack = "AS-REP Roasting"
    mitre = "T1558.004"
elif event_id == 4624 and logon_type == "3" and auth_pkg == "NTLM":
    attack = "Pass-the-Hash"
    mitre = "T1550.002"
else:
    attack = "Unknown / Benign"
    mitre = "N/A"

log_data = f"""
Event ID: {event.get('EventId')}
Account Name: {event.get('AccountName')}
Service Name: {event.get('ServiceName')}
Ticket Encryption Type: {event.get('TicketEncryptionType')}
Logon Type: {event.get('LogonType')}
Authentication Package: {event.get('AuthPackage')}
Client Address: {event.get('ClientAddress')}
"""

client = anthropic.Anthropic()

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[
        {
            "role": "user",
            "content": f"""You are a cybersecurity analyst. My detection pipeline has already classified this event as a **{attack}** attack (MITRE {mitre}) based on the event fields. Write an incident report for this specific attack that includes:
1. Confirmation and explanation of the {attack} technique
2. The MITRE ATT&CK technique ID and name ({mitre})
3. Severity level (Low/Medium/High/Critical) with rationale
4. What the attacker is trying to do
5. Recommended response actions

Log data:
{log_data}

Provide a clear incident report."""
        }
    ]
)

print(f"=== INCIDENT REPORT: {attack} ({mitre}) ===")
print(message.content[0].text)
