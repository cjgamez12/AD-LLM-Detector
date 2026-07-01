# AD Attack Detection Lab with LLM Analysis

## Project Overview
A cybersecurity home lab simulating Active Directory attacks and 
using AI-powered log analysis to detect and report on threats.

## Lab Architecture
- **DC01** — Windows Server 2022 Domain Controller (corp.local)
- **WIN11-CLIENT** — Windows 11 domain-joined target machine
- **Kali Linux** — Attacker machine

## Attacks Simulated
- Kerberoasting (MITRE ATT&CK T1558.003)

## Detection
- Windows Event ID 4769 monitoring
- LLM-powered incident report generation using Claude API

## Tools Used
- Impacket (GetUserSPNs.py)
- Active Directory Domain Services
- Python + Anthropic Claude API

## How It Works
1. Run Kerberoasting attack from Kali against DC01
2. Capture Event ID 4769 from Windows Security logs
3. Feed log data to Claude API
4. Receive automated incident report with MITRE ATT&CK mapping

## Skills Demonstrated
- Active Directory administration
- Offensive security techniques
- Log analysis and threat detection
- AI-augmented security operations
- Python scripting
