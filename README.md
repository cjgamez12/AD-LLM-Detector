# Active Directory Attack-Detection Lab (Purple Team)

This project is a hands-on purple-team lab built to demonstrate the full lifecycle of an Active Directory attack — from building and hardening a domain, to attacking it, to detecting those attacks from the defender's side. I set up a Windows Server 2022 domain controller running Active Directory and DNS for the `corp.local` domain, joined a Windows 11 client, and configured realistic security groups with role-based permissions and least-privilege access. After hardening the environment and deploying endpoint logging, I used Kali Linux to run three real attacks — Kerberoasting, AS-REP Roasting, and Pass-the-Hash — and mapped attack paths with BloodHound. Each attack was captured in Windows telemetry and fed into a Python detection pipeline that classifies the attack and generates a MITRE ATT&CK-mapped incident report.

## Lab Architecture
- **DC01** - Windows Server 2022, 192.168.64.21 domain corp.local
- **WIN11-CLIENT** - Windows 11, domain-joined
- **Kali** - attacker, 192.168.64.7

  <img src="images/kerberoast-4769.png" width="700">

  ## Domain Setup (RBAC, Hardening, Telemetry)

  ## Mapping the Attack Path with BloodHound

  ## Attack 1 - Kerberoasting (T1558.003)


  ## Attack 2 - AS-REP Roasting (T1558.004)

  ## Attack 3 - Pass-the-Hash (T1550.002)

  ## The Detection Pipeline

  ## What I learned
  

