# Active Directory Attack-Detection Lab (Purple Team)
This project is a hands-on purple-team lab built to demonstrate the full lifecycle of an Active Directory attack — from building and hardening a domain, to attacking it, to detecting those attacks from the defender's side. I set up a Windows Server 2022 domain controller running Active Directory and DNS for the `corp.local` domain, joined a Windows 11 client, and configured realistic security groups with role-based permissions and least-privilege access. After hardening the environment and deploying endpoint logging, I used Kali Linux to run three real attacks — Kerberoasting, AS-REP Roasting, and Pass-the-Hash — and mapped attack paths with BloodHound. Each attack was captured in Windows telemetry and fed into a Python detection pipeline that classifies the attack and generates a MITRE ATT&CK-mapped incident report.

## Lab Architecture
- **DC01** - Windows Server 2022, 192.168.64.21 domain corp.local
- **WIN11-CLIENT** - Windows 11, domain-joined
- **Kali** - attacker, 192.168.64.7

<img src="Active%20Directory%20Images/Pn10.png" width="700">

*Active Directory Users and Computers for the `corp.local` domain.*

<img src="Active%20Directory%20Images/Pn60.png" width="700">

*The six user accounts created in the UserAccounts OU.*

## Domain Setup (RBAC, Hardening, Telemetry)
I built the domain to resemble a small but realistic organization rather than an empty test environment. On DC01, I configured Active Directory and DNS for the `corp.local` domain, then created organizational units to hold users and groups the way a real administrator would. Inside them, I created six user accounts and three security groups — `IT_Admins`, `Finance_Team`, and `HelpDesk` — and assigned each user to the group matching their role.

<img src="Active%20Directory%20Images/Pn61.png" width="700">

*The three role-based security groups: `IT_Admins`, `Finance_Team`, and `HelpDesk`.*

<img src="Active%20Directory%20Images/Pn66.png" width="700">

*`IT_Admins` membership — including `bob.jones`, the service account targeted later in the lab, and `john.smith`, the account used to launch the Kerberoasting attack.*

This structure follows **role-based access control (RBAC)**: permissions are granted to groups, and users inherit them through membership, rather than being assigned access one person at a time. To make that access model concrete, I created three file shares mapped to those groups and removed the default "Everyone" permission from each, enforcing **least privilege** so a compromised account can only reach what its role needs.

<img src="Active%20Directory%20Images/Pn71.png" width="700">

*The IT share locked down to `IT_Admins` only — the default "Everyone" permission removed.*

I then hardened the domain with a password and lockout policy through Group Policy: a 12-character minimum, complexity enabled, password history, a maximum password age, and account lockout after five failed attempts. These settings directly slow down password-guessing and spraying attacks, and I verified they applied using `net accounts`.

<img src="Active%20Directory%20Images/Pn88.png" width="700">

*Group Policy password policy: 12-character minimum, complexity, and history enforced.*

<img src="Active%20Directory%20Images/Pn95.png" width="700">

*Verifying the applied policy with `net accounts` — 12-character minimum, history of 10, lockout after 5 attempts.*

Finally, before running any attacks, I deployed the detection layer. I installed **Sysmon** on both DC01 and the Windows 11 client using the SwiftOnSecurity configuration, giving me rich endpoint telemetry — process creation, network connections, and more — beyond what the default Windows logs capture. Setting up detection *before* attacking was deliberate: it meant I could watch each attack happen through the telemetry rather than reconstruct it afterward.

<!-- IMAGE NOT YET VERIFIED: Pn114 (Sysmon telemetry) has not been checked against this slot. -->
<img src="Active%20Directory%20Images/Pn114.png" width="700">

*Sysmon telemetry flowing on DC01, verified with `Get-WinEvent`.*

## Mapping the Attack Path with BloodHound
Before running any attacks, I used **BloodHound Community Edition** to map the relationships in `corp.local` as a graph and reveal privilege-escalation paths that are hard to see by reading group memberships one at a time. I collected the domain data from Kali using `bloodhound-ce-python`, then ran BloodHound itself in Docker to visualize it.

The graph confirmed the intentional attack path I had built: `bob.jones` is both **Kerberoastable** (he has a Service Principal Name, so any user can request his ticket) and a direct **member of `IT_Admins`**. That combination is the whole point — cracking that one service account's password doesn't just recover a single password, it hands an attacker membership in an administrative group. BloodHound made that escalation path visible in a single picture, and it explains *why* a low-privilege service account is worth attacking in the first place.

<!-- IMAGE NOT YET VERIFIED: Pn138 (BloodHound graph) has not been checked against this slot. -->
<img src="Active%20Directory%20Images/Pn138.png" width="700">

*BloodHound showing the shortest path: `bob.jones` → `MemberOf` → `IT_Admins`.*

## Attack 1 - Kerberoasting (T1558.003)
Kerberoasting exploits how Kerberos handles service tickets. Any authenticated domain user can request a service ticket for any account that has a Service Principal Name (SPN) registered, and that ticket is encrypted with the service account's password hash. An attacker can take the ticket offline and crack it without ever touching the domain controller again, which makes it very hard to detect after the initial request.

From Kali, I used Impacket's `GetUserSPNs`, authenticating as the compromised `john.smith` account, to request the service ticket for `bob.jones`'s SPN (`MSSQLSvc/dc01.corp.local:1433`). The domain controller returned an encrypted TGS ticket using **RC4 encryption (type 0x17)** — a weak, legacy cipher that attack tools deliberately request because RC4 hashes are far faster to crack offline than modern AES.

<!-- IMAGE NOT YET VERIFIED: Pn145 (GetUserSPNs). REDACTION-SENSITIVE — must have the plaintext password covered before publishing. Also confirm whether this shows john.smith or a sarah.connor re-run; caption assumes john.smith to match all verified evidence so far. -->
<img src="Active%20Directory%20Images/Pn145.png" width="700">

*Impacket `GetUserSPNs` returning the Kerberoastable hash for `bob.jones`.*

On the defender's side, this request generated **Windows Security Event ID 4769**. I wrote a PowerShell script to pull the event and export the key fields — the requesting account, the target service, the encryption type, and the source IP — as structured JSON. The captured event shows the service-ticket request for `bob.jones`'s SPN, with encryption type `0x17` from the Kali host — the exact signature of a Kerberoasting attack.

<!-- IMAGE NOT YET VERIFIED: Pn209 (Event 4769 JSON) has not been checked against this slot. -->
<img src="Active%20Directory%20Images/Pn209.png" width="700">

*Event 4769 captured on DC01: RC4 (0x17) ticket request from the Kali host (192.168.64.7).*

## Attack 2 — AS-REP Roasting (T1558.004)

AS-REP Roasting targets user accounts that have Kerberos pre-authentication disabled, and it is more dangerous than Kerberoasting because it requires **no valid credentials at all**. Normally, a user must prove their identity before the domain controller issues a ticket. When pre-authentication is disabled, the DC hands back an AS-REP response — a blob encrypted with the user's password hash — to anyone who asks, which the attacker can then crack offline.

To set up the attack, I disabled pre-authentication on `rachel.green` using `Set-ADAccountControl`. From Kali, I ran Impacket's `GetNPUsers` against the domain with a list of usernames. It correctly reported that five of the six users were protected, and returned a crackable hash for only `rachel.green` — the one account I had weakened. The hash uses **RC4 (0x17)** encryption, the same offline-cracking signature as Kerberoasting.

<!-- IMAGE NOT YET VERIFIED: Pn159 (Set-ADAccountControl setup). SHUFFLE-RISK + REDACTION-SENSITIVE — verify by content (should show Set-ADAccountControl on rachel.green, "Rachel Green ... True") and check for exposed password before publishing. -->
<img src="Active%20Directory%20Images/Pn159.png" width="700">

*Disabling pre-authentication on `rachel.green` with `Set-ADAccountControl`.*

<!-- IMAGE NOT YET VERIFIED: Pn170 (GetNPUsers hash). SHUFFLE-RISK — verify by content (Kali, impacket-GetNPUsers, five "doesn't have UF_DONT_REQUIRE_PREAUTH" lines, then rachel.green AS-REP hash). -->
<img src="Active%20Directory%20Images/Pn170.png" width="700">

*Impacket `GetNPUsers` returning an AS-REP hash for `rachel.green`; the other five users are protected by pre-authentication.*

On the defender's side, AS-REP Roasting generates **Event ID 4768** (the initial authentication request) rather than 4769. I captured it the same way, filtering for the malicious request: `rachel.green`, RC4 encryption, from the Kali host.

<!-- IMAGE NOT YET VERIFIED: Pn185 (fixed 4768 collector). SHUFFLE-RISK — verify by content (PowerShell dump4768.ps1 table with rachel.green + sarah.connor, 0x17, 192.168.64.7, real values NOT null). -->
<img src="Active%20Directory%20Images/Pn185.png" width="700">

*Event 4768 captured on DC01: RC4 (0x17) authentication request for `rachel.green` from the Kali host.*

## Attack 3 — Pass-the-Hash (T1550.002)

Pass-the-Hash is different from the two roasting attacks: it skips cracking entirely. Windows NTLM authentication doesn't use the plaintext password to log in — it uses the password's NTLM hash. So if an attacker obtains the hash, they can authenticate as that user directly, without ever knowing the password. This is what makes it dangerous: a password reset doesn't stop the attack until the hash itself changes.

It's a two-part attack — first obtain a hash, then use it. To get the hashes, I ran Impacket's `secretsdump` from Kali against DC01, which dumped the NTLM hashes for every domain account. I then used that hash with Impacket's `psexec`/`wmiexec` to authenticate to DC01 as **Administrator using only the hash — no password**. The successful SMB session and access to administrative shares confirm the authentication worked.

<!-- IMAGE NOT YET VERIFIED: Pn189 (secretsdump). REDACTION-SENSITIVE — must cover the Administrator NT hash, machine plaintext_password_hex, and DPAPI keys before publishing. -->
<img src="Active%20Directory%20Images/Pn189.png" width="700">

*Impacket `secretsdump` dumping NTLM hashes from DC01.*

<!-- IMAGE NOT YET VERIFIED: Pn195 (wmiexec PtH). SHUFFLE-RISK + REDACTION-SENSITIVE — verify by content (Kali, impacket-wmiexec -hashes, "SMBv3.0 dialect used", whoami/hostname) and cover the NTLM hash on the command line before publishing. -->
<img src="Active%20Directory%20Images/Pn195.png" width="700">

*Impacket `wmiexec` authenticating to DC01 as Administrator using only the NTLM hash — no password.*

On the defender's side, Pass-the-Hash produces **Event ID 4624** (a successful logon) with a distinctive signature: **Logon Type 3** (network logon) using **NTLM** authentication, for a privileged account, from a remote host. I captured it by filtering for exactly that combination. The logs show `Administrator` logging on via NTLM Type-3 from the Kali host — the defender's side proof that the hash authenticated successfully.

<!-- IMAGE NOT YET VERIFIED: Pn196 (Event 4624) has not been checked against this slot. -->
<img src="Active%20Directory%20Images/Pn196.png" width="700">

*Event 4624 captured on DC01: Administrator logons via NTLM, Logon Type 3, from the Kali host (192.168.64.7).*

## The Detection Pipeline
The detection layer is the core of this project. The important design principle behind it: **the language model does not detect the attacks — code does.** A large language model can't monitor a network; it's a text-in, text-out system. So the detection is handled by a pipeline around it, and the model's job is only the final analysis-and-reporting step.

The pipeline works in three stages:

1. **Collection** — PowerShell scripts read the relevant Windows Security events off DC01 (4769, 4768, 4624) and export the key fields as structured JSON.
2. **Classification** — a Python script inspects each event's fields and decides which attack it is, using plain conditional logic:
   - Event **4769** with RC4 (`0x17`) → **Kerberoasting** (T1558.003)
   - Event **4768** with RC4 (`0x17`) → **AS-REP Roasting** (T1558.004)
   - Event **4624** with Logon Type 3 + NTLM → **Pass-the-Hash** (T1550.002)
3. **Reporting** — the classified event is sent to the Claude API, which writes a full incident report: confirming the technique, mapping it to MITRE ATT&CK, assigning a severity with rationale, explaining the attacker's objective, and recommending response actions.

This separation matters. The **detection** is done by collecting the right telemetry and matching it against known attack signatures — reliable, explainable code. The **language model adds enrichment**: turning a raw event into a readable, analyst-quality incident report. Notably, each attack has a *different* signature — the roasting attacks key on RC4 encryption, while Pass-the-Hash keys on the logon type and authentication package — which shows that good detection comes from knowing which fields matter for each technique.

Running the detector against all three captured events produces three correctly classified, MITRE-mapped incident reports — a working multi-attack detection pipeline rather than a single-attack script.

<!-- IMAGE NOT YET VERIFIED: Pn182 (all-three-attacks capstone). If any generated report in this shot names sarah.connor as the Kerberoast attacker while the evidence shows john.smith, regenerate before publishing. Also crop the local shell prompt (eduroam host/IP) out of report screenshots. -->
<img src="Active%20Directory%20Images/Pn182.png" width="700">

*The detector classifying and reporting on all three attacks (Kerberoasting, AS-REP Roasting, Pass-the-Hash).*
