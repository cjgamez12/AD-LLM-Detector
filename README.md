# Active Directory Attack-Detection Lab (Purple Team)
This project is a hands-on purple-team lab built to demonstrate the full lifecycle of an Active Directory attack — from building and hardening a domain, to attacking it, to detecting those attacks from the defender's side. I set up a Windows Server 2022 domain controller running Active Directory and DNS for the `corp.local` domain, joined a Windows 11 client, and configured realistic security groups with role-based permissions and least-privilege access. After hardening the environment and deploying endpoint logging, I used Kali Linux to run three real attacks — Kerberoasting, AS-REP Roasting, and Pass-the-Hash — and mapped attack paths with BloodHound. Each attack was captured in Windows telemetry and fed into a Python detection pipeline that classifies the attack and generates a MITRE ATT&CK-mapped incident report.

## Lab Architecture
- **DC01** - Windows Server 2022, 192.168.64.21 domain corp.local
- **WIN11-CLIENT** - Windows 11, domain-joined
- **Kali** - attacker, 192.168.64.7

  <img src="images/kerberoast-4769.png" width="700">

## Domain Setup (RBAC, Hardening, Telemetry)
I built the domain to resemble a small but realistic organization rather than an empty test environment. On DC01, I configured Active Directory and DNS for the `corp.local` domain, then created organizational units to hold users and groups the way a real administrator would. Inside them, I created six user accounts and three security groups — `IT_Admins`, `Finance_Team`, and `HelpDesk` — and assigned each user to the group matching their role.

This structure follows **role-based access control (RBAC)**: permissions are granted to groups, and users inherit them through membership, rather than being assigned access one person at a time. To make that access model concrete, I created three file shares mapped to those groups and removed the default "Everyone" permission from each, enforcing **least privilege** so a compromised account can only reach what its role needs.

I then hardened the domain with a password and lockout policy through Group Policy: a 12-character minimum, complexity enabled, password history, a maximum password age, and account lockout after five failed attempts. These settings directly slow down password-guessing and spraying attacks, and I verified they applied using `net accounts`.

Finally, before running any attacks, I deployed the detection layer. I installed **Sysmon** on both DC01 and the Windows 11 client using the SwiftOnSecurity configuration, giving me rich endpoint telemetry — process creation, network connections, and more — beyond what the default Windows logs capture. Setting up detection *before* attacking was deliberate: it meant I could watch each attack happen through the telemetry rather than reconstruct it afterward.

## Mapping the Attack Path with BloodHound
Before running any attacks, I used **BloodHound Community Edition** to map the relationships in `corp.local` as a graph and reveal privilege-escalation paths that are hard to see by reading group memberships one at a time. I collected the domain data from Kali using `bloodhound-ce-python`, then ran BloodHound itself in Docker to visualize it.

The graph confirmed the intentional attack path I had built: `bob.jones` is both **Kerberoastable** (he has a Service Principal Name, so any user can request his ticket) and a direct **member of `IT_Admins`**. That combination is the whole point — cracking that one service account's password doesn't just recover a single password, it hands an attacker membership in an administrative group. BloodHound made that escalation path visible in a single picture, and it explains *why* a low-privilege service account is worth attacking in the first place.

<img src="images/bloodhound-path.png" width="700">

*BloodHound showing the shortest path: `bob.jones` → `MemberOf` → `IT_Admins`.*

## Attack 1 - Kerberoasting (T1558.003)
Kerberoasting exploits how Kerberos handles service tickets. Any authenticated domain user can request a service ticket for any account that has a Service Principal Name (SPN) registered, and that ticket is encrypted with the service account's password hash. An attacker can take the ticket offline and crack it without ever touching the domain controller again, which makes it very hard to detect after the initial request.

From Kali, I used Impacket's `GetUserSPNs`, authenticating as `sarah.connor`, to request the service ticket for `bob.jones`'s SPN (`MSSQLSvc/dc01.corp.local:1433`). The domain controller returned an encrypted TGS ticket using **RC4 encryption (type 0x17)** — a weak, legacy cipher that attack tools deliberately request because RC4 hashes are far faster to crack offline than modern AES.

<img src="images/kerberoast-attack.png" width="700">

*Impacket `GetUserSPNs` returning the Kerberoastable hash for `bob.jones`.*

On the defender's side, this request generated **Windows Security Event ID 4769**. I wrote a PowerShell script to pull the event and export the key fields — the requesting account, the target service, the encryption type, and the source IP — as structured JSON. The captured event shows `sarah.connor` requesting `bob.jones`'s service, with encryption type `0x17` from the Kali host — the exact signature of a Kerberoasting attack.

<img src="images/kerberoast-4769.png" width="700">

*Event 4769 captured on DC01: RC4 (0x17) ticket request from the Kali host (192.168.64.7).*


## Attack 2 — AS-REP Roasting (T1558.004)

AS-REP Roasting targets user accounts that have Kerberos pre-authentication disabled, and it is more dangerous than Kerberoasting because it requires **no valid credentials at all**. Normally, a user must prove their identity before the domain controller issues a ticket. When pre-authentication is disabled, the DC hands back an AS-REP response — a blob encrypted with the user's password hash — to anyone who asks, which the attacker can then crack offline.

To set up the attack, I disabled pre-authentication on `rachel.green` using `Set-ADAccountControl`. From Kali, I ran Impacket's `GetNPUsers` against the domain with a list of usernames. It correctly reported that five of the six users were protected, and returned a crackable hash for only `rachel.green` — the one account I had weakened. The hash uses **RC4 (0x17)** encryption, the same offline-cracking signature as Kerberoasting.

<img src="images/asrep-attack.png" width="700">

*Impacket `GetNPUsers` returning an AS-REP hash for `rachel.green`; the other five users are protected by pre-authentication.*

On the defender's side, AS-REP Roasting generates **Event ID 4768** (the initial authentication request) rather than 4769. I captured it the same way, filtering for the malicious request: `rachel.green`, RC4 encryption, from the Kali host.

<img src="images/asrep-4768.png" width="700">

*Event 4768 captured on DC01: RC4 (0x17) authentication request for `rachel.green` from the Kali host.*

## Attack 3 — Pass-the-Hash (T1550.002)

Pass-the-Hash is different from the two roasting attacks: it skips cracking entirely. Windows NTLM authentication doesn't use the plaintext password to log in — it uses the password's NTLM hash. So if an attacker obtains the hash, they can authenticate as that user directly, without ever knowing the password. This is what makes it dangerous: a password reset doesn't stop the attack until the hash itself changes.

It's a two-part attack — first obtain a hash, then use it. To get the hashes, I ran Impacket's `secretsdump` from Kali against DC01, which dumped the NTLM hashes for every domain account. I then used that hash with Impacket's `psexec`/`wmiexec` to authenticate to DC01 as **Administrator using only the hash — no password**. The successful SMB session and access to administrative shares confirm the authentication worked.

<img src="images/pth-secretsdump.png" width="700">

*Impacket `secretsdump` dumping NTLM hashes from DC01.*

On the defender's side, Pass-the-Hash produces **Event ID 4624** (a successful logon) with a distinctive signature: **Logon Type 3** (network logon) using **NTLM** authentication, for a privileged account, from a remote host. I captured it by filtering for exactly that combination. The logs show `Administrator` logging on via NTLM Type-3 from the Kali host — the defender's side proof that the hash authenticated successfully.

<img src="images/pth-4624.png" width="700">

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

<img src="images/detector-reports.png" width="700">

*The detector classifying and reporting on all three attacks (Kerberoasting, AS-REP Roasting, Pass-the-Hash).*

  ## What I learned
  

