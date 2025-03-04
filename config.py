#!/usr/bin/env python3
"""
Shared configuration file for AD Pentest Tools
This file contains credentials, targets, and settings used by all tools in the suite.
"""

# Target IP addresses or hostnames
TARGETS = [
    "192.168.1.100",  # Example DC
    "10.0.0.5",       # Example file server
    # Add more targets as needed
]

# Domain user credentials to try
DOMAIN_USERS = [
    "Administrator",
    "admin",
    "svc_sql",
    "svc_web",
    "helpdesk",
    "backup",
    # Add more usernames as needed
]

# Passwords to try (for password spraying)
DOMAIN_PASSWORDS = [
    "Password123!",
    "Spring2023!",
    "Winter2023!",
    "Company2023!",
    "P@ssw0rd",
    "Welcome1",
    # Add more passwords as needed
]

#TODO Create a known user and password set variable, or user and ntlm hash set and fill it in whenever a set of credentials is found to work

# NTLM hashes to try (for pass-the-hash)
NTLM_HASHES = [
    "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",  # Example hash
    # Add more hashes as needed
]

# Command execution settings
TIMEOUT = 60  # Seconds to wait for command execution
MAX_THREADS = 10  # Maximum number of parallel threads

# Logging settings
LOG_DIRECTORY = "logs"
RESULTS_DIRECTORY = "results"
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL

# Tool-specific settings
NETEXEC_SETTINGS = {
    "retries": 3,
    "domain": "contoso.local",  # Default domain to use
    "modules": ["mimikatz", "lsassy", "spider_plus"]
}

KERBEROAST_SETTINGS = {
    "wordlist": "wordlists/rockyou.txt",
    "hash_mode": 13100,  # Hashcat mode for Kerberos TGS tickets
    "rules": ["rules/best64.rule"],
    "crack_timeout": 3600  # Seconds to allow for cracking
}

BLOODHOUND_SETTINGS = {
    "collection_methods": ["All"],
    "domain": "contoso.local",
    "neo4j_uri": "bolt://localhost:7687",
    "neo4j_user": "neo4j",
    "neo4j_password": "BloodHound"
}

# Impacket settings
IMPACKET_SETTINGS = {
    "domain": "contoso.local",
    "dc_ip": "",  # Will be set dynamically to target IP if empty
}

# Additional enumeration commands to run
ADDITIONAL_COMMANDS = {
    "smb": [
        "smbclient -L //{target} -U {username}%{password}",
        "crackmapexec smb {target} -u {username} -p {password} -M mimikatz"
    ],
    "ldap": [
        "ldapsearch -x -h {target} -D '{domain}\\{username}' -w {password} -b 'DC={domain_part1},DC={domain_part2}' '(objectClass=user)'",
        "windapsearch --dc {target} -d {domain} -u {username} -p {password} --da"
    ]
}

# Custom functions for special handling
def parse_domain(domain_string):
    """Parse domain string into parts for LDAP queries"""
    parts = domain_string.split('.')
    return parts

def obfuscate_password(password):
    """Return an obfuscated version of the password for logging"""
    if not password:
        return ""
    return "*" * len(password)