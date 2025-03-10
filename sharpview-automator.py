#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import json
import base64
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

# Import shared configuration
try:
    from config import (
        TARGETS, DOMAIN_USERS, DOMAIN_PASSWORDS, NTLM_HASHES,
        LOG_DIRECTORY, RESULTS_DIRECTORY
    )
except ImportError:
    print("Error: config.py not found. Please ensure it exists in the current directory.")
    sys.exit(1)

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

class SharpViewWrapper:
    """Wrapper for SharpView tool to automate AD enumeration tasks"""
    
    def __init__(self):
        self.results_dir = Path(RESULTS_DIRECTORY) / "sharpview"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = None
        self.end_time = None
        
        # Find SharpView binary
        self.sharpview_path = self._find_sharpview()
        
        # Directory for temporary scripts
        self.scripts_dir = Path("scripts/sharpview")
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
    
    def _find_sharpview(self) -> Optional[Path]:
        """Find SharpView binary in common locations"""
        sharpview_locations = [
            "SharpView.exe",
            "Ghostpack-CompiledBinaries/dotnet v4.5 compiled binaries/SharpView.exe",
            "Ghostpack-CompiledBinaries/dotnet v4.7.2 compiled binaries/SharpView.exe",
            "SharpView/SharpView.exe",
            "tools/SharpView.exe",
            "../tools/SharpView.exe"
        ]
        
        for location in sharpview_locations:
            path = Path(location)
            if path.exists():
                Logger.success(f"Found SharpView at: {path.absolute()}")
                return path.absolute()
        
        Logger.warning("SharpView binary not found. Using a dynamic download approach.")
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
    
    def save_json_results(self, target: str, data: dict, operation: str) -> Path:
        """Save JSON results to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{operation}_{timestamp}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def create_powershell_loader(self, sharpview_commands: List[str], download_sharpview: bool = False) -> Path:
        """Create a PowerShell script that loads and executes SharpView commands"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sharpview_loader_{timestamp}.ps1"
        filepath = self.scripts_dir / filename
        
        script_content = """
# PowerShell script to execute SharpView commands
$ErrorActionPreference = "SilentlyContinue"

"""
        # Add the SharpView download logic if requested
        if download_sharpview:
            script_content += """
# Function to download SharpView if not available locally
function Get-SharpView {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:TEMP\\SharpView.exe"
    )
    
    if (Test-Path $OutputPath) {
        Write-Output "SharpView already exists at: $OutputPath"
        return $OutputPath
    }
    
    # Try to download SharpView from a GitHub repo
    try {
        # Create a web client with TLS 1.2 support
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $client = New-Object System.Net.WebClient
        
        # Define GitHub raw URL for SharpView
        # Note: This URL would need to be updated with a valid SharpView binary source
        $url = "https://github.com/tevora-threat/SharpView/releases/download/v1.0/SharpView.exe"
        
        Write-Output "Downloading SharpView from: $url"
        $client.DownloadFile($url, $OutputPath)
        
        if (Test-Path $OutputPath) {
            Write-Output "SharpView downloaded successfully to: $OutputPath"
            return $OutputPath
        } else {
            throw "Downloaded file not found at $OutputPath"
        }
    } catch {
        Write-Error "Failed to download SharpView: $_"
        
        # Try an alternative source if the first one fails
        try {
            $alternativeUrl = "https://github.com/GhostPack/SharpView/releases/latest/download/SharpView.exe"
            Write-Output "Trying alternative source: $alternativeUrl"
            $client.DownloadFile($alternativeUrl, $OutputPath)
            
            if (Test-Path $OutputPath) {
                Write-Output "SharpView downloaded successfully from alternative source to: $OutputPath"
                return $OutputPath
            } else {
                throw "Downloaded file not found at $OutputPath"
            }
        } catch {
            Write-Error "Failed to download SharpView from alternative source: $_"
            return $null
        }
    }
}

# Get SharpView.exe path
$sharpViewPath = Get-SharpView
if (-not $sharpViewPath) {
    Write-Error "Failed to get SharpView. Exiting."
    exit 1
}

"""
        else:
            # Use the specified SharpView path
            if self.sharpview_path:
                script_content += f"""
# Use the specified SharpView path
$sharpViewPath = "{self.sharpview_path}"
if (-not (Test-Path $sharpViewPath)) {{
    Write-Error "SharpView not found at: $sharpViewPath"
    exit 1
}}

"""
            else:
                # Look for SharpView in common locations
                script_content += """
# Function to find SharpView in common locations
function Find-SharpView {
    $commonLocations = @(
        "SharpView.exe",
        "C:\\Tools\\SharpView.exe",
        "$env:TEMP\\SharpView.exe",
        "$env:USERPROFILE\\Downloads\\SharpView.exe",
        ".\\SharpView.exe"
    )
    
    foreach ($location in $commonLocations) {
        if (Test-Path $location) {
            Write-Output "Found SharpView at: $location"
            return $location
        }
    }
    
    return $null
}

# Find SharpView
$sharpViewPath = Find-SharpView
if (-not $sharpViewPath) {
    Write-Error "SharpView not found in common locations. Use download option."
    exit 1
}

"""
        
        # Add the SharpView execution commands
        script_content += """
# Execute SharpView commands
Write-Output "Executing SharpView commands..."

$results = @{}

"""
        
        # Add each SharpView command
        for i, command in enumerate(sharpview_commands):
            cmd_name = f"cmd{i}"
            command = command.replace('"', '`"')  # Escape double quotes for PowerShell
            script_content += f"""
Write-Output "Running: $sharpViewPath {command}"
$results["{cmd_name}"] = & $sharpViewPath {command} | Out-String

"""
        
        # Add code to output results
        script_content += """
# Output all results as JSON
$resultsJson = $results | ConvertTo-Json -Depth 10
Write-Output "--- RESULTS_JSON_START ---"
Write-Output $resultsJson
Write-Output "--- RESULTS_JSON_END ---"
"""
        
        with open(filepath, 'w') as f:
            f.write(script_content)
        
        Logger.success(f"Created PowerShell SharpView loader at: {filepath}")
        return filepath
    
    def execute_sharpview_locally(self, commands: List[str], description: str) -> str:
        """Execute SharpView locally with given commands"""
        # Create a PowerShell loader script
        ps_script = self.create_powershell_loader(commands, download_sharpview=(self.sharpview_path is None))
        
        # Execute the script
        output = self.execute_command(f"powershell -ExecutionPolicy Bypass -File \"{ps_script}\"", f"Executing SharpView {description}")
        
        # Extract JSON results if available
        json_match = re.search(r"--- RESULTS_JSON_START ---\s*([\s\S]*?)\s*--- RESULTS_JSON_END ---", output)
        if json_match:
            try:
                json_str = json_match.group(1).strip()
                results = json.loads(json_str)
                return json.dumps(results, indent=4)
            except Exception as e:
                Logger.warning(f"Failed to parse JSON results: {str(e)}")
        
        return output
    
    def execute_sharpview_remotely(self, target: str, username: str, password: str, commands: List[str], description: str) -> str:
        """Execute SharpView on a remote system using PowerShell remoting"""
        # Create PowerShell script with SharpView commands
        ps_script = self.create_powershell_loader(commands, download_sharpview=True)
        
        # Execute PowerShell script on remote system
        ps_command = f"powershell -ep bypass -command \"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        ps_command += f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $pw); "
        ps_command += f"Invoke-Command -ComputerName {target} -Credential $cred -FilePath '{ps_script}'\""
        
        output = self.execute_command(ps_command, f"Executing SharpView remotely on {target}: {description}")
        
        # Extract JSON results if available
        json_match = re.search(r"--- RESULTS_JSON_START ---\s*([\s\S]*?)\s*--- RESULTS_JSON_END ---", output)
        if json_match:
            try:
                json_str = json_match.group(1).strip()
                results = json.loads(json_str)
                return json.dumps(results, indent=4)
            except Exception as e:
                Logger.warning(f"Failed to parse JSON results: {str(e)}")
        
        return output
    
    def enum_domain_info(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate basic domain information"""
        Logger.section("Enumerating Domain Information")
        
        # Build commands for domain info
        commands = [
            "Get-NetDomain", 
            "Get-NetForest", 
            "Get-NetDomainController",
            "Get-DomainPolicy"
        ]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain information enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain information enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_info")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_info_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_trusts(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate domain trusts"""
        Logger.section("Enumerating Domain Trusts")
        
        # Build commands for domain trusts
        commands = [
            "Get-NetDomainTrust", 
            "Get-NetForestTrust"
        ]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain trusts enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain trusts enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_trusts")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_trusts_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_users(self, target: str = None, username: str = None, password: str = None, admin_only: bool = False) -> Dict[str, Any]:
        """Enumerate domain users"""
        description = "admin users" if admin_only else "all domain users"
        Logger.section(f"Enumerating {description}")
        
        # Build commands for user enumeration
        commands = []
        if admin_only:
            commands.append("Get-NetUser -AdminCount")
        else:
            commands.append("Get-NetUser")
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"{description} enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"{description} enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        operation = "admin_users" if admin_only else "domain_users"
        output_file = self.save_results(target_name, output, operation)
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"{operation}_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_groups(self, target: str = None, username: str = None, password: str = None, admin_only: bool = False) -> Dict[str, Any]:
        """Enumerate domain groups"""
        description = "admin groups" if admin_only else "all domain groups"
        Logger.section(f"Enumerating {description}")
        
        # Build commands for group enumeration
        commands = []
        if admin_only:
            commands.append("Get-NetGroup -AdminCount")
        else:
            commands.append("Get-NetGroup")
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"{description} enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"{description} enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        operation = "admin_groups" if admin_only else "domain_groups"
        output_file = self.save_results(target_name, output, operation)
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"{operation}_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_computers(self, target: str = None, username: str = None, password: str = None, servers_only: bool = False) -> Dict[str, Any]:
        """Enumerate domain computers"""
        description = "domain servers" if servers_only else "all domain computers"
        Logger.section(f"Enumerating {description}")
        
        # Build commands for computer enumeration
        commands = []
        if servers_only:
            commands.append("Get-NetComputer -OperatingSystem \"*server*\"")
        else:
            commands.append("Get-NetComputer")
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"{description} enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"{description} enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        operation = "domain_servers" if servers_only else "domain_computers"
        output_file = self.save_results(target_name, output, operation)
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"{operation}_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_group_members(self, group_name: str, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate members of a specific group"""
        Logger.section(f"Enumerating Members of Group: {group_name}")
        
        # Build command for group member enumeration
        command = f"Get-NetGroupMember -GroupName \"{group_name}\""
        commands = [command]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"group members enumeration for {group_name}"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"group members enumeration for {group_name}"
            )
        
        # Save the raw output
        target_name = target or "local"
        group_name_safe = re.sub(r'[^\w\-]', '_', group_name)
        output_file = self.save_results(target_name, output, f"group_{group_name_safe}_members")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"group_{group_name_safe}_members_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_gpo(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate Group Policy Objects"""
        Logger.section("Enumerating Group Policy Objects")
        
        # Build commands for GPO enumeration
        commands = ["Get-NetGPO"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="GPO enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="GPO enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "gpo")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "gpo_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def find_local_admin_access(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Find local admin access for current user"""
        Logger.section("Finding Local Admin Access")
        
        # Build commands for local admin access
        commands = ["Find-LocalAdminAccess"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="local admin access enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="local admin access enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "local_admin_access")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "local_admin_access_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def find_domain_shares(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Find domain shares"""
        Logger.section("Finding Domain Shares")
        
        # Build commands for domain shares
        commands = ["Find-DomainShare"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain shares enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain shares enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_shares")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_shares_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def find_interesting_domain_acl(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Find interesting domain ACLs"""
        Logger.section("Finding Interesting Domain ACLs")
        
        # Build commands for domain ACLs
        commands = ["Find-InterestingDomainAcl"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="interesting domain ACL enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="interesting domain ACL enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "interesting_acls")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "interesting_acls_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def get_domain_ou(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Get domain organizational units"""
        Logger.section("Getting Domain Organizational Units")
        
        # Build commands for domain OUs
        commands = ["Get-NetOU"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain OUs enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain OUs enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_ous")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_ous_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def run_full_enumeration(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Run a full enumeration using all available functions"""
        self.start_time = datetime.now()
        
        Logger.section("Starting Full AD Enumeration with SharpView")
        Logger.info(f"Start Time: {self.start_time}")
        
        if target:
            Logger.info(f"Target: {target}")
            Logger.info(f"Username: {username}")
        else:
            Logger.info("Running locally on current machine")
        
        # Initialize results dictionary
        all_results = {
            "start_time": str(self.start_time),
            "target": target or "local",
            "username": username,
            "domain_info": None,
            "domain_trusts": None,
            "domain_users": None,
            "admin_users": None,
            "domain_groups": None,
            "admin_groups": None,
            "domain_computers": None,
            "domain_servers": None,
            "domain_admin_members": None,
            "enterprise_admin_members": None,
            "gpo": None,
            "domain_ous": None,
            "local_admin_access": None,
            "domain_shares": None,
            "interesting_acls": None
        }
        
        # Run each enumeration function and store results
        try:
            Logger.info("Enumerating domain information...")
            all_results["domain_info"] = self.enum_domain_info(target, username, password)
            
            Logger.info("Enumerating domain trusts...")
            all_results["domain_trusts"] = self.enum_domain_trusts(target, username, password)
            
            Logger.info("Enumerating domain users...")
            all_results["domain_users"] = self.enum_domain_users(target, username, password)
            
            Logger.info("Enumerating admin users...")
            all_results["admin_users"] = self.enum_domain_users(target, username, password, admin_only=True)
            
            Logger.info("Enumerating domain groups...")
            all_results["domain_groups"] = self.enum_domain_groups(target, username, password)
            
            Logger.info("Enumerating admin groups...")
            all_results["admin_groups"] = self.enum_domain_groups(target, username, password, admin_only=True)
            
            Logger.info("Enumerating domain computers...")
            all_results["domain_computers"] = self.enum_domain_computers(target, username, password)
            
            Logger.info("Enumerating domain servers...")
            all_results["domain_servers"] = self.enum_domain_computers(target, username, password, servers_only=True)
            
            Logger.info("Enumerating Domain Admins group members...")
            all_results["domain_admin_members"] = self.enum_group_members("Domain Admins", target, username, password)
            
            Logger.info("Enumerating Enterprise Admins group members...")
            all_results["enterprise_admin_members"] = self.enum_group_members("Enterprise Admins", target, username, password)
            
            Logger.info("Enumerating Group Policy Objects...")
            all_results["gpo"] = self.enum_gpo(target, username, password)
            
            Logger.info("Enumerating Domain Organizational Units...")
            all_results["domain_ous"] = self.get_domain_ou(target, username, password)
            
            # The following functions may take longer and potentially trigger alerts
            Logger.warning("The following enumeration functions may be more 'noisy' and could trigger alerts...")
            
            Logger.info("Finding local admin access...")
            all_results["local_admin_access"] = self.find_local_admin_access(target, username, password)
            
            Logger.info("Finding domain shares...")
            all_results["domain_shares"] = self.find_domain_shares(target, username, password)
            
            Logger.info("Finding interesting domain ACLs...")
            all_results["interesting_acls"] = self.find_interesting_domain_acl(target, username, password)
            
        except KeyboardInterrupt:
            Logger.warning("Enumeration interrupted by user. Saving partial results...")
        except Exception as e:
            Logger.error(f"Error during enumeration: {str(e)}")
        
        # Complete the operation
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        all_results["end_time"] = str(self.end_time)
        all_results["duration"] = str(duration)
        
        Logger.section("AD Enumeration Complete")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {self.end_time}")
        Logger.info(f"Duration: {duration}")
        
        # Save overall results
        summary_file = self.results_dir / f"sharpview_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(all_results, f, indent=4)
        
        Logger.success(f"Summary saved to {summary_file}")
        
        return all_results

def main():
    parser = argparse.ArgumentParser(description=f'{Colors.BOLD}SharpView Automation Tool{Colors.ENDC}')
    
    # Main command subparsers
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Full enumeration command
    full_parser = subparsers.add_parser('full', help='Run full AD enumeration')
    full_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    full_parser.add_argument('-u', '--username', help='Username for remote execution')
    full_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # Domain info command
    domain_parser = subparsers.add_parser('domain', help='Enumerate basic domain information')
    domain_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    domain_parser.add_argument('-u', '--username', help='Username for remote execution')
    domain_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # Domain trusts command
    trusts_parser = subparsers.add_parser('trusts', help='Enumerate domain trusts')
    trusts_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    trusts_parser.add_argument('-u', '--username', help='Username for remote execution')
    trusts_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # Users command
    users_parser = subparsers.add_parser('users', help='Enumerate domain users')
    users_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    users_parser.add_argument('-u', '--username', help='Username for remote execution')
    users_parser.add_argument('-p', '--password', help='Password for remote execution')
    users_parser.add_argument('-a', '--admin-only', action='store_true', help='Enumerate admin users only')
    
    # Groups command
    groups_parser = subparsers.add_parser('groups', help='Enumerate domain groups')
    groups_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    groups_parser.add_argument('-u', '--username', help='Username for remote execution')
    groups_parser.add_argument('-p', '--password', help='Password for remote execution')
    groups_parser.add_argument('-a', '--admin-only', action='store_true', help='Enumerate admin groups only')
    
    # Group members command
    group_members_parser = subparsers.add_parser('group-members', help='Enumerate members of a specific group')
    group_members_parser.add_argument('-g', '--group-name', required=True, help='Group name to enumerate')
    group_members_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    group_members_parser.add_argument('-u', '--username', help='Username for remote execution')
    group_members_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # Computers command
    computers_parser = subparsers.add_parser('computers', help='Enumerate domain computers')
    computers_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    computers_parser.add_argument('-u', '--username', help='Username for remote execution')
    computers_parser.add_argument('-p', '--password', help='Password for remote execution')
    computers_parser.add_argument('-s', '--servers-only', action='store_true', help='Enumerate servers only')
    
    # GPO command
    gpo_parser = subparsers.add_parser('gpo', help='Enumerate Group Policy Objects')
    gpo_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    gpo_parser.add_argument('-u', '--username', help='Username for remote execution')
    gpo_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # OU command
    ou_parser = subparsers.add_parser('ou', help='Enumerate Organizational Units')
    ou_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    ou_parser.add_argument('-u', '--username', help='Username for remote execution')
    ou_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # Local admin access command
    admin_access_parser = subparsers.add_parser('admin-access', help='Find local admin access')
    admin_access_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    admin_access_parser.add_argument('-u', '--username', help='Username for remote execution')
    admin_access_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # Domain shares command
    shares_parser = subparsers.add_parser('shares', help='Find domain shares')
    shares_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    shares_parser.add_argument('-u', '--username', help='Username for remote execution')
    shares_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    # ACL command
    acl_parser = subparsers.add_parser('acl', help='Find interesting domain ACLs')
    acl_parser.add_argument('-t', '--target', help='Target IP address or hostname for remote execution')
    acl_parser.add_argument('-u', '--username', help='Username for remote execution')
    acl_parser.add_argument('-p', '--password', help='Password for remote execution')
    
    args = parser.parse_args()
    
    wrapper = SharpViewWrapper()
    
    # Check credentials for remote execution
    if args.target and (not args.username or not args.password):
        Logger.error("For remote execution, username and password are required")
        return
    
    # Handle commands
    if args.command == 'full':
        wrapper.run_full_enumeration(args.target, args.username, args.password)
    elif args.command == 'domain':
        wrapper.enum_domain_info(args.target, args.username, args.password)
    elif args.command == 'trusts':
        wrapper.enum_domain_trusts(args.target, args.username, args.password)
    elif args.command == 'users':
        wrapper.enum_domain_users(args.target, args.username, args.password, args.admin_only)
    elif args.command == 'groups':
        wrapper.enum_domain_groups(args.target, args.username, args.password, args.admin_only)
    elif args.command == 'group-members':
        wrapper.enum_group_members(args.group_name, args.target, args.username, args.password)
    elif args.command == 'computers':
        wrapper.enum_domain_computers(args.target, args.username, args.password, args.servers_only)
    elif args.command == 'gpo':
        wrapper.enum_gpo(args.target, args.username, args.password)
    elif args.command == 'ou':
        wrapper.get_domain_ou(args.target, args.username, args.password)
    elif args.command == 'admin-access':
        wrapper.find_local_admin_access(args.target, args.username, args.password)
    elif args.command == 'shares':
        wrapper.find_domain_shares(args.target, args.username, args.password)
    elif args.command == 'acl':
        wrapper.find_interesting_domain_acl(args.target, args.username, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
    
    def enum_domain_trusts(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate domain trusts"""
        Logger.section("Enumerating Domain Trusts")
        
        # Build commands for domain trusts
        commands = [
            "Get-NetDomainTrust", 
            "Get-NetForestTrust"
        ]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain trusts enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain trusts enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_trusts")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_trusts_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_users(self, target: str = None, username: str = None, password: str = None, admin_only: bool = False) -> Dict[str, Any]:
        """Enumerate domain users"""
        description = "admin users" if admin_only else "all domain users"
        Logger.section(f"Enumerating {description}")
        
        # Build commands for user enumeration
        commands = []
        if admin_only:
            commands.append("Get-NetUser -AdminCount")
        else:
            commands.append("Get-NetUser")
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"{description} enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"{description} enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        operation = "admin_users" if admin_only else "domain_users"
        output_file = self.save_results(target_name, output, operation)
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"{operation}_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_groups(self, target: str = None, username: str = None, password: str = None, admin_only: bool = False) -> Dict[str, Any]:
        """Enumerate domain groups"""
        description = "admin groups" if admin_only else "all domain groups"
        Logger.section(f"Enumerating {description}")
        
        # Build commands for group enumeration
        commands = []
        if admin_only:
            commands.append("Get-NetGroup -AdminCount")
        else:
            commands.append("Get-NetGroup")
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"{description} enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"{description} enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        operation = "admin_groups" if admin_only else "domain_groups"
        output_file = self.save_results(target_name, output, operation)
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"{operation}_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_domain_computers(self, target: str = None, username: str = None, password: str = None, servers_only: bool = False) -> Dict[str, Any]:
        """Enumerate domain computers"""
        description = "domain servers" if servers_only else "all domain computers"
        Logger.section(f"Enumerating {description}")
        
        # Build commands for computer enumeration
        commands = []
        if servers_only:
            commands.append("Get-NetComputer -OperatingSystem \"*server*\"")
        else:
            commands.append("Get-NetComputer")
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"{description} enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"{description} enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        operation = "domain_servers" if servers_only else "domain_computers"
        output_file = self.save_results(target_name, output, operation)
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"{operation}_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_group_members(self, group_name: str, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate members of a specific group"""
        Logger.section(f"Enumerating Members of Group: {group_name}")
        
        # Build command for group member enumeration
        command = f"Get-NetGroupMember -GroupName \"{group_name}\""
        commands = [command]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description=f"group members enumeration for {group_name}"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description=f"group members enumeration for {group_name}"
            )
        
        # Save the raw output
        target_name = target or "local"
        group_name_safe = re.sub(r'[^\w\-]', '_', group_name)
        output_file = self.save_results(target_name, output, f"group_{group_name_safe}_members")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, f"group_{group_name_safe}_members_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def enum_gpo(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Enumerate Group Policy Objects"""
        Logger.section("Enumerating Group Policy Objects")
        
        # Build commands for GPO enumeration
        commands = ["Get-NetGPO"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="GPO enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="GPO enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "gpo")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "gpo_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def find_local_admin_access(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Find local admin access for current user"""
        Logger.section("Finding Local Admin Access")
        
        # Build commands for local admin access
        commands = ["Find-LocalAdminAccess"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="local admin access enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="local admin access enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "local_admin_access")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "local_admin_access_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def find_domain_shares(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Find domain shares"""
        Logger.section("Finding Domain Shares")
        
        # Build commands for domain shares
        commands = ["Find-DomainShare"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain shares enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain shares enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_shares")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_shares_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def find_interesting_domain_acl(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Find interesting domain ACLs"""
        Logger.section("Finding Interesting Domain ACLs")
        
        # Build commands for domain ACLs
        commands = ["Find-InterestingDomainAcl"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="interesting domain ACL enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="interesting domain ACL enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "interesting_acls")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "interesting_acls_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_output": output, "output_file": str(output_file)}
    
    def get_domain_ou(self, target: str = None, username: str = None, password: str = None) -> Dict[str, Any]:
        """Get domain organizational units"""
        Logger.section("Getting Domain Organizational Units")
        
        # Build commands for domain OUs
        commands = ["Get-NetOU"]
        
        if target and username and password:
            # Remote execution
            Logger.info(f"Executing remotely on {target}")
            output = self.execute_sharpview_remotely(
                target=target, 
                username=username, 
                password=password, 
                commands=commands, 
                description="domain OUs enumeration"
            )
        else:
            # Local execution
            Logger.info("Executing locally")
            output = self.execute_sharpview_locally(
                commands=commands, 
                description="domain OUs enumeration"
            )
        
        # Save the raw output
        target_name = target or "local"
        output_file = self.save_results(target_name, output, "domain_ous")
        
        # Try to parse the output as JSON
        try:
            results = json.loads(output)
            self.save_json_results(target_name, results, "domain_ous_parsed")
            return results
        except json.JSONDecodeError:
            Logger.warning("Could not parse output as JSON")
            return {"raw_