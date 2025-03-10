#!/usr/bin/env python3
import subprocess
import sys
import os
from pathlib import Path

from utils import Colors, Logger, execute_command, save_results

def print_colored(color, text):
    print(f"{color}{text}{Colors.ENDC}")

def check_tool_exists(tool_name):
    """Check if a tool exists in the system PATH"""
    try:
        result = subprocess.run(f"which {tool_name}", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, result.stdout.strip()
        
        # Try Windows where command
        result = subprocess.run(f"where {tool_name} 2>nul", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            return True, result.stdout.strip()
            
        return False, None
    except Exception:
        return False, None

def check_config_file():
    """Check if config.py exists and has all required variables"""
    if not Path("config.py").exists():
        print_colored(Colors.RED, "Error: config.py not found!")
        return False
    
    try:
        with open("config.py", "r") as f:
            content = f.read()
        
        required_vars = [
            "TARGETS", "DOMAIN_USERS", "DOMAIN_PASSWORDS", "NTLM_HASHES",
            "NETEXEC_SETTINGS", "KERBEROAST_SETTINGS", "BLOODHOUND_SETTINGS",
            "LOG_DIRECTORY", "RESULTS_DIRECTORY", "IMPACKET_SETTINGS"
        ]
        
        missing_vars = []
        for var in required_vars:
            if var not in content:
                missing_vars.append(var)
        
        if missing_vars:
            print_colored(Colors.RED, f"Error: Missing variables in config.py: {', '.join(missing_vars)}")
            return False
        
        print_colored(Colors.GREEN, "Config file exists and contains all required variables")
        return True
    except Exception as e:
        print_colored(Colors.RED, f"Error checking config file: {str(e)}")
        return False

def check_required_directories():
    """Check if required directories exist and create them if not"""
    try:
        # Get settings from config.py
        from config import LOG_DIRECTORY, RESULTS_DIRECTORY
        
        dirs_to_check = [
            LOG_DIRECTORY,
            RESULTS_DIRECTORY,
            f"{RESULTS_DIRECTORY}/kerberoast",
            f"{RESULTS_DIRECTORY}/impacket",
            f"{RESULTS_DIRECTORY}/ad_enumeration",
            f"{RESULTS_DIRECTORY}/mimikatz",
            "scripts",
            "scripts/enumeration"
        ]
        
        for dir_path in dirs_to_check:
            path = Path(dir_path)
            if not path.exists():
                path.mkdir(parents=True)
                print_colored(Colors.YELLOW, f"Created directory: {path}")
            else:
                print_colored(Colors.GREEN, f"Directory exists: {path}")
        
        return True
    except Exception as e:
        print_colored(Colors.RED, f"Error checking directories: {str(e)}")
        return False

def check_required_tools():
    """Check if all required tools are installed"""
    required_tools = [
        "netexec",
        "GetUserSPNs.py",
        "hashcat",
        "BloodHound.py",
        "secretsdump.py",
        "psexec.py",
        "smbclient.py",
        "wmiexec.py",
        "dcomexec.py"
    ]
    
    missing_tools = []
    found_tools = []
    
    for tool in required_tools:
        exists, path = check_tool_exists(tool)
        if exists:
            found_tools.append(f"{tool} ({path})")
        else:
            missing_tools.append(tool)
    
    print_colored(Colors.BLUE, "\n=== Tool Check Results ===")
    
    if found_tools:
        print_colored(Colors.GREEN, "\nFound tools:")
        for tool in found_tools:
            print(f"  - {tool}")
    
    if missing_tools:
        print_colored(Colors.YELLOW, "\nMissing tools (some functionality may be limited):")
        for tool in missing_tools:
            print(f"  - {tool}")
    
    return len(missing_tools) == 0

def check_python_modules():
    """Check if required Python modules are installed"""
    required_modules = [
        "pathlib",
        "datetime",
        "json",
        "base64",
        "re",
        "subprocess",
        "argparse"
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print_colored(Colors.RED, f"\nMissing Python modules: {', '.join(missing_modules)}")
        print("Install them using: pip install " + " ".join(missing_modules))
        return False
    else:
        print_colored(Colors.GREEN, "\nAll required Python modules are installed")
        return True

def main():
    print_colored(Colors.BOLD + Colors.BLUE, "\n=== AD Pentest Toolkit Environment Check ===\n")
    
    # Check Python version
    python_version = sys.version.split()[0]
    print(f"Python version: {python_version}")
    if not python_version.startswith(("3.6", "3.7", "3.8", "3.9", "3.10", "3.11")):
        print_colored(Colors.YELLOW, "Warning: Tested with Python 3.6-3.11. Other versions may not work correctly.")
    
    # Check config file
    config_ok = check_config_file()
    
    # Check required directories
    if config_ok:
        dirs_ok = check_required_directories()
    else:
        dirs_ok = False
        print_colored(Colors.YELLOW, "Skipping directory check due to config file issues.")
    
    # Check required tools
    tools_ok = check_required_tools()
    
    # Check Python modules
    modules_ok = check_python_modules()
    
    # Summary
    print_colored(Colors.BOLD + Colors.BLUE, "\n=== Environment Check Summary ===")
    print(f"Config file: {'✅' if config_ok else '❌'}")
    print(f"Directories: {'✅' if dirs_ok else '❌'}")
    print(f"Tools: {'✅' if tools_ok else '⚠️'}")
    print(f"Python modules: {'✅' if modules_ok else '❌'}")
    
    if config_ok and dirs_ok and tools_ok and modules_ok:
        print_colored(Colors.GREEN, "\nEnvironment is ready for AD Pentest Toolkit!")
    else:
        print_colored(Colors.YELLOW, "\nSome issues need to be addressed before the toolkit can function properly.")

if __name__ == "__main__":
    main()