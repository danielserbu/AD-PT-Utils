#!/usr/bin/env python3
import datetime
from pathlib import Path

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

# Add common utility functions that might be used across scripts
def save_results(output: str, filepath: Path) -> Path:
    """Save command results to a file"""
    with open(filepath, 'w') as f:
        f.write(output)
    
    Logger.success(f"Results saved to {filepath}")
    return filepath

def execute_command(command: str, description: str, log_file: Path = None) -> str:
    """Execute a shell command and return its output"""
    import subprocess
    
    try:
        Logger.command(command)
        
        # Write command to log file if provided
        if log_file:
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] COMMAND: {command}\n")
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout if result.stdout else result.stderr
        
        # Write output to log file if provided
        if log_file:
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] OUTPUT:\n{output}\n")
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
        
        # Write error to log file if provided
        if log_file:
            with open(log_file, 'a') as f:
                f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ERROR: {error_msg}\n")
                f.write("-" * 80 + "\n")
        
        return error_msg