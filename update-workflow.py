#!/usr/bin/env python3
"""
Script to update the AD-Pentest-Workflow to properly find tools in their new locations.
"""

import os
import re
from pathlib import Path

def update_tool_paths_in_workflow():
    """Update the ad-pentest-workflow.py script to find tools in their new locations"""
    # Path to the workflow script
    workflow_path = Path("ad-pentest-workflow.py")
    
    if not workflow_path.exists():
        print(f"Error: Could not find {workflow_path}")
        return False
    
    # Read the original script
    with open(workflow_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create backup
    backup_path = workflow_path.with_suffix('.py.bak')
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Created backup at {backup_path}")
    
    # Add tool path resolution code to use wrappers directory
    tool_path_resolver = """
    def _resolve_tool_path(self, tool_name: str) -> Path:
        """Resolve the path to a tool based on its name"""
        # Check explicit tool_paths.py if it exists
        tool_paths_py = self.script_dir / "tool_paths.py"
        if tool_paths_py.exists():
            try:
                sys.path.insert(0, str(self.script_dir))
                from tool_paths import TOOL_PATHS
                if tool_name in TOOL_PATHS:
                    return TOOL_PATHS[tool_name]
            except ImportError:
                Logger.warning("Failed to import tool_paths.py")
        
        # Check in wrappers directories based on tool type
        if tool_name in ["secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py", 
                         "psexec.py", "wmiexec.py", "smbclient.py"]:
            wrapper_path = self.script_dir / "wrappers" / "impacket" / tool_name
            if wrapper_path.exists():
                return wrapper_path
        
        elif tool_name in ["bloodhound-python.py", "bloodhound.py"]:
            wrapper_path = self.script_dir / "wrappers" / "bloodhound" / f"{tool_name.split('.')[0]}.bat"
            if wrapper_path.exists():
                return wrapper_path
        
        elif tool_name == "mimikatz.exe":
            wrapper_path = self.script_dir / "wrappers" / "mimikatz" / "mimikatz.bat"
            if wrapper_path.exists():
                return wrapper_path
        
        elif tool_name in ["responder.py", "ldapsearch-ad.py", "enum4linux.pl", "netexec", "crackmapexec"]:
            wrapper_name = tool_name.split('.')[0]
            wrapper_path = self.script_dir / "wrappers" / "utilities" / f"{wrapper_name}.bat"
            if wrapper_path.exists():
                return wrapper_path
        
        # Check in bin directory
        bin_path = self.script_dir / "bin" / tool_name
        if bin_path.exists():
            return bin_path
        
        # Check in common locations
        common_locations = [
            self.script_dir / tool_name,
            self.script_dir / "tools" / tool_name,
            self.script_dir.parent / "tools" / tool_name
        ]
        
        for location in common_locations:
            if location.exists():
                return location
        
        # If not found, return the tool name and hope it's in PATH
        return Path(tool_name)
    """
    
    # Find where to insert the tool path resolver
    init_match = re.search(r'def verify_tools\(self\).*?return all_tools_found', content, re.DOTALL)
    if init_match:
        # Insert after the verify_tools method
        insert_point = init_match.end()
        content = content[:insert_point] + tool_path_resolver + content[insert_point:]
    
    # Update the execute_command method to use _resolve_tool_path
    execute_cmd_pattern = r'(def execute_command\(self, command: str, description: str\) -> str:.*?try:.*?)(Logger\.command\(command\))'
    execute_cmd_replacement = r'\1# Resolve tool paths in command\n        for tool in ["secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py", "psexec.py", "wmiexec.py", "smbclient.py", "bloodhound-python", "mimikatz.exe", "netexec", "crackmapexec", "enum4linux", "ldapsearch-ad"]:\n            if tool in command:\n                resolved_path = self._resolve_tool_path(tool)\n                command = command.replace(tool, str(resolved_path))\n        \n        \2'
    
    content = re.sub(execute_cmd_pattern, execute_cmd_replacement, content, flags=re.DOTALL)
    
    # Update tool initializations to use _resolve_tool_path
    init_tools_pattern = r'(# Initialize the tools paths\s+)(self\.netexec_script = self\.script_dir / "netexec-enumerator\.py".*?self\.adpentest_script = self\.script_dir / "adpentest-toolkit\.py")'
    init_tools_replacement = r'\1self.netexec_script = self.script_dir / "netexec-enumerator.py"\n        self.kerberoast_script = self.script_dir / "kerberoast.py"\n        self.impacket_script = self.script_dir / "impacket-toolkit.py"\n        self.powershell_script = self.script_dir / "powershell-enumeration.py"\n        self.sharpview_script = self.script_dir / "sharpview-automator.py"\n        self.mimikatz_script = self.script_dir / "mimikatz-wrapper.py"\n        self.adpentest_script = self.script_dir / "adpentest-toolkit.py"\n        \n        # Also resolve paths for external tools\n        self.netexec_path = self._resolve_tool_path("netexec")\n        self.psexec_path = self._resolve_tool_path("psexec.py")\n        self.wmiexec_path = self._resolve_tool_path("wmiexec.py")\n        self.mimikatz_path = self._resolve_tool_path("mimikatz.exe")\n        self.bloodhound_path = self._resolve_tool_path("bloodhound-python")'
    
    content = re.sub(init_tools_pattern, init_tools_replacement, content, flags=re.DOTALL)
    
    # Add imports if not already present
    if "import sys" not in content:
        import_pattern = r'(import os\s+)'
        content = re.sub(import_pattern, r'\1import sys\n', content)
    
    # Write the updated content back to the file
    with open(workflow_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Updated {workflow_path} to properly find tools in their new locations")
    return True

def update_tool_paths_in_all_scripts():
    """Update all scripts to properly find tools in their new locations"""
    scripts = [
        "netexec-enumerator.py",
        "kerberoast.py", 
        "impacket-toolkit.py",
        "powershell-enumeration.py",
        "mimikatz-wrapper.py",
        "sharpview-automator.py",
        "adpentest-toolkit.py",
        "ad-autorecon.py"
    ]
    
    updated_scripts = []
    
    for script_name in scripts:
        script_path = Path(script_name)
        if not script_path.exists():
            print(f"Warning: Could not find {script_path}")
            continue
        
        try:
            # Read the script
            with open(script_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create backup
            backup_path = script_path.with_suffix('.py.bak')
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            # Add code to look for tools in the wrappers directory
            wrappers_code = """
# Try to find tools in the wrappers directory
def find_tool(tool_name):
    """Find a tool in the wrappers directory or common locations"""
    script_dir = Path(__file__).parent.absolute()
    
    # Check in wrappers directories based on tool type
    if tool_name in ["secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py", 
                     "psexec.py", "wmiexec.py", "smbclient.py"]:
        wrapper_path = script_dir / "wrappers" / "impacket" / tool_name
        if wrapper_path.exists():
            return str(wrapper_path)
    
    elif tool_name in ["bloodhound-python", "bloodhound"]:
        wrapper_path = script_dir / "wrappers" / "bloodhound" / f"{tool_name}.bat"
        if wrapper_path.exists():
            return str(wrapper_path)
    
    elif tool_name == "mimikatz":
        wrapper_path = script_dir / "wrappers" / "mimikatz" / "mimikatz.bat"
        if wrapper_path.exists():
            return str(wrapper_path)
    
    elif tool_name in ["responder", "ldapsearch-ad", "enum4linux", "netexec", "crackmapexec"]:
        wrapper_path = script_dir / "wrappers" / "utilities" / f"{tool_name}.bat"
        if wrapper_path.exists():
            return str(wrapper_path)
    
    # Check in bin directory
    bin_path = script_dir / "bin" / tool_name
    if bin_path.exists():
        return str(bin_path)
    
    # Just return the tool name if not found (assume it's in PATH)
    return tool_name
"""
            
            # Add the find_tool function if it's not already there
            if "def find_tool(tool_name):" not in content:
                # Find import section to add after
                import_match = re.search(r'from utils import.*?\n', content)
                if import_match:
                    insert_point = import_match.end()
                    content = content[:insert_point] + wrappers_code + content[insert_point:]
            
            # Update common tool command patterns
            tool_patterns = [
                (r'([\"\'])secretsdump\.py([\"\'])', r'\1' + 'find_tool("secretsdump.py")' + r'\2'),
                (r'([\"\'])GetUserSPNs\.py([\"\'])', r'\1' + 'find_tool("GetUserSPNs.py")' + r'\2'),
                (r'([\"\'])GetNPUsers\.py([\"\'])', r'\1' + 'find_tool("GetNPUsers.py")' + r'\2'),
                (r'([\"\'])psexec\.py([\"\'])', r'\1' + 'find_tool("psexec.py")' + r'\2'),
                (r'([\"\'])wmiexec\.py([\"\'])', r'\1' + 'find_tool("wmiexec.py")' + r'\2'),
                (r'([\"\'])smbclient\.py([\"\'])', r'\1' + 'find_tool("smbclient.py")' + r'\2'),
                (r'([\"\'])bloodhound-python([\"\'])', r'\1' + 'find_tool("bloodhound-python")' + r'\2'),
                (r'([\"\'])netexec([\"\'])', r'\1' + 'find_tool("netexec")' + r'\2'),
                (r'([\"\'])mimikatz\.exe([\"\'])', r'\1' + 'find_tool("mimikatz")' + r'\2')
            ]
            
            # Apply each pattern
            for pattern, replacement in tool_patterns:
                content = re.sub(pattern, replacement, content)
            
            # Write the updated content back to the file
            with open(script_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            print(f"Updated {script_path} to use find_tool for locating tools")
            updated_scripts.append(script_name)
            
        except Exception as e:
            print(f"Error updating {script_path}: {e}")
    
    print(f"Updated {len(updated_scripts)} scripts to find tools in their new locations")
    return updated_scripts

def create_path_script():
    """Create a script to add the wrappers directories to the PATH"""
    # Create batch script for Windows
    with open("setup_path.bat", "w") as f:
        f.write("@echo off\n")
        f.write("echo Adding toolkit directories to PATH...\n\n")
        
        # Add each wrapper directory to the PATH
        wrapper_dirs = [
            "wrappers\\impacket",
            "wrappers\\bloodhound",
            "wrappers\\mimikatz",
            "wrappers\\utilities",
            "bin"
        ]
        
        for dir_path in wrapper_dirs:
            full_path = "%~dp0" + dir_path  # %~dp0 expands to the script's directory
            f.write(f'set "PATH=%PATH%;{full_path}"\n')
        
        f.write("\necho Directories added to PATH for this session.\n")
        f.write("echo To make this permanent, update your system PATH environment variable.\n")
    
    print(f"Created PATH setup script: setup_path.bat")
    
    # Create shell script for Linux/macOS
    with open("setup_path.sh", "w") as f:
        f.write("#!/bin/bash\n")
        f.write("echo Adding toolkit directories to PATH...\n\n")
        
        # Add each wrapper directory to the PATH
        wrapper_dirs = [
            "wrappers/impacket",
            "wrappers/bloodhound",
            "wrappers/mimikatz",
            "wrappers/utilities",
            "bin"
        ]
        
        script_dir = '$(dirname "$(readlink -f "$0")")'
        for dir_path in wrapper_dirs:
            f.write(f'export PATH="$PATH:{script_dir}/{dir_path}"\n')
        
        f.write("\necho Directories added to PATH for this session.\n")
        f.write("echo To make this permanent, add these lines to your .bashrc or .zshrc file.\n")
    
    # Make the shell script executable on Unix-like systems
    if os.name != 'nt':
        os.chmod("setup_path.sh", 0o755)
    
    print(f"Created PATH setup script: setup_path.sh")

def main():
    print("Updating AD-Pentest-Workflow and other scripts to find tools in their new locations...")
    
    # Update the workflow script
    if update_tool_paths_in_workflow():
        print("Successfully updated ad-pentest-workflow.py")
    else:
        print("Failed to update ad-pentest-workflow.py")
    
    # Update other scripts
    updated_scripts = update_tool_paths_in_all_scripts()
    
    # Create path setup scripts
    create_path_script()
    
    print("\nUpdate complete!")
    print("To use the updated scripts:")
    print("1. Run 'setup_path.bat' (Windows) or 'source setup_path.sh' (Linux/macOS) to add wrappers to your PATH")
    print("2. Use the ad-pentest-workflow.py script as before - it will find tools in their new locations")
    print("3. If tools are still not found, make sure they are installed in the expected locations")

if __name__ == "__main__":
    main()