#!/usr/bin/env python3
"""
Fix Paths Script for AD Pentest Toolkit

This script updates all the tool scripts in the toolkit to use correct local paths
rather than requiring tools to be in the system PATH.
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

# ANSI color codes for terminal output
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

def print_header(text: str):
    """Print a formatted header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{text}{Colors.ENDC}")

def print_success(text: str):
    """Print a success message"""
    print(f"{Colors.GREEN}[+] {text}{Colors.ENDC}")

def print_info(text: str):
    """Print an informational message"""
    print(f"{Colors.BLUE}[*] {text}{Colors.ENDC}")

def print_warning(text: str):
    """Print a warning message"""
    print(f"{Colors.YELLOW}[!] {text}{Colors.ENDC}")

def print_error(text: str):
    """Print an error message"""
    print(f"{Colors.RED}[-] {text}{Colors.ENDC}")

def find_toolkit_scripts(base_dir: Path) -> List[Path]:
    """Find all Python scripts that are part of the toolkit"""
    toolkit_scripts = [
        "netexec-enumerator.py",
        "kerberoast.py",
        "impacket-toolkit.py",
        "powershell-enumeration.py",
        "mimikatz-wrapper.py",
        "sharpview-automator.py",
        "adpentest-toolkit.py",
        "ad-autorecon.py",
        "bloodhound_analyzer.py",
        "ad-pentest-workflow.py",
        "check-environment.py"
    ]
    
    found_scripts = []
    for script in toolkit_scripts:
        script_path = base_dir / script
        if script_path.exists():
            found_scripts.append(script_path)
    
    return found_scripts

def find_tool_paths(base_dir: Path) -> Dict[str, Path]:
    """Find the paths to common AD pentest tools"""
    tools_dir = base_dir / "tools"
    
    # Initialize with default relative paths to common tools
    tool_paths = {
        # Impacket tools
        "secretsdump.py": tools_dir / "impacket" / "examples" / "secretsdump.py",
        "GetUserSPNs.py": tools_dir / "impacket" / "examples" / "GetUserSPNs.py",
        "GetNPUsers.py": tools_dir / "impacket" / "examples" / "GetNPUsers.py",
        "smbclient.py": tools_dir / "impacket" / "examples" / "smbclient.py",
        "psexec.py": tools_dir / "impacket" / "examples" / "psexec.py",
        "wmiexec.py": tools_dir / "impacket" / "examples" / "wmiexec.py",
        "dcomexec.py": tools_dir / "impacket" / "examples" / "dcomexec.py",
        
        # NetExec
        "netexec": tools_dir / "netexec" / "netexec.exe" if os.name == "nt" else tools_dir / "netexec" / "netexec",
        "crackmapexec": tools_dir / "netexec" / "netexec.exe" if os.name == "nt" else tools_dir / "netexec" / "netexec",
        
        # BloodHound
        "bloodhound-python": tools_dir / "BloodHound.py" / "bloodhound.py",
        "SharpHound.exe": base_dir / "SharpHound.exe",
        
        # Other tools
        "mimikatz.exe": tools_dir / "mimikatz" / "x64" / "mimikatz.exe",
        "SharpView.exe": base_dir / "SharpView.exe",
        "enum4linux": tools_dir / "enum4linux" / "enum4linux.pl",
        "responder": tools_dir / "Responder" / "Responder.py",
        "ldapsearch-ad": tools_dir / "ldapsearch-ad" / "ldapsearch-ad.py"
    }
    
    # Find actual paths by checking standard locations
    actual_paths = {}
    for tool_name, default_path in tool_paths.items():
        # First check if the default path exists
        if default_path.exists():
            actual_paths[tool_name] = default_path
            continue
        
        # If not, search in the tools directory
        found = False
        for file_path in tools_dir.glob(f"**/{tool_name}"):
            if file_path.exists() and file_path.is_file():
                actual_paths[tool_name] = file_path
                found = True
                break
        
        # As a last resort, check if it's in the base directory
        if not found:
            base_tool_path = base_dir / tool_name
            if base_tool_path.exists():
                actual_paths[tool_name] = base_tool_path
                found = True
        
        # If still not found, keep the default path
        if not found:
            actual_paths[tool_name] = default_path
            print_warning(f"Could not find actual path for {tool_name}. Using default: {default_path}")
    
    return actual_paths

def update_script_paths(script_path: Path, tool_paths: Dict[str, Path], dry_run: bool = False) -> bool:
    """Update a script to use the correct tool paths"""
    print_info(f"Processing script: {script_path.name}")
    
    # Read the script content
    with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Original content for comparison
    original_content = content
    
    # Patterns to search for:
    # 1. Direct tool calls in execute_command or subprocess.run
    # 2. Tool path definitions or assignments
    # 3. Direct command strings with tool names
    
    modified = False
    
    # For each tool, replace instances of the tool name with the full path
    for tool_name, tool_path in tool_paths.items():
        # Patterns for different ways tools might be called
        patterns = [
            # Direct command execution
            (rf'execute_command\(["\']({re.escape(tool_name)}[^"\']*)["\']', f'execute_command("{tool_path}\\1"'),
            (rf'subprocess\.run\(["\']({re.escape(tool_name)}[^"\']*)["\']', f'subprocess.run("{tool_path}\\1"'),
            (rf'subprocess\.Popen\(["\']({re.escape(tool_name)}[^"\']*)["\']', f'subprocess.Popen("{tool_path}\\1"'),
            
            # Shell=True variant with command as first element
            (rf'subprocess\.run\(\["{re.escape(tool_name)}', f'subprocess.run(["{tool_path}'),
            (rf'subprocess\.Popen\(\["{re.escape(tool_name)}', f'subprocess.Popen(["{tool_path}'),
            
            # Command string assignments
            (rf'command\s*=\s*["\']({re.escape(tool_name)}[^"\']*)["\']', f'command = "{tool_path}\\1"'),
            (rf'cmd\s*=\s*["\']({re.escape(tool_name)}[^"\']*)["\']', f'cmd = "{tool_path}\\1"'),
            
            # Self path assignments for tools
            (rf'self\.{tool_name.replace(".", "_").replace("-", "_")}_path\s*=\s*["\'][^"\']*["\']', f'self.{tool_name.replace(".", "_").replace("-", "_")}_path = "{tool_path}"'),
            
            # Path lookups
            (rf'path\s*=\s*["\']({re.escape(tool_name)})["\']', f'path = "{tool_path}"'),
        ]
        
        # Apply each pattern
        for pattern, replacement in patterns:
            new_content = re.sub(pattern, replacement, content)
            if new_content != content:
                content = new_content
                modified = True
    
    # Handle special cases where tools are referenced by variables
    impacket_tools = ["secretsdump.py", "GetUserSPNs.py", "GetNPUsers.py", "psexec.py", "wmiexec.py", "smbclient.py"]
    for tool in impacket_tools:
        if tool in tool_paths:
            # Replace variable assignments that might reference the tool
            tool_var = tool.replace('.py', '').lower()
            pattern = rf'{tool_var}_path\s*=\s*["\'][^"\']*["\']'
            replacement = f'{tool_var}_path = "{tool_paths[tool]}"'
            new_content = re.sub(pattern, replacement, content)
            if new_content != content:
                content = new_content
                modified = True
    
    # If modified and not in dry run mode, write back the changes
    if modified and not dry_run:
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print_success(f"Updated paths in {script_path.name}")
        return True
    elif modified:
        print_info(f"Would update paths in {script_path.name} (dry run)")
        return True
    else:
        print_info(f"No path updates needed in {script_path.name}")
        return False

def create_tool_path_module(base_dir: Path, tool_paths: Dict[str, Path], dry_run: bool = False) -> None:
    """Create a Python module with all tool paths for easy import in scripts"""
    tool_paths_py = base_dir / "tool_paths.py"
    
    content = """#!/usr/bin/env python3
\"\"\"
Tool Paths Module for AD Pentest Toolkit

This module contains the paths to all tools used by the toolkit.
It is automatically generated by the fix-paths.py script.
\"\"\"

from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.absolute()
TOOLS_DIR = BASE_DIR / "tools"

# Tool paths
TOOL_PATHS = {
"""
    
    # Add each tool path
    for tool_name, tool_path in sorted(tool_paths.items()):
        relative_path = tool_path.relative_to(base_dir) if tool_path.is_relative_to(base_dir) else tool_path
        content += f'    "{tool_name}": BASE_DIR / "{relative_path}",\n'
    
    content += """
}

# Function to get a tool path
def get_tool_path(tool_name):
    \"\"\"Get the path to a tool\"\"\"
    if tool_name in TOOL_PATHS:
        return TOOL_PATHS[tool_name]
    else:
        raise ValueError(f"Tool {tool_name} not found in TOOL_PATHS")

# Common tool variables for easy import
"""
    
    # Add variables for common tools
    for tool_name, tool_path in sorted(tool_paths.items()):
        var_name = tool_name.replace('.', '_').replace('-', '_').upper() + "_PATH"
        content += f"{var_name} = TOOL_PATHS[\"{tool_name}\"]\n"
    
    if not dry_run:
        with open(tool_paths_py, 'w', encoding='utf-8') as f:
            f.write(content)
        print_success(f"Created tool paths module at {tool_paths_py}")
    else:
        print_info(f"Would create tool paths module at {tool_paths_py} (dry run)")

def create_tool_path_importer(base_dir: Path, tool_paths: Dict[str, Path], dry_run: bool = False) -> None:
    """Create a Python script to patch sys.path in other scripts"""
    importer_py = base_dir / "add_tool_paths_to_path.py"
    
    content = """#!/usr/bin/env python3
\"\"\"
Tool Paths Importer for AD Pentest Toolkit

This module adds tool directories to sys.path.
It can be imported at the beginning of scripts to ensure tools are available.
\"\"\"

import sys
import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).parent.absolute()
TOOLS_DIR = BASE_DIR / "tools"

# Add common tool directories to path
paths_to_add = [
    str(BASE_DIR),
"""
    
    # Add each unique directory containing tools
    tool_dirs = set()
    for tool_path in tool_paths.values():
        if tool_path.exists():
            tool_dir = tool_path.parent
            if tool_dir.is_relative_to(base_dir):
                relative_dir = tool_dir.relative_to(base_dir)
                tool_dirs.add(str(relative_dir))
    
    for tool_dir in sorted(tool_dirs):
        content += f'    str(BASE_DIR / "{tool_dir}"),\n'
    
    content += """
]

# Add paths to sys.path if not already present
for path in paths_to_add:
    if path not in sys.path:
        sys.path.insert(0, path)

print(f"Added {len(paths_to_add)} tool directories to sys.path")
"""
    
    if not dry_run:
        with open(importer_py, 'w', encoding='utf-8') as f:
            f.write(content)
        print_success(f"Created tool path importer at {importer_py}")
    else:
        print_info(f"Would create tool path importer at {importer_py} (dry run)")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Fix tool paths in AD Pentest Toolkit scripts")
    parser.add_argument("--dir", "-d", help="Base directory for the toolkit", default=".")
    parser.add_argument("--dry-run", "-n", action="store_true", help="Don't modify files, just show what would be done")
    
    args = parser.parse_args()
    
    base_dir = Path(args.dir).absolute()
    
    print_header(f"AD Pentest Toolkit Path Fixer")
    print_info(f"Base directory: {base_dir}")
    
    if args.dry_run:
        print_info("Dry run mode - no files will be modified")
    
    # Find toolkit scripts
    scripts = find_toolkit_scripts(base_dir)
    print_info(f"Found {len(scripts)} toolkit scripts")
    
    # Find tool paths
    tool_paths = find_tool_paths(base_dir)
    print_info(f"Found {len(tool_paths)} tool paths")
    
    # Update scripts
    updated_count = 0
    for script in scripts:
        if update_script_paths(script, tool_paths, args.dry_run):
            updated_count += 1
    
    # Create tool paths module
    create_tool_path_module(base_dir, tool_paths, args.dry_run)
    
    # Create tool path importer
    create_tool_path_importer(base_dir, tool_paths, args.dry_run)
    
    # Summary
    print_header("Summary")
    if args.dry_run:
        print_info(f"Would update {updated_count} out of {len(scripts)} scripts")
        print_info("Run without --dry-run to apply changes")
    else:
        print_success(f"Updated {updated_count} out of {len(scripts)} scripts")
        print_success("Created tool paths module and importer")
        print_info("You can now import tool_paths.py in your scripts to get tool paths")

if __name__ == "__main__":
    main()