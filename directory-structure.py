#!/usr/bin/env python3
"""
Script to create an organized directory structure for the AD Pentest Toolkit
and move batch files to appropriate locations.
"""

import os
import shutil
from pathlib import Path

def create_directory_structure():
    """Create an organized directory structure for the toolkit"""
    # Base directory is the current directory
    base_dir = Path.cwd()
    
    # Create main directories if they don't exist
    directories = {
        "wrappers": {
            "impacket": None,
            "bloodhound": None,
            "mimikatz": None,
            "utilities": None
        },
        "bin": None,
        "scripts": {
            "enumeration": None,
            "credentials": None,
            "lateral": None,
            "persistence": None
        }
    }
    
    # Create the directory structure
    for dir_name, subdirs in directories.items():
        dir_path = base_dir / dir_name
        dir_path.mkdir(exist_ok=True)
        print(f"Created directory: {dir_path}")
        
        if subdirs:
            for subdir_name, subsubdirs in subdirs.items():
                subdir_path = dir_path / subdir_name
                subdir_path.mkdir(exist_ok=True)
                print(f"Created directory: {subdir_path}")
                
                if subsubdirs:
                    for subsubdir_name in subsubdirs:
                        subsubdir_path = subdir_path / subsubdir_name
                        subsubdir_path.mkdir(exist_ok=True)
                        print(f"Created directory: {subsubdir_path}")

def move_batch_files():
    """Move batch files to appropriate directories"""
    base_dir = Path.cwd()
    
    # Mapping of batch files to their target directories
    batch_mapping = {
        # Impacket tools
        "secretsdump.py": "wrappers/impacket",
        "GetUserSPNs.py": "wrappers/impacket",
        "GetNPUsers.py": "wrappers/impacket",
        "psexec.py": "wrappers/impacket",
        "wmiexec.py": "wrappers/impacket",
        "smbclient.py": "wrappers/impacket",
        
        # BloodHound tools
        "bloodhound.bat": "wrappers/bloodhound",
        "bloodhound-python.bat": "wrappers/bloodhound",
        "sharphound.bat": "wrappers/bloodhound",
        
        # Mimikatz tools
        "mimikatz.bat": "wrappers/mimikatz",
        
        # Utility tools
        "responder.bat": "wrappers/utilities",
        "ldapsearch-ad.bat": "wrappers/utilities",
        "enum4linux.bat": "wrappers/utilities",
        "netexec.bat": "wrappers/utilities",
        "crackmapexec.bat": "wrappers/utilities"
    }
    
    # Move batch files
    moved_files = []
    not_found_files = []
    
    for batch_file, target_dir in batch_mapping.items():
        source_path = base_dir / batch_file
        target_path = base_dir / target_dir / batch_file
        
        if source_path.exists():
            # Create target directory if it doesn't exist
            target_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Copy the file to the target directory
            shutil.copy2(source_path, target_path)
            print(f"Copied: {source_path} -> {target_path}")
            
            # For safety, don't delete the originals in this script
            # You can manually delete them after verifying everything works
            moved_files.append(batch_file)
        else:
            not_found_files.append(batch_file)
    
    print(f"\nSuccessfully copied {len(moved_files)} batch files")
    if not_found_files:
        print(f"Could not find {len(not_found_files)} batch files: {', '.join(not_found_files)}")
    
    print("\nIMPORTANT: The original files were not deleted for safety.")
    print("After verifying the copies work, you can manually delete the originals.")

def create_path_script():
    """Create a script to add the wrappers directories to the PATH"""
    base_dir = Path.cwd()
    
    # Create batch script for Windows
    with open(base_dir / "setup_path.bat", "w") as f:
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
            full_path = base_dir / dir_path
            f.write(f'set "PATH=%PATH%;{full_path}"\n')
        
        f.write("\necho Directories added to PATH for this session.\n")
        f.write("echo To make this permanent, update your system PATH environment variable.\n")
    
    print(f"Created PATH setup script: {base_dir / 'setup_path.bat'}")
    
    # Create shell script for Linux/macOS
    with open(base_dir / "setup_path.sh", "w") as f:
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
        
        for dir_path in wrapper_dirs:
            full_path = base_dir / dir_path
            f.write(f'export PATH="$PATH:{full_path}"\n')
        
        f.write("\necho Directories added to PATH for this session.\n")
        f.write("echo To make this permanent, add these lines to your .bashrc or .zshrc file.\n")
    
    # Make the shell script executable
    os.chmod(base_dir / "setup_path.sh", 0o755)
    print(f"Created PATH setup script: {base_dir / 'setup_path.sh'}")

def main():
    print("Creating organized directory structure for AD Pentest Toolkit...")
    create_directory_structure()
    
    print("\nMoving batch files to appropriate directories...")
    move_batch_files()
    
    print("\nCreating PATH setup scripts...")
    create_path_script()
    
    print("\nDirectory reorganization complete!")
    print("Run setup_path.bat (Windows) or source setup_path.sh (Linux/macOS) to update your PATH for this session.")

if __name__ == "__main__":
    main()