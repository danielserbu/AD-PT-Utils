#!/usr/bin/env python3
"""
Patch script to update tools-installer.py to place batch files in organized directories.
"""

import re
from pathlib import Path

def patch_tools_installer():
    """Update the tools-installer.py script to organize batch files"""
    # Path to the original script
    installer_path = Path("tools-installer.py")
    
    if not installer_path.exists():
        print(f"Error: Could not find {installer_path}")
        return False
    
    # Read the original script
    with open(installer_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create backup
    backup_path = installer_path.with_suffix('.py.bak')
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Created backup at {backup_path}")
    
    # Add code to create wrapper directories
    dirs_init_code = """
        # Create wrappers directories for organized batch files
        self.wrappers_dir = self.base_dir / "wrappers"
        self.wrappers_dir.mkdir(exist_ok=True)
        (self.wrappers_dir / "impacket").mkdir(exist_ok=True)
        (self.wrappers_dir / "bloodhound").mkdir(exist_ok=True)
        (self.wrappers_dir / "mimikatz").mkdir(exist_ok=True)
        (self.wrappers_dir / "utilities").mkdir(exist_ok=True)
        self.bin_dir = self.base_dir / "bin"
        self.bin_dir.mkdir(exist_ok=True)
"""
    
    # Find where to insert the new directories code
    init_match = re.search(r'(self\.logs_dir\.mkdir\(exist_ok=True\)\s+self\.results_dir\.mkdir\(exist_ok=True\))', content)
    if init_match:
        content = content.replace(init_match.group(0), f"{init_match.group(0)}{dirs_init_code}")
    
    # Update batch file creation for impacket tools
    impacket_pattern = r'batch_file = self\.base_dir / "([^"]+\.py)"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(impacket_pattern, 
                    r'batch_file = self.wrappers_dir / "impacket" / "\1"\n        with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for BloodHound
    bloodhound_pattern = r'batch_file = self\.base_dir / "bloodhound\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(bloodhound_pattern, 
                    r'batch_file = self.wrappers_dir / "bloodhound" / "bloodhound.bat"\n            with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for BloodHound Python
    bloodhound_py_pattern = r'batch_file = self\.base_dir / "bloodhound-python\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(bloodhound_py_pattern, 
                    r'batch_file = self.wrappers_dir / "bloodhound" / "bloodhound-python.bat"\n                with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for SharpHound
    sharphound_pattern = r'shutil\.copy\(sharphound_exe, self\.base_dir / "SharpHound\.exe"\)'
    content = re.sub(sharphound_pattern, 
                    r'shutil.copy(sharphound_exe, self.bin_dir / "SharpHound.exe")', 
                    content)
    
    # Update batch file creation for Mimikatz
    mimikatz_pattern = r'batch_file = self\.base_dir / "mimikatz\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(mimikatz_pattern, 
                    r'batch_file = self.wrappers_dir / "mimikatz" / "mimikatz.bat"\n            with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for Responder
    responder_pattern = r'batch_file = self\.base_dir / "responder\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(responder_pattern, 
                    r'batch_file = self.wrappers_dir / "utilities" / "responder.bat"\n            with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for NetExec/CrackMapExec
    netexec_pattern = r'batch_file = self\.base_dir / "netexec\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(netexec_pattern, 
                    r'batch_file = self.wrappers_dir / "utilities" / "netexec.bat"\n            with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for CrackMapExec alias
    cme_pattern = r'batch_file_cme = self\.base_dir / "crackmapexec\.bat"\s+with open\(batch_file_cme, \'w\'\) as f:'
    content = re.sub(cme_pattern, 
                    r'batch_file_cme = self.wrappers_dir / "utilities" / "crackmapexec.bat"\n            with open(batch_file_cme, \'w\') as f:', 
                    content)
    
    # Update batch file creation for enum4linux
    enum4linux_pattern = r'batch_file = self\.base_dir / "enum4linux\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(enum4linux_pattern, 
                    r'batch_file = self.wrappers_dir / "utilities" / "enum4linux.bat"\n            with open(batch_file, \'w\') as f:', 
                    content)
    
    # Update batch file creation for ldapsearch-ad
    ldapsearch_pattern = r'batch_file = self\.base_dir / "ldapsearch-ad\.bat"\s+with open\(batch_file, \'w\'\) as f:'
    content = re.sub(ldapsearch_pattern, 
                    r'batch_file = self.wrappers_dir / "utilities" / "ldapsearch-ad.bat"\n            with open(batch_file, \'w\') as f:', 
                    content)
    
    # Write the updated content back to the file
    with open(installer_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Updated {installer_path} to organize batch files into directories")
    return True

def main():
    print("Patching tools-installer.py to organize batch files...")
    if patch_tools_installer():
        print("Patch applied successfully!")
        print("The next time you run tools-installer.py, batch files will be organized into subdirectories.")
    else:
        print("Failed to apply patch.")

if __name__ == "__main__":
    main()