#!/usr/bin/env python3
"""
Patch script to fix the SharpView downloading functionality in sharpview-automator.py.
"""

import re
from pathlib import Path

def patch_sharpview_automator():
    """Update the sharpview-automator.py script to fix SharpView downloading"""
    # Path to the original script
    automator_path = Path("sharpview-automator.py")
    
    if not automator_path.exists():
        print(f"Error: Could not find {automator_path}")
        return False
    
    # Read the original script
    with open(automator_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Create backup
    backup_path = automator_path.with_suffix('.py.bak')
    with open(backup_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Created backup at {backup_path}")
    
    # Fix the SharpView download function in the PowerShell script
    download_function = """
# Function to download SharpView if not available locally
function Get-SharpView {
    param (
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = "$env:TEMP\\SharpView.exe"
    )
    
    if (Test-Path $OutputPath) {
        Write-Output "SharpView already exists at: $OutputPath"
        return $OutputPath
    }
    
    # Create a web client with TLS 1.2 support
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $client = New-Object System.Net.WebClient
    
    # URLs to try (in order)
    $urls = @(
        "https://github.com/tevora-threat/SharpView/releases/download/v2.0/SharpView.exe",
        "https://github.com/dmchell/SharpView/raw/master/SharpView/bin/Debug/SharpView.exe",
        "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/SharpView.exe"
    )
    
    foreach ($url in $urls) {
        try {
            Write-Output "Attempting to download SharpView from: $url"
            $client.DownloadFile($url, $OutputPath)
            
            if (Test-Path $OutputPath) {
                $fileInfo = Get-Item $OutputPath
                if ($fileInfo.Length -gt 1000) {  # Basic check to ensure it's a valid file
                    Write-Output "SharpView downloaded successfully to: $OutputPath"
                    return $OutputPath
                }
                else {
                    Write-Output "Downloaded file appears to be invalid (too small)"
                    Remove-Item $OutputPath -Force
                }
            }
        }
        catch {
            Write-Output "Failed to download from $url`: $_"
        }
    }
    
    # As a fallback, try to use the GitHub API to find the latest release
    try {
        $repoUrl = "https://api.github.com/repos/tevora-threat/SharpView/releases/latest"
        $response = Invoke-RestMethod -Uri $repoUrl -ErrorAction Stop
        
        if ($response.assets.Count -gt 0) {
            $downloadUrl = $response.assets[0].browser_download_url
            Write-Output "Found latest release: $downloadUrl"
            
            $client.DownloadFile($downloadUrl, $OutputPath)
            
            if (Test-Path $OutputPath) {
                Write-Output "SharpView downloaded successfully to: $OutputPath"
                return $OutputPath
            }
        }
    }
    catch {
        Write-Output "Failed to find latest release: $_"
    }
    
    # If all download attempts fail, look for SharpView.exe in common locations
    $commonLocations = @(
        "$PSScriptRoot\\SharpView.exe",
        "C:\\Tools\\SharpView.exe",
        "C:\\Windows\\Temp\\SharpView.exe",
        "$env:USERPROFILE\\Downloads\\SharpView.exe"
    )
    
    foreach ($location in $commonLocations) {
        if (Test-Path $location) {
            Write-Output "Found existing SharpView at: $location"
            Copy-Item $location $OutputPath
            return $OutputPath
        }
    }
    
    Write-Error "Failed to download or find SharpView.exe"
    return $null
}
"""
    
    # Find the old download function and replace it
    old_download_function_pattern = r'# Function to download SharpView if not available locally(.*?)return \$null\s*\}'
    content = re.sub(old_download_function_pattern, download_function, content, flags=re.DOTALL)
    
    # Write the updated content back to the file
    with open(automator_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Updated {automator_path} with improved SharpView download functionality")
    
    # Now create a standalone script to download SharpView if needed
    download_script = """#!/usr/bin/env python3
\"\"\"
Script to download SharpView.exe directly.
\"\"\"

import os
import sys
import requests
from pathlib import Path

def download_sharpview(output_path=None):
    \"\"\"Download SharpView.exe from GitHub\"\"\"
    if output_path is None:
        output_path = Path("SharpView.exe")
    else:
        output_path = Path(output_path)
    
    print(f"Attempting to download SharpView.exe to {output_path}")
    
    # URLs to try (in order)
    urls = [
        "https://github.com/tevora-threat/SharpView/releases/download/v2.0/SharpView.exe",
        "https://github.com/dmchell/SharpView/raw/master/SharpView/bin/Debug/SharpView.exe",
        "https://github.com/PowerShellMafia/PowerSploit/raw/master/Recon/SharpView.exe"
    ]
    
    for url in urls:
        try:
            print(f"Trying URL: {url}")
            response = requests.get(url, stream=True)
            
            if response.status_code == 200:
                # Get file size from headers
                total_size = int(response.headers.get('content-length', 0))
                if total_size < 1000:  # Basic check to ensure it's a valid file
                    print("File appears to be too small, trying next URL...")
                    continue
                
                # Download the file
                with open(output_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                print(f"Successfully downloaded SharpView.exe to {output_path}")
                return True
        except Exception as e:
            print(f"Error downloading from {url}: {str(e)}")
    
    # If direct URLs failed, try GitHub API to find the latest release
    try:
        print("Attempting to find latest release via GitHub API...")
        api_response = requests.get("https://api.github.com/repos/tevora-threat/SharpView/releases/latest")
        
        if api_response.status_code == 200:
            release_data = api_response.json()
            if 'assets' in release_data and len(release_data['assets']) > 0:
                download_url = release_data['assets'][0]['browser_download_url']
                print(f"Found latest release: {download_url}")
                
                file_response = requests.get(download_url, stream=True)
                if file_response.status_code == 200:
                    with open(output_path, 'wb') as f:
                        for chunk in file_response.iter_content(chunk_size=8192):
                            if chunk:
                                f.write(chunk)
                    
                    print(f"Successfully downloaded SharpView.exe to {output_path}")
                    return True
    except Exception as e:
        print(f"Error finding latest release: {str(e)}")
    
    print("Failed to download SharpView.exe from any source.")
    return False

def main():
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    else:
        output_path = "SharpView.exe"
    
    success = download_sharpview(output_path)
    if success:
        print("SharpView.exe downloaded successfully!")
    else:
        print("Failed to download SharpView.exe")
        sys.exit(1)

if __name__ == "__main__":
    main()
"""
    
    # Write the download script
    download_script_path = Path("get-sharpview.py")
    with open(download_script_path, 'w', encoding='utf-8') as f:
        f.write(download_script)
    
    # Make it executable on Unix-like systems
    if os.name != 'nt':
        os.chmod(download_script_path, 0o755)
    
    print(f"Created standalone script to download SharpView: {download_script_path}")
    print("You can run this script directly with: python get-sharpview.py")
    
    return True

def main():
    print("Patching sharpview-automator.py to fix SharpView downloading...")
    if patch_sharpview_automator():
        print("Patch applied successfully!")
        print("You can now use the sharpview-automator.py script with the fixed download functionality.")
        print("Additionally, you can use get-sharpview.py to download SharpView.exe directly.")
    else:
        print("Failed to apply patch.")

if __name__ == "__main__":
    main()