# Run-BloodHoundAnalyzer.ps1
# PowerShell script to set up and run the BloodHound Analyzer

[CmdletBinding()]
param (
    [Parameter()]
    [string]$Neo4jUri = "bolt://localhost:7687",
    
    [Parameter()]
    [string]$Neo4jUser = "neo4j",
    
    [Parameter()]
    [string]$Neo4jPassword = "BloodHound",
    
    [Parameter()]
    [string]$OutputDir = ".\reports",
    
    [Parameter()]
    [switch]$VerifyEnvironment,
    
    [Parameter()]
    [switch]$InstallDependencies,
    
    [Parameter()]
    [switch]$Verbose
)

# Set up logging
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "White" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "SUCCESS" { "Green" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

# Function to check if a command exists
function Test-CommandExists {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Command
    )
    
    $exists = $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
    return $exists
}

# Function to check Python and required packages
function Test-PythonEnvironment {
    # Check if Python is installed
    if (-not (Test-CommandExists "python")) {
        Write-Log "Python is not installed or not in PATH" "ERROR"
        return $false
    }
    
    # Check Python version
    $pythonVersion = python --version 2>&1
    Write-Log "Found $pythonVersion" "INFO"
    
    # Check Neo4j package
    $neo4jInstalled = python -c "import neo4j; print(f'neo4j {neo4j.__version__}')" 2>$null
    
    if ($neo4jInstalled) {
        Write-Log "Found $neo4jInstalled" "SUCCESS"
    } else {
        Write-Log "Neo4j Python package is not installed" "WARNING"
        return $false
    }
    
    return $true
}

# Function to install required packages
function Install-PythonDependencies {
    Write-Log "Installing Python dependencies..." "INFO"
    
    try {
        python -m pip install --upgrade pip
        python -m pip install neo4j
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Dependencies installed successfully" "SUCCESS"
            return $true
        } else {
            Write-Log "Failed to install dependencies" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error installing dependencies: $_" "ERROR"
        return $false
    }
}

# Function to check if BloodHound is running
function Test-BloodHoundRunning {
    try {
        # Try to connect to Neo4j
        $testConnection = python -c "
from neo4j import GraphDatabase
try:
    driver = GraphDatabase.driver('$Neo4jUri', auth=('$Neo4jUser', '$Neo4jPassword'))
    driver.verify_connectivity()
    driver.close()
    print('SUCCESS')
except Exception as e:
    print(f'ERROR: {str(e)}')
"
        
        if ($testConnection -like "SUCCESS*") {
            Write-Log "Successfully connected to BloodHound Neo4j database" "SUCCESS"
            return $true
        } else {
            $errorMsg = $testConnection -replace 'ERROR: ', ''
            Write-Log "Failed to connect to Neo4j: $errorMsg" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error testing Neo4j connection: $_" "ERROR"
        return $false
    }
}

# Function to run the BloodHound Analyzer
function Run-Analyzer {
    # Create output directory if it doesn't exist
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Log "Created output directory: $OutputDir" "INFO"
    }
    
    # Build the command
    $analyzerPath = Join-Path $PSScriptRoot "bloodhound_analyzer.py"
    
    if (-not (Test-Path $analyzerPath)) {
        Write-Log "BloodHound Analyzer script not found at: $analyzerPath" "ERROR"
        Write-Log "Please ensure bloodhound_analyzer.py is in the same directory as this script" "ERROR"
        return $false
    }
    
    $verboseFlag = if ($Verbose) { "--verbose" } else { "" }
    
    $command = "python `"$analyzerPath`" --uri `"$Neo4jUri`" --username `"$Neo4jUser`" --password `"$Neo4jPassword`" --output-dir `"$OutputDir`" $verboseFlag"
    
    # Run the analyzer
    Write-Log "Running BloodHound Analyzer..." "INFO"
    Write-Log "Command: $command" "INFO"
    
    try {
        Invoke-Expression $command
        
        if ($LASTEXITCODE -eq 0) {
            Write-Log "BloodHound Analyzer completed successfully" "SUCCESS"
            return $true
        } else {
            Write-Log "BloodHound Analyzer failed with exit code $LASTEXITCODE" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Error running BloodHound Analyzer: $_" "ERROR"
        return $false
    }
}

# Main script execution
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "            BloodHound Analyzer Runner                " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

# If only environment verification was requested
if ($VerifyEnvironment) {
    Write-Log "Verifying environment..." "INFO"
    $pythonOk = Test-PythonEnvironment
    $bloodhoundOk = Test-BloodHoundRunning
    
    Write-Host ""
    Write-Host "Environment Check Results:" -ForegroundColor Cyan
    Write-Host "- Python Environment: $($pythonOk ? 'OK ✓' : 'Failed ✗')" -ForegroundColor ($pythonOk ? 'Green' : 'Red')
    Write-Host "- BloodHound Neo4j: $($bloodhoundOk ? 'OK ✓' : 'Failed ✗')" -ForegroundColor ($bloodhoundOk ? 'Green' : 'Red')
    
    if (-not $pythonOk -or -not $bloodhoundOk) {
        Write-Host "`nRecommendation:" -ForegroundColor Yellow
        
        if (-not $pythonOk) {
            Write-Host "- Run this script with -InstallDependencies to install required Python packages" -ForegroundColor Yellow
        }
        
        if (-not $bloodhoundOk) {
            Write-Host "- Ensure BloodHound and Neo4j are running" -ForegroundColor Yellow
            Write-Host "- Verify Neo4j credentials (default: neo4j/BloodHound)" -ForegroundColor Yellow
        }
    }
    
    exit
}

# Install dependencies if requested
if ($InstallDependencies) {
    Install-PythonDependencies
    exit
}

# Verify environment before running
$pythonOk = Test-PythonEnvironment
if (-not $pythonOk) {
    Write-Log "Python environment check failed. Run with -InstallDependencies to install required packages." "ERROR"
    exit 1
}

$bloodhoundOk = Test-BloodHoundRunning
if (-not $bloodhoundOk) {
    Write-Log "BloodHound Neo4j connection failed. Ensure BloodHound is running and credentials are correct." "ERROR"
    Write-Log "Default Neo4j credentials are neo4j/BloodHound" "INFO"
    exit 1
}

# Run the analyzer
$success = Run-Analyzer
if (-not $success) {
    exit 1
}

Write-Host ""
Write-Host "======================================================" -ForegroundColor Green
Write-Host "            Analysis Completed Successfully            " -ForegroundColor Green
Write-Host "======================================================" -ForegroundColor Green
Write-Host ""