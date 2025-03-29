<#
.SYNOPSIS
    Manages Windows Updates on local or remote computers.

.DESCRIPTION
    This script provides functionality to check, install, and schedule Windows Updates.
    It requires administrative privileges and uses the PSWindowsUpdate module to interact
    with Windows Update services. The script can check for available updates, install updates
    immediately, or schedule updates for a later time.

.PARAMETER Install
    Switch parameter to trigger the installation of available Windows updates.

.PARAMETER Schedule
    Specifies a date and time when updates should be installed.
    Format: "MM/dd/yyyy HH:mm:ss" (e.g., "12/31/2023 23:59:59")

.PARAMETER RebootPolicy
    Specifies the reboot behavior after updates are installed.
    Accepted values: "Never", "IfRequired", "Always"

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1
    Checks for available Windows Updates and displays them.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Install -RebootPolicy "IfRequired"
    Installs all available Windows Updates and reboots if required.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Schedule "12/31/2023 23:59:59" -RebootPolicy "Never"
    Schedules Windows Updates to be installed on December 31, 2023 at 11:59:59 PM without rebooting.

.NOTES
    File Name      : Manage-WindowsUpdates.ps1
    Prerequisite   : PowerShell 5.1 or later, PSWindowsUpdate module, Administrative privileges
    Author         : AdminToolkit
    Version        : 1.0
#>

[CmdletBinding(DefaultParameterSetName = "Check")]
param (
    [Parameter(ParameterSetName = "Install", Mandatory = $false)]
    [switch]$Install,
    
    [Parameter(ParameterSetName = "Schedule", Mandatory = $true)]
    [datetime]$Schedule,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Never", "IfRequired", "Always")]
    [string]$RebootPolicy = "Never"
)

# Set up logging
$LogPath = Join-Path -Path $env:TEMP -ChildPath "WindowsUpdates_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ErrorActionPreference = "Stop"

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$Level] $Message"
    
    # Output to console with appropriate color
    switch ($Level) {
        "Info"    { Write-Host $LogMessage -ForegroundColor Green }
        "Warning" { Write-Host $LogMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $LogMessage -ForegroundColor Red }
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $LogMessage
}

function Test-AdminPrivileges {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "This script requires administrative privileges. Please restart PowerShell as Administrator." -Level "Error"
        return $false
    }
    
    Write-Log "Administrative privileges confirmed." -Level "Info"
    return $true
}

function Test-WindowsUpdateService {
    try {
        $service = Get-Service -Name "wuauserv" -ErrorAction Stop
        
        if ($service.Status -ne "Running") {
            Write-Log "Windows Update service is not running. Attempting to start..." -Level "Warning"
            Start-Service -Name "wuauserv" -ErrorAction Stop
            Write-Log "Windows Update service started successfully." -Level "Info"
        } else {
            Write-Log "Windows Update service is running." -Level "Info"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to check or start Windows Update service: $_" -Level "Error"
        return $false
    }
}

function Test-PSWindowsUpdateModule {
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Log "PSWindowsUpdate module not found. Attempting to install..." -Level "Warning"
            Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -ErrorAction Stop
            Write-Log "PSWindowsUpdate module installed successfully." -Level "Info"
        } else {
            Write-Log "PSWindowsUpdate module is already installed." -Level "Info"
        }
        
        # Import the module
        Import-Module -Name PSWindowsUpdate -ErrorAction Stop
        Write-Log "PSWindowsUpdate module imported successfully." -Level "Info"
        
        return $true
    }
    catch {
        Write-Log "Failed to install or import PSWindowsUpdate module: $_" -Level "Error"
        return $false
    }
}

function Get-AvailableUpdates {
    try {
        Write-Log "Checking for available Windows Updates..." -Level "Info"
        $updates = Get-WindowsUpdate -ErrorAction Stop
        
        if ($updates.Count -eq 0) {
            Write-Log "No updates available." -Level "Info"
        } else {
            Write-Log "Found $($updates.Count) update(s) available:" -Level "Info"
            foreach ($update in $updates) {
                Write-Log "  - $($update.Title) [KB$($update.KB)]" -Level "Info"
            }
        }
        
        return $updates
    }
    catch {
        Write-Log "Failed to check for available updates: $_" -Level "Error"
        return $null
    }
}

function Install-PendingUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Never", "IfRequired", "Always")]
        [string]$RebootPolicy
    )
    
    try {
        Write-Log "Installing Windows Updates..." -Level "Info"
        
        # Convert RebootPolicy to appropriate parameters for Install-WindowsUpdate
        $rebootParam = switch ($RebootPolicy) {
            "Never" { "-AutoReboot:$false" }
            "IfRequired" { "-AutoReboot:$true" }
            "Always" { "-AutoReboot:$true -ForceReboot:$true" }
        }
        
        # Using Invoke-Expression to handle the dynamic parameters
        $command = "Install-WindowsUpdate -AcceptAll -IgnoreReboot:$($RebootPolicy -eq 'Never') -AutoReboot:$($RebootPolicy -ne 'Never') -ForceReboot:$($RebootPolicy -eq 'Always') -Verbose"
        Write-Log "Running command: $command" -Level "Info"
        $results = Invoke-Expression $command
        
        if ($results) {
            $installed = $results | Where-Object { $_.Result -eq "Installed" }
            $failed = $results | Where-Object { $_.Result -eq "Failed" }
            
            Write-Log "Installation complete. Installed: $($installed.Count), Failed: $($failed.Count)" -Level "Info"
            
            if ($failed.Count -gt 0) {
                foreach ($fail in $failed) {
                    Write-Log "Failed to install: $($fail.Title) [KB$($fail.KB)] - Error: $($fail.ErrorCode)" -Level "Warning"
                }
            }
        } else {
            Write-Log "No updates were installed." -Level "Info"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to install updates: $_" -Level "Error"
        return $false
    }
}

function Schedule-WindowsUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [datetime]$ScheduledTime,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Never", "IfRequired", "Always")]
        [string]$RebootPolicy
    )
    
    try {
        $now = Get-Date
        if ($ScheduledTime -lt $now) {
            Write-Log "Scheduled time is in the past. Please provide a future date and time." -Level "Error"
            return $false
        }
        
        # Create a scheduled task to run the script with Install parameter
        $scriptPath = $MyInvocation.MyCommand.Path
        $taskName = "WindowsUpdates_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Install -RebootPolicy `"$RebootPolicy`""
        $trigger = New-ScheduledTaskTrigger -Once -At $ScheduledTime
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        
        Write-Log "Windows Updates scheduled to install on $($ScheduledTime.ToString('yyyy-MM-dd HH:mm:ss')) with reboot policy: $RebootPolicy" -Level "Info"
        Write-Log "Scheduled task created: $taskName" -Level "Info"
        
        return $true
    }
    catch {
        Write-Log "Failed to schedule updates: $_" -Level "Error"
        return $false
    }
}

# Main script execution
try {
    # 1. Check for administrative privileges
    if (-not (Test-AdminPrivileges)) {
        exit 1
    }
    
    # 2. Check Windows Update service
    if (-not (Test-WindowsUpdateService)) {
        exit 1
    }
    
    # 3. Check and install required modules
    if (-not (Test-PSWindowsUpdateModule)) {
        exit 1
    }
    
    # 4. Get available updates (always perform this check)
    $availableUpdates = Get-AvailableUpdates
    
    # 5. Process based on parameters
    if ($Install) {
        Write-Log "Install parameter detected. Proceeding with immediate installation." -Level "Info"
        Install-PendingUpdates -RebootPolicy $RebootPolicy
    }
    elseif ($PSBoundParameters.ContainsKey('Schedule')) {
        Write-Log "Schedule parameter detected. Setting up scheduled installation." -Level "Info"
        Schedule-WindowsUpdates -ScheduledTime $Schedule -RebootPolicy $RebootPolicy
    }
    else {
        Write-Log "No action parameters specified. Update check complete." -Level "Info"
    }
    
    Write-Log "Script execution completed successfully." -Level "Info"
    Write-Host "Log file saved to: $LogPath" -ForegroundColor Cyan
}
catch {
    Write-Log "Unhandled exception: $_" -Level "Error"
    Write-Host "Script execution failed. See log file for details: $LogPath" -ForegroundColor Red
    exit 1
}

