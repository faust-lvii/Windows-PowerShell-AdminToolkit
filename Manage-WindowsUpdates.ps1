<#
.SYNOPSIS
    Manages Windows Updates with extensive options for checking, listing, and installing updates.

.DESCRIPTION
    This PowerShell script provides comprehensive functionality for managing Windows Updates, including:
    - Checking for available Windows Updates
    - Listing available updates with detailed information
    - Installing specific updates or all available updates
    - Automatic installation with optional system restart
    - Progress tracking during update operations
    - Detailed logging and robust error handling
    - Viewing update history and system update status

.PARAMETER Action
    Specifies the action to perform: Check, List, Install, History, or Status
    Default: List

.PARAMETER UpdateIDs
    Specifies the IDs of updates to install. Use with Action 'Install' to install specific updates.
    Default: Install all available updates when not specified

.PARAMETER AutoRestart
    Indicates whether to automatically restart the system after installing updates if required.
    Default: False

.PARAMETER LogPath
    Specifies the path to save the log file.
    Default: "$env:TEMP\WindowsUpdates_<date>.log"

.PARAMETER Verbose
    Provides detailed information about script execution.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action Check
    Checks for available Windows Updates and displays a summary.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action List
    Lists all available Windows Updates with detailed information.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action Install
    Installs all available Windows Updates without automatic restart.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action Install -AutoRestart
    Installs all available Windows Updates with automatic restart if required.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action Install -UpdateIDs KB4562830,KB4566782
    Installs only the specified Windows Updates.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action History
    Displays Windows Update installation history.

.EXAMPLE
    PS> .\Manage-WindowsUpdates.ps1 -Action Status
    Displays Windows Update service status and configuration.

.NOTES
    File Name      : Manage-WindowsUpdates.ps1
    Prerequisite   : PowerShell 5.0 or later
                    Administrator rights required for installation
    Author         : Windows-PowerShell-AdminToolkit
    Version        : 1.0

.LINK
    https://github.com/Windows-PowerShell-AdminToolkit
#>

#Requires -Version 5.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Check', 'List', 'Install', 'History', 'Status')]
    [string]$Action = 'List',

    [Parameter(Mandatory = $false)]
    [string[]]$UpdateIDs,

    [Parameter(Mandatory = $false)]
    [switch]$AutoRestart,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\WindowsUpdates_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
)

#region Functions

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Information', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Information'
    )

    # Define timestamp
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    
    # Build log entry
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Define console colors based on level
    switch ($Level) {
        'Information' { $consoleColor = 'White' }
        'Warning'     { $consoleColor = 'Yellow' }
        'Error'       { $consoleColor = 'Red' }
        'Success'     { $consoleColor = 'Green' }
        default       { $consoleColor = 'White' }
    }
    
    # Write to console with appropriate color
    Write-Host $logEntry -ForegroundColor $consoleColor
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

function Initialize-WindowsUpdateSession {
    [CmdletBinding()]
    param()
    
    Write-Log -Message "Initializing Windows Update session" -Level Information
    
    try {
        # Create Microsoft.Update.Session COM object
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        Write-Log -Message "Windows Update session initialized successfully" -Level Success
        return $updateSession
    }
    catch {
        Write-Log -Message "Failed to initialize Windows Update session: $_" -Level Error
        throw "Failed to initialize Windows Update session: $_"
    }
}

function Get-WindowsUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.__ComObject]$UpdateSession
    )
    
    Write-Log -Message "Searching for available Windows Updates..." -Level Information
    
    try {
        # Create update searcher and search criteria
        $updateSearcher = $UpdateSession.CreateUpdateSearcher()
        $searchCriteria = "IsInstalled=0 and Type='Software' and IsHidden=0"
        
        # Show progress
        $searchProgressActivity = "Searching for Windows Updates"
        Write-Progress -Activity $searchProgressActivity -Status "Initializing search..." -PercentComplete 0
        
        # Search for updates
        Write-Log -Message "Search criteria: $searchCriteria" -Level Information
        $searchResult = $updateSearcher.Search($searchCriteria)
        
        Write-Progress -Activity $searchProgressActivity -Status "Search completed" -PercentComplete 100 -Completed
        
        # Log results
        $updateCount = $searchResult.Updates.Count
        if ($updateCount -gt 0) {
            Write-Log -Message "Found $updateCount available update(s)" -Level Success
        }
        else {
            Write-Log -Message "No updates available" -Level Information
        }
        
        return $searchResult.Updates
    }
    catch {
        Write-Progress -Activity $searchProgressActivity -Status "Search failed" -PercentComplete 100 -Completed
        Write-Log -Message "Failed to search for Windows Updates: $_" -Level Error
        throw "Failed to search for Windows Updates: $_"
    }
}

function Format-UpdateSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [long]$SizeInBytes
    )
    
    if ($SizeInBytes -lt 1KB) {
        return "$SizeInBytes B"
    }
    elseif ($SizeInBytes -lt 1MB) {
        return "{0:N2} KB" -f ($SizeInBytes / 1KB)
    }
    elseif ($SizeInBytes -lt 1GB) {
        return "{0:N2} MB" -f ($SizeInBytes / 1MB)
    }
    else {
        return "{0:N2} GB" -f ($SizeInBytes / 1GB)
    }
}

function Show-WindowsUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.__ComObject]$Updates
    )
    
    $updateCount = $Updates.Count
    
    if ($updateCount -eq 0) {
        Write-Host "`nNo updates available." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n====== Available Windows Updates ($updateCount) ======" -ForegroundColor Cyan
    
    for ($i = 0; $i -lt $updateCount; $i++) {
        $update = $Updates.Item($i)
        $size = if ($update.IsDownloaded) { Format-UpdateSize $update.MaxDownloadSize } else { "Not downloaded" }
        $kbNumbers = @($update.KBArticleIDs | ForEach-Object { "KB$_" }) -join ", "
        $kbDisplay = if ($kbNumbers) { $kbNumbers } else { "N/A" }
        
        # Define update status color
        $statusColor = switch ($true) {
            $update.MsrcSeverity -eq "Critical" { "Red" }
            $update.MsrcSeverity -eq "Important" { "Yellow" }
            default { "White" }
        }
        
        Write-Host ("`n{0}. " -f ($i + 1)) -ForegroundColor Cyan -NoNewline
        Write-Host $update.Title -ForegroundColor $statusColor
        Write-Host "   KB Articles: " -NoNewline
        Write-Host $kbDisplay -ForegroundColor White
        Write-Host "   Severity:    " -NoNewline
        Write-Host ($update.MsrcSeverity ?? "Regular") -ForegroundColor $statusColor
        Write-Host "   Size:        $size"
        Write-Host "   Categories:  " -NoNewline
        Write-Host ($update.Categories | ForEach-Object { $_.Name } | Join-String -Separator ", ")
        
        if ($update.RebootRequired) {
            Write-Host "   Reboot:      " -NoNewline
            Write-Host "Required" -ForegroundColor Red
        }
        
        Write-Host "   Description:`n   " -NoNewline
        Write-Host $update.Description -ForegroundColor Gray
    }
    
    Write-Host "`n=================================================" -ForegroundColor Cyan
}

function Install-WindowsUpdates {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.__ComObject]$UpdateSession,
        
        [Parameter(Mandatory = $true)]
        [System.__ComObject]$Updates,
        
        [Parameter(Mandatory = $false)]
        [string[]]$UpdateIDs,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoRestart
    )
    
    $updateCount = $Updates.Count
    
    if ($updateCount -eq 0) {
        Write-Log -Message "No updates available to install" -Level Warning
        return
    }
    
    # Create collection of updates to install
    try {
        $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
        
        # If specific updates requested, filter them
        if ($UpdateIDs) {
            Write-Log -Message "Filtering updates based on provided IDs: $($UpdateIDs -join ', ')" -Level Information
            $found = $false
            
            for ($i = 0; $i -lt $updateCount; $i++) {
                $update = $Updates.Item($i)
                $updateKBs = @($update.KBArticleIDs | ForEach-Object { "KB$_" })
                
                foreach ($kbId in $UpdateIDs) {
                    if ($updateKBs -contains $kbId) {
                        Write-Log -Message "Adding update to installation queue: $($update.Title)" -Level Information
                        $updatesToInstall.Add($update) | Out-Null
                        $found = $true
                        break
                    }
                }
            }
            
            if (-not $found) {
                Write-Log -Message "None of the specified updates were found in the available updates" -Level Warning
                return
            }
        }
        else {
            # Add all updates to collection
            for ($i = 0; $i -lt $updateCount; $i++) {
                $update = $Updates.Item($i)
                Write-Log -Message "Adding update to installation queue: $($update.Title)" -Level Information
                $updatesToInstall.Add($update) | Out-Null
            }
        }
        
        $installCount = $updatesToInstall.Count
        if ($installCount -eq 0) {
            Write-Log -Message "No updates to install" -Level Warning
            return
        }
        
        Write-Log -Message "Preparing to install $installCount update(s)" -Level Information
        
        # Download updates
        Write-Log -Message "Starting update download process" -Level Information
        $downloader = $UpdateSession.CreateUpdateDownloader()
        $downloader.Updates = $updatesToInstall
        
        $downloadProgressActivity = "Downloading Windows Updates"
        Write-Progress -Activity $downloadProgressActivity -Status "Initializing download..." -PercentComplete 0
        
        try {
            $downloadResult = $downloader.Download()
            Write-Progress -Activity $downloadProgressActivity -Status "Download completed" -PercentComplete 100 -Completed
            
            if ($downloadResult.ResultCode -eq 2) { # orcSucceeded
                Write-Log -Message "All updates downloaded successfully" -Level Success
            }
            else {
                Write-Log -Message "Download completed with status: $($downloadResult.ResultCode)" -Level Warning
            }
        }
        catch {
            Write-Progress -Activity $downloadProgressActivity -Status "Download failed" -PercentComplete 100 -Completed
            Write-Log -Message "Failed to download updates: $_" -Level Error
            throw "Failed to download updates: $_"
        }
        
        # Install updates
        Write-Log -Message "Starting update installation process" -Level Information
        $installer = $UpdateSession.CreateUpdateInstaller()
        $installer.Updates = $updatesToInstall
        
        $installProgressActivity = "Installing Windows Updates"
        Write-Progress -Activity $installProgressActivity -Status "Initializing installation..." -PercentComplete 0
        
        try {
            $installResult = $installer.Install()
            Write-Progress -Activity $installProgressActivity -Status "Installation completed" -PercentComplete 100 -Completed
            
            # Report installation results
            Write-Log -Message "Installation completed with result code: $($installResult.ResultCode)" -Level Information
            Write-Log -Message "Reboot required: $($installResult.RebootRequired)" -Level Information
            
            for ($i = 0; $i -lt $updatesToInstall.Count; $i++) {
                $update = $updatesToInstall.Item($i)
                $updateResult = $installResult.GetUpdateResult($i)
                $resultMessage = switch ($updateResult.ResultCode) {
                    0 { "Not Started" } # orcNotStarted
                    1 { "In Progress" } # orcInProgress
                    2 { "Succeeded" }   # orcSucceeded
                    3 { "SucceededWithErrors" } # orcSucceededWithErrors
                    4 { "Failed" }      # orcFailed
                    5 { "Aborted" }     # orcAborted
                    default { "Unknown result ($($updateResult.ResultCode))" }
                }
                
                $logLevel = if ($updateResult.ResultCode -eq 2) { "Success" } elseif ($updateResult.ResultCode -gt 2) { "Error" } else { "Information" }
                Write-Log -Message "Update '$($update.Title)' - $resultMessage" -Level $logLevel
            }
            
            # Handle reboot if required
            if ($installResult.RebootRequired) {
                if ($AutoRestart) {
                    Write-Log -Message "Automatic restart is enabled. System will restart in 60 seconds..." -Level Warning
                    Write-Host "`nThis system will restart in 60 seconds to complete Windows Updates installation.`nPress Ctrl+C to cancel." -

