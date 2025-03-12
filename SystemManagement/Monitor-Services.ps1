<#
.SYNOPSIS
    Monitors and manages Windows services.

.DESCRIPTION
    The Monitor-Services script allows users to view, filter, and manage Windows services.
    It provides detailed information about services and supports various operations such as
    starting, stopping, and restarting services. The script supports multiple output formats
    and includes comprehensive error handling.

.PARAMETER Name
    Filter services by name. Supports wildcards.

.PARAMETER Status
    Filter services by status. Valid values: Running, Stopped, All.

.PARAMETER StartupType
    Filter services by startup type. Valid values: Automatic, Manual, Disabled, All.

.PARAMETER Action
    Action to perform on selected services. Valid values: None, Start, Stop, Restart.
    Requires elevated privileges for Start, Stop, and Restart actions.

.PARAMETER Format
    Output format. Valid values: Console, CSV, HTML.

.PARAMETER ExportPath
    Path to export the results when using CSV or HTML format.

.PARAMETER LogPath
    Path to log file. If not specified, logs will be written to the default location.

.EXAMPLE
    .\Monitor-Services.ps1
    Displays all services in console format.

.EXAMPLE
    .\Monitor-Services.ps1 -Status Running
    Displays only running services.

.EXAMPLE
    .\Monitor-Services.ps1 -Name "win*" -Status Stopped
    Displays stopped services with names starting with "win".

.EXAMPLE
    .\Monitor-Services.ps1 -StartupType Automatic -Format HTML -ExportPath "C:\Reports\Services.html"
    Exports automatic startup services to an HTML file.

.EXAMPLE
    .\Monitor-Services.ps1 -Name "BITS" -Action Restart
    Restarts the BITS service. Requires elevated privileges.

.NOTES
    Author: PowerShell AdminToolkit
    Version: 1.0
    Requires: PowerShell 5.1 or later
    Requires elevated privileges for Start, Stop, and Restart actions.

.LINK
    https://github.com/yourusername/Windows-PowerShell-AdminToolkit
#>

[CmdletBinding()]
param (
    [Parameter(Position=0, HelpMessage="Filter services by name. Supports wildcards.")]
    [string]$Name = "*",

    [Parameter(HelpMessage="Filter services by status.")]
    [ValidateSet("Running", "Stopped", "All")]
    [string]$Status = "All",

    [Parameter(HelpMessage="Filter services by startup type.")]
    [ValidateSet("Automatic", "Manual", "Disabled", "All")]
    [string]$StartupType = "All",

    [Parameter(HelpMessage="Action to perform on selected services.")]
    [ValidateSet("None", "Start", "Stop", "Restart")]
    [string]$Action = "None",

    [Parameter(HelpMessage="Output format.")]
    [ValidateSet("Console", "CSV", "HTML")]
    [string]$Format = "Console",

    [Parameter(HelpMessage="Path to export the results.")]
    [string]$ExportPath,

    [Parameter(HelpMessage="Path to log file.")]
    [string]$LogPath = "$env:TEMP\ServiceMonitor.log"
)

# Function to write to log file
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }

    # Also write to console based on level
    switch ($Level) {
        "INFO" { Write-Verbose $Message }
        "WARNING" { Write-Warning $Message }
        "ERROR" { Write-Error $Message }
    }
}

# Function to check if running as administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to manage service (Start, Stop, Restart)
function Manage-Service {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.ServiceProcess.ServiceController]$Service,

        [Parameter(Mandatory=$true)]
        [ValidateSet("Start", "Stop", "Restart")]
        [string]$Action
    )

    $serviceName = $Service.DisplayName
    
    try {
        switch ($Action) {
            "Start" {
                if ($Service.Status -eq "Stopped") {
                    Write-Log -Message "Starting service: $serviceName" -Level "INFO"
                    $Service.Start()
                    $Service.WaitForStatus("Running", "00:00:30")
                    Write-Host "Service '$serviceName' started successfully." -ForegroundColor Green
                } else {
                    Write-Log -Message "Service $serviceName is already running" -Level "INFO"
                    Write-Host "Service '$serviceName' is already running." -ForegroundColor Yellow
                }
            }
            "Stop" {
                if ($Service.Status -eq "Running") {
                    Write-Log -Message "Stopping service: $serviceName" -Level "INFO"
                    $Service.Stop()
                    $Service.WaitForStatus("Stopped", "00:00:30")
                    Write-Host "Service '$serviceName' stopped successfully." -ForegroundColor Green
                } else {
                    Write-Log -Message "Service $serviceName is already stopped" -Level "INFO"
                    Write-Host "Service '$serviceName' is already stopped." -ForegroundColor Yellow
                }
            }
            "Restart" {
                Write-Log -Message "Restarting service: $serviceName" -Level "INFO"
                if ($Service.Status -eq "Running") {
                    $Service.Stop()
                    $Service.WaitForStatus("Stopped", "00:00:30")
                }
                $Service.Start()
                $Service.WaitForStatus("Running", "00:00:30")
                Write-Host "Service '$serviceName' restarted successfully." -ForegroundColor Green
            }
        }
        return $true
    }
    catch {
        Write-Log -Message "Failed to $Action service $serviceName. Error: $_" -Level "ERROR"
        Write-Host "Failed to $Action service '$serviceName'. Error: $_" -ForegroundColor Red
        return $false
    }
}

# Function to get service details
function Get-ServiceDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [System.ServiceProcess.ServiceController]$Service
    )

    $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$($Service.Name)'"
    
    $startupTypeMap = @{
        "Auto" = "Automatic"
        "Automatic" = "Automatic"
        "Manual" = "Manual"
        "Disabled" = "Disabled"
    }

    $startupType = $startupTypeMap[$wmiService.StartMode]
    if (-not $startupType) { $startupType = $wmiService.StartMode }

    $dependencies = @($Service.DependentServices | Select-Object -ExpandProperty DisplayName)
    $dependenciesStr = if ($dependencies.Count -gt 0) { $dependencies -join ", " } else { "None" }

    return [PSCustomObject]@{
        Name = $Service.Name
        DisplayName = $Service.DisplayName
        Status = $Service.Status
        StartupType = $startupType
        Account = $wmiService.StartName
        Description = $wmiService.Description
        Path = $wmiService.PathName
        Dependencies = $dependenciesStr
    }
}

# Function to generate HTML report
function Generate-HtmlReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [object[]]$Services,

        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Services Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
        .running { color: green; font-weight: bold; }
        .stopped { color: red; font-weight: bold; }
        .footer { margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <h1>Windows Services Report</h1>
    <p>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <table>
        <tr>
            <th>Name</th>
            <th>Display Name</th>
            <th>Status</th>
            <th>Startup Type</th>
            <th>Account</th>
            <th>Description</th>
        </tr>
"@

    $htmlRows = foreach ($service in $Services) {
        $statusClass = if ($service.Status -eq "Running") { "running" } else { "stopped" }
        
        "<tr>" +
        "<td>$($service.Name)</td>" +
        "<td>$($service.DisplayName)</td>" +
        "<td class='$statusClass'>$($service.Status)</td>" +
        "<td>$($service.StartupType)</td>" +
        "<td>$($service.Account)</td>" +
        "<td>$($service.Description)</td>" +
        "</tr>"
    }

    $htmlFooter = @"
    </table>
    <div class="footer">
        <p>Report generated by PowerShell AdminToolkit - Service Monitor</p>
    </div>
</body>
</html>
"@

    $htmlContent = $htmlHeader + ($htmlRows -join "") + $htmlFooter

    try {
        $htmlContent | Out-File -FilePath $FilePath -Encoding UTF8 -Force
        Write-Log -Message "HTML report generated successfully at $FilePath" -Level "INFO"
        return $true
    }
    catch {
        Write-Log -Message "Failed to generate HTML report. Error: $_" -Level "ERROR"
        return $false
    }
}

# Script begins
Write-Log -Message "Script started with parameters: Name=$Name, Status=$Status, StartupType=$StartupType, Action=$Action, Format=$Format" -Level "INFO"

# Check administrator privileges if action is specified
if ($Action -ne "None") {
    if (-not (Test-Administrator)) {
        Write-Log -Message "Administrator privileges required for action: $Action" -Level "ERROR"
        Write-Host "Error: Administrator privileges required to perform $Action action on services." -ForegroundColor Red
        Write-Host "Please run the script as Administrator." -ForegroundColor Red
        exit 1
    }
}

# Get services with filtering
try {
    Write-Verbose "Retrieving services..."
    $services = Get-Service -Name $Name -ErrorAction Stop
    
    # Apply status filter
    if ($Status -ne "All") {
        $services = $services | Where-Object { $_.Status -eq $Status }
    }
    
    # Get detailed service information
    $serviceDetails = @()
    $totalServices = $services.Count
    $currentService = 0
    
    foreach ($service in $services) {
        $currentService++
        $percentComplete = ($currentService / $totalServices) * 100
        Write-Progress -Activity "Processing Services" -Status "Processing $($service.DisplayName)" -PercentComplete $percentComplete
        
        $detail = Get-ServiceDetails -Service $service
        
        # Apply startup type filter
        $include = $true
        if ($StartupType -ne "All") {
            if ($detail.StartupType -ne $StartupType) {
                $include = $false
            }
        }
        
        if ($include) {
            $serviceDetails += $detail
        }
    }
    
    Write-Progress -Activity "Processing Services" -Completed
    
    # Check if any services match the filters
    if ($serviceDetails.Count -eq 0) {
        Write-Log -Message "No services found matching the specified filters" -Level "WARNING"
        Write-Host "No services found matching the specified filters." -ForegroundColor Yellow
        exit 0
    }
    
    Write-Log -Message "Found $($serviceDetails.Count) services matching the specified filters" -Level "INFO"
    
    # Perform action if specified
    if ($Action -ne "None") {
        $actionCount = 0
        $successCount = 0
        
        foreach ($detail in $serviceDetails) {
            $actionCount++
            $service = Get-Service -Name $detail.Name
            $result = Manage-Service -Service $service -Action $Action
            if ($result) { $successCount++ }
        }
        
        Write-Host "`nAction Summary:" -ForegroundColor Cyan
        Write-Host "  Action: $Action" -ForegroundColor Cyan
        Write-Host "  Total services: $actionCount" -ForegroundColor Cyan
        Write-Host "  Successful: $successCount" -ForegroundColor Cyan
        Write-Host "  Failed: $($actionCount - $successCount)" -ForegroundColor Cyan
        
        # Refresh service details after actions
        if ($successCount -gt 0) {
            Write-Verbose "Refreshing service information..."
            $services = Get-Service -Name $Name
            
            # Apply status filter
            if ($Status -ne "All") {
                $services = $services | Where-Object { $_.Status -eq $Status }
            }
            
            # Get detailed service information again
            $serviceDetails = @()
            foreach ($service in $services) {
                $detail = Get-ServiceDetails -Service $service
                
                # Apply startup type filter
                $include = $true
                if ($StartupType -ne "All") {
                    if ($detail.StartupType -ne $StartupType) {
                        $include = $false
                    }
                }
                
                if ($include) {
                    $serviceDetails += $detail
                }
            }
        }
    }
    
    # Output results based on format
    switch ($Format) {
        "Console" {
            Write-Host "`nServices Report:" -ForegroundColor Cyan
            
            foreach ($service in $serviceDetails) {
                $statusColor = switch ($service.Status) {
                    "Running" { "Green" }
                    "Stopped" { "Red" }
                    default { "Yellow" }
                }
                
                Write-Host "`n$($service.DisplayName) ($($service.Name))" -ForegroundColor Cyan
                Write-Host "  Status: " -NoNewline
                Write-Host "$($service.Status)" -ForegroundColor $statusColor
                Write-Host "  Startup Type: $($service.StartupType)"

