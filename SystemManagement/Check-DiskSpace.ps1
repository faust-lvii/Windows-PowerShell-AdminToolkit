<#
.SYNOPSIS
    Checks disk space usage for all drives and provides warnings based on configured thresholds.

.DESCRIPTION
    This script checks the disk space usage of all available drives and reports warnings when
    disk space is below the specified thresholds. It can output the results to the console, 
    CSV file, or HTML file. It also supports sending email notifications when disk space is low.

.PARAMETER WarningThreshold
    The percentage of free space below which a warning will be displayed. Default is 20%.

.PARAMETER CriticalThreshold
    The percentage of free space below which a critical warning will be displayed. Default is 10%.

.PARAMETER OutputFormat
    The format in which to output the results. Valid values are "Console", "CSV", and "HTML". Default is "Console".

.PARAMETER OutputPath
    The path to which the CSV or HTML file will be written. Required if OutputFormat is "CSV" or "HTML".

.PARAMETER SendEmail
    Switch parameter that enables sending email notifications for low disk space.

.PARAMETER SmtpServer
    The SMTP server to use for sending email notifications. Required if SendEmail is specified.

.PARAMETER EmailFrom
    The email address from which notifications will be sent. Required if SendEmail is specified.

.PARAMETER EmailTo
    The email address to which notifications will be sent. Required if SendEmail is specified.

.PARAMETER EmailSubject
    The subject of the email notification. Default is "Disk Space Alert".

.EXAMPLE
    .\Check-DiskSpace.ps1
    Checks disk space on all drives and displays results in the console with default thresholds.

.EXAMPLE
    .\Check-DiskSpace.ps1 -WarningThreshold 30 -CriticalThreshold 15
    Checks disk space on all drives with custom thresholds and displays results in the console.

.EXAMPLE
    .\Check-DiskSpace.ps1 -OutputFormat CSV -OutputPath "C:\Reports\DiskSpace.csv"
    Checks disk space on all drives and saves the results to a CSV file.

.EXAMPLE
    .\Check-DiskSpace.ps1 -OutputFormat HTML -OutputPath "C:\Reports\DiskSpace.html"
    Checks disk space on all drives and saves the results to an HTML file.

.EXAMPLE
    .\Check-DiskSpace.ps1 -SendEmail -SmtpServer "smtp.company.com" -EmailFrom "monitoring@company.com" -EmailTo "admin@company.com"
    Checks disk space on all drives and sends email notifications for low disk space.

.NOTES
    File Name     : Check-DiskSpace.ps1
    Author        : System Administrator
    Prerequisite  : PowerShell 5.1 or higher
    Copyright     : (c) 2023 Your Organization
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 99)]
    [int]$WarningThreshold = 20,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 99)]
    [int]$CriticalThreshold = 10,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "HTML")]
    [string]$OutputFormat = "Console",

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$SendEmail,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer,

    [Parameter(Mandatory = $false)]
    [string]$EmailFrom,

    [Parameter(Mandatory = $false)]
    [string]$EmailTo,

    [Parameter(Mandatory = $false)]
    [string]$EmailSubject = "Disk Space Alert"
)

# Function to write colored output
function Write-ColorOutput {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $true)]
        [System.ConsoleColor]$ForegroundColor
    )

    $originalColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $ForegroundColor
    Write-Output $Message
    $Host.UI.RawUI.ForegroundColor = $originalColor
}

# Function to validate parameters
function Test-Parameters {
    if (($OutputFormat -eq "CSV" -or $OutputFormat -eq "HTML") -and -not $OutputPath) {
        Write-Error "OutputPath is required when OutputFormat is $OutputFormat."
        return $false
    }

    if ($SendEmail) {
        if (-not $SmtpServer -or -not $EmailFrom -or -not $EmailTo) {
            Write-Error "SmtpServer, EmailFrom, and EmailTo are required when SendEmail is specified."
            return $false
        }
    }

    return $true
}

# Function to get disk space information
function Get-DiskSpaceInfo {
    try {
        $drives = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType = 3" | 
            Select-Object DeviceID, 
                VolumeName, 
                @{Name = "TotalGB"; Expression = {[math]::Round($_.Size / 1GB, 2)}}, 
                @{Name = "FreeGB"; Expression = {[math]::Round($_.FreeSpace / 1GB, 2)}}, 
                @{Name = "FreePercent"; Expression = {[math]::Round(($_.FreeSpace / $_.Size) * 100, 2)}}, 
                @{Name = "UsedGB"; Expression = {[math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)}}, 
                @{Name = "UsedPercent"; Expression = {[math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 2)}}
        
        return $drives
    }
    catch {
        Write-Error "Failed to retrieve disk information: $_"
        return $null
    }
}

# Function to output disk information to console
function Write-ConsoleOutput {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]$DiskInfo
    )

    Write-ColorOutput "DISK SPACE REPORT" "White"
    Write-ColorOutput "================" "White"
    Write-Output ""
    
    foreach ($drive in $DiskInfo) {
        $driveName = if ($drive.VolumeName) { "$($drive.DeviceID) ($($drive.VolumeName))" } else { $drive.DeviceID }
        
        # Determine status color based on thresholds
        $statusColor = "Green"
        $status = "OK"
        
        if ($drive.FreePercent -le $WarningThreshold) {
            $statusColor = "Yellow"
            $status = "WARNING"
        }
        
        if ($drive.FreePercent -le $CriticalThreshold) {
            $statusColor = "Red"
            $status = "CRITICAL"
        }
        
        Write-ColorOutput "Drive: $driveName" "White"
        Write-Output "  Total Size: $($drive.TotalGB) GB"
        Write-Output "  Used Space: $($drive.UsedGB) GB ($($drive.UsedPercent)%)"
        Write-Output "  Free Space: $($drive.FreeGB) GB ($($drive.FreePercent)%)"
        Write-ColorOutput "  Status: $status" $statusColor
        Write-Output ""
    }
}

# Function to save disk information to CSV
function Export-ToCsv {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]$DiskInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $DiskInfo | 
            Select-Object DeviceID, VolumeName, TotalGB, UsedGB, UsedPercent, FreeGB, FreePercent, 
                @{Name = "Status"; Expression = {
                    if ($_.FreePercent -le $CriticalThreshold) { "CRITICAL" }
                    elseif ($_.FreePercent -le $WarningThreshold) { "WARNING" }
                    else { "OK" }
                }} | 
            Export-Csv -Path $FilePath -NoTypeInformation
        
        Write-Output "CSV report saved to: $FilePath"
    }
    catch {
        Write-Error "Failed to export to CSV: $_"
    }
}

# Function to save disk information to HTML
function Export-ToHtml {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]$DiskInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    try {
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Disk Space Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333366; }
        table { border-collapse: collapse; width: 100%; }
        th { background-color: #333366; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .ok { background-color: #dff0d8; }
        .warning { background-color: #fcf8e3; }
        .critical { background-color: #f2dede; }
        .timestamp { font-size: 0.8em; color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>Disk Space Report</h1>
    <div class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
    <table>
        <tr>
            <th>Drive</th>
            <th>Volume Name</th>
            <th>Total (GB)</th>
            <th>Used (GB)</th>
            <th>Used (%)</th>
            <th>Free (GB)</th>
            <th>Free (%)</th>
            <th>Status</th>
        </tr>
"@

        $htmlRows = ""
        foreach ($drive in $DiskInfo) {
            $status = "ok"
            if ($drive.FreePercent -le $WarningThreshold) {
                $status = "warning"
            }
            if ($drive.FreePercent -le $CriticalThreshold) {
                $status = "critical"
            }
            
            $statusText = if ($status -eq "critical") { "CRITICAL" } elseif ($status -eq "warning") { "WARNING" } else { "OK" }
            
            $htmlRows += @"
        <tr class="$status">
            <td>$($drive.DeviceID)</td>
            <td>$($drive.VolumeName)</td>
            <td>$($drive.TotalGB)</td>
            <td>$($drive.UsedGB)</td>
            <td>$($drive.UsedPercent)%</td>
            <td>$($drive.FreeGB)</td>
            <td>$($drive.FreePercent)%</td>
            <td>$statusText</td>
        </tr>
"@
        }

        $htmlFooter = @"
    </table>
</body>
</html>
"@

        $html = $htmlHeader + $htmlRows + $htmlFooter
        $html | Out-File -FilePath $FilePath -Encoding utf8
        
        Write-Output "HTML report saved to: $FilePath"
    }
    catch {
        Write-Error "Failed to export to HTML: $_"
    }
}

# Function to send email notification
function Send-EmailAlert {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]$DiskInfo
    )
    
    try {
        # Check if there are any drives that have low disk space
        $lowSpaceDisks = $DiskInfo | Where-Object { $_.FreePercent -le $WarningThreshold }
        
        if ($lowSpaceDisks.Count -eq 0) {
            Write-Output "No low disk space detected. Email not sent."
            return
        }
        
        # Prepare email body in HTML format
        $emailBody = @"
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        h1 { color: #333366; }
        table { border-collapse: collapse; width: 100%; }
        th { background-color: #333366; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning { background-color: #fcf8e3; }
        .critical { background-color: #f2dede; }
    </style>
</head>
<body>
    <h1>Disk Space Alert</h1>
    <p>The following drives have low disk space:</p>
    <table>
        <tr>
            <th>Drive</th>
            <th>Volume Name</th>
            <th>Total (GB)</th>
            <th>Free (GB)</th>
            <th>Free (%)</th>
            <th>Status</th>
        </tr>
"@

        foreach ($drive in $lowSpaceDisks) {
            $status = if ($drive.FreePercent -le $CriticalThreshold) { "CRITICAL" } else { "WARNING" }
            $class = if ($drive.FreePercent -le $CriticalThreshold) { "critical" } else { "warning" }
            
            $emailBody += @"
        <tr class="$class">
            <td>$($drive.DeviceID)</td>
            <td>$($drive.VolumeName)</td>
            <td>$($drive.TotalGB)</td>
            <td>$($drive.FreeGB)</td>
            <td>$($drive.FreePercent)%</td>
            <td>$status</td>
        </tr>
"@
        }

        $emailBody += @"
    </table>
    <p>This is an automated message from the disk space monitoring script.</p>
    <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") from server: $env:COMPUTERNAME</p>
</body>
</html>
"@

        # Set up email parameters
        $emailParams = @{
            SmtpServer = $SmtpServer
            From = $EmailFrom
            To = $EmailTo
            Subject = $EmailSubject
            Body = $emailBody
            BodyAsHtml = $true
        }
        
        # Send the email
        Send-MailMessage @emailParams
        Write-Output "Email alert sent to $EmailTo"
    }
    catch {
        Write-Error "Failed to send email notification: $_"
    }
}

# Main script execution
function Main {
    # Validate parameters
    if (-not (Test-Parameters)) {
        return
    }
    

