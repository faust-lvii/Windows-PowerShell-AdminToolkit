#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Analyzes and filters Windows event logs to identify suspicious activities.

.DESCRIPTION
    The Analyze-Logs.ps1 script searches through Windows event logs (System, Application, Security)
    using predefined XPath queries to identify potentially suspicious events. Results can be
    displayed in the console with color-coding based on severity, and/or exported to CSV or HTML formats.

.PARAMETER LogType
    Specifies which event log to analyze. Valid options are "System", "Application", or "Security".

.PARAMETER DaysBack
    Specifies how many days back to analyze logs. Default is 1 day.

.PARAMETER OutputFormat
    Specifies the format for outputting results. Valid options are "Console", "CSV", "HTML", or "All".
    Default is "Console".

.PARAMETER OutputPath
    Specifies the directory path where exported logs should be saved. Required when OutputFormat
    is not set to "Console".

.EXAMPLE
    .\Analyze-Logs.ps1 -LogType Security -DaysBack 7 -OutputFormat Console
    Analyzes the Security log for the past 7 days and displays results in the console.

.EXAMPLE
    .\Analyze-Logs.ps1 -LogType System -DaysBack 3 -OutputFormat All -OutputPath "C:\Logs"
    Analyzes the System log for the past 3 days, displays results in the console, and exports to both CSV and HTML in C:\Logs.

.NOTES
    Author: AdminToolkit Team
    Version: 1.0
    Requires: PowerShell 5.1 or later
    Date: Created as part of AdminToolkit development
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("System", "Application", "Security")]
    [string]$LogType,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 1,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "HTML", "All")]
    [string]$OutputFormat = "Console",

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($OutputFormat -ne "Console" -and -not (Test-Path -Path $_ -IsValid)) {
            throw "Output path is invalid: $_"
        }
        if ($OutputFormat -ne "Console" -and -not (Test-Path -Path $_ -PathType Container) -and -not (New-Item -Path $_ -ItemType Directory -Force -ErrorAction SilentlyContinue)) {
            throw "Cannot create output directory: $_"
        }
        return $true
    })]
    [string]$OutputPath
)

# Initialize logging
$LogFile = Join-Path -Path $env:TEMP -ChildPath "Analyze-Logs_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry
    
    # Also output to console with appropriate color
    switch ($Level) {
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
        "DEBUG"   { if ($VerbosePreference -eq 'Continue') { Write-Host $logEntry -ForegroundColor Cyan } }
        default   { Write-Host $logEntry }
    }
}

function Get-EventXPathQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("System", "Application", "Security")]
        [string]$LogType,
        
        [Parameter(Mandatory = $true)]
        [int]$DaysBack
    )
    
    $StartTime = (Get-Date).AddDays(-$DaysBack).ToUniversalTime()
    $TimeCreatedFilter = "*[System[TimeCreated[@SystemTime>='" + $StartTime.ToString("yyyy-MM-ddTHH:mm:ss.000Z") + "']]]"
    
    switch ($LogType) {
        "System" {
            # Critical system errors, services failing, etc.
            $EventIDs = @(
                1074,  # System shutdown
                6008,  # Unexpected shutdown
                41,    # System rebooted without clean shutdown
                1076,  # Unexpected shutdown
                7031,  # Service terminated unexpectedly
                10016, # DCOM permission errors
                104,   # Event log cleared
                7034,  # Service crashed unexpectedly
                7040   # Service start type changed
            )
            
            $EventIDFilter = "*[System[("
            for ($i = 0; $i -lt $EventIDs.Count; $i++) {
                $EventIDFilter += "EventID=$($EventIDs[$i])"
                if ($i -lt $EventIDs.Count - 1) {
                    $EventIDFilter += " or "
                }
            }
            $EventIDFilter += ")]]"
            
            $XPathQuery = "$EventIDFilter and $TimeCreatedFilter"
        }
        "Application" {
            # Application crashes, errors, warnings
            $EventIDs = @(
                1000,  # Application errors
                1001,  # Application fault
                1002,  # Application hang
                1026,  # Application install/uninstall
                1033,  # Installation completed
                1034,  # Application removal completed
                1040,  # Application crash
                11707, # Installation completed
                11708, # Installation operation failed
                11724  # Application removal completed
            )
            
            $EventIDFilter = "*[System[("
            for ($i = 0; $i -lt $EventIDs.Count; $i++) {
                $EventIDFilter += "EventID=$($EventIDs[$i])"
                if ($i -lt $EventIDs.Count - 1) {
                    $EventIDFilter += " or "
                }
            }
            $EventIDFilter += ")]]"
            
            $XPathQuery = "$EventIDFilter and $TimeCreatedFilter"
        }
        "Security" {
            # Various security-related events
            $EventIDs = @(
                4624,  # Account logon successful
                4625,  # Account logon failure
                4634,  # Account logoff
                4648,  # Logon using explicit credentials
                4672,  # Admin privilege assigned
                4720,  # Account created
                4722,  # Account enabled
                4724,  # Password reset
                4728,  # Member added to security-enabled group
                4732,  # Member added to local group
                4738,  # User account changed
                4740,  # Account locked out
                4768,  # Kerberos authentication
                4771,  # Kerberos pre-authentication failed
                4776,  # NTLM authentication
                4777,  # Domain controller failed to validate credentials
                7035,  # Service control success/error
                7045,  # New service installed
                1102   # Audit log cleared
            )
            
            $EventIDFilter = "*[System[("
            for ($i = 0; $i -lt $EventIDs.Count; $i++) {
                $EventIDFilter += "EventID=$($EventIDs[$i])"
                if ($i -lt $EventIDs.Count - 1) {
                    $EventIDFilter += " or "
                }
            }
            $EventIDFilter += ")]]"
            
            $XPathQuery = "$EventIDFilter and $TimeCreatedFilter"
        }
    }
    
    return $XPathQuery
}

function Get-SuspiciousEventSeverity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$LogType,
        
        [Parameter(Mandatory = $true)]
        [int]$EventID
    )
    
    # Define severity levels for specific event IDs
    $HighSeverityEvents = @{
        "Security" = @(4625, 4740, 4648, 4672, 4720, 1102, 4776, 4738, 7045)
        "System" = @(41, 1074, 6008, 1076, 104)
        "Application" = @(1000, 1002, 11708)
    }
    
    $MediumSeverityEvents = @{
        "Security" = @(4624, 4634, 4728, 4732, 4771, 4777)
        "System" = @(7031, 7034, 10016)
        "Application" = @(1001, 1026, 1034)
    }
    
    if ($HighSeverityEvents[$LogType] -contains $EventID) {
        return "High"
    }
    elseif ($MediumSeverityEvents[$LogType] -contains $EventID) {
        return "Medium"
    }
    else {
        return "Low"
    }
}

function Get-SuspiciousEvents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("System", "Application", "Security")]
        [string]$LogType,
        
        [Parameter(Mandatory = $true)]
        [int]$DaysBack
    )
    
    try {
        Write-Log -Message "Starting analysis of $LogType logs for the past $DaysBack days" -Level INFO
        
        $XPathQuery = Get-EventXPathQuery -LogType $LogType -DaysBack $DaysBack
        Write-Log -Message "Using XPath query: $XPathQuery" -Level DEBUG
        
        # Get events using the XPath query
        $Events = Get-WinEvent -LogName $LogType -FilterXPath $XPathQuery -ErrorAction Stop
        Write-Log -Message "Retrieved $($Events.Count) events from $LogType log" -Level INFO
        
        # Process and analyze events
        $SuspiciousEvents = foreach ($Event in $Events) {
            $Severity = Get-SuspiciousEventSeverity -LogType $LogType -EventID $Event.Id
            
            # Create custom object for each event
            [PSCustomObject]@{
                LogType = $LogType
                TimeCreated = $Event.TimeCreated
                EventID = $Event.Id
                Source = $Event.ProviderName
                Message = $Event.Message -replace "`r`n|`r|`n", " "
                Severity = $Severity
                ComputerName = $Event.MachineName
                Username = try { $Event.Properties[5].Value } catch { "N/A" }
            }
        }
        
        return $SuspiciousEvents
    }
    catch {
        Write-Log -Message "Error retrieving events from $LogType log: $_" -Level ERROR
        return $null
    }
}

function Show-ColoredResults {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Events
    )
    
    if ($null -eq $Events -or $Events.Count -eq 0) {
        Write-Host "No suspicious events found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n=== Suspicious Events Report ===`n" -ForegroundColor Cyan
    
    foreach ($Event in $Events) {
        # Set color based on severity
        $Color = switch ($Event.Severity) {
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Green" }
            default { "White" }
        }
        
        # Format the output with color
        Write-Host "Time: " -NoNewline
        Write-Host $Event.TimeCreated -ForegroundColor $Color
        Write-Host "EventID: " -NoNewline
        Write-Host $Event.EventID -ForegroundColor $Color
        Write-Host "Source: " -NoNewline
        Write-Host $Event.Source -ForegroundColor $Color
        Write-Host "Severity: " -NoNewline
        Write-Host $Event.Severity -ForegroundColor $Color
        Write-Host "Username: " -NoNewline
        Write-Host $Event.Username -ForegroundColor $Color
        Write-Host "Message: " -NoNewline
        Write-Host $Event.Message -ForegroundColor $Color
        Write-Host "-----------------------------------------" -ForegroundColor DarkGray
    }
}

function Export-EventsToCSV {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Events,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$LogType
    )
    
    try {
        $CSVFile = Join-Path -Path $OutputPath -ChildPath "$($LogType)_Events_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $Events | Export-Csv -Path $CSVFile -NoTypeInformation -Force
        Write-Log -Message "Successfully exported events to CSV file: $CSVFile" -Level INFO
        return $CSVFile
    }
    catch {
        Write-Log -Message "Error exporting to CSV: $_" -Level ERROR
        return $null
    }
}

function Export-EventsToHTML {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Events,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string]$LogType
    )
    
    try {
        $HTMLFile = Join-Path -Path $OutputPath -ChildPath "$($LogType)_Events_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        
        # Create HTML header with some basic CSS
        $HTMLHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>$LogType Log Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .high { color: red; font-weight: bold; }
        .medium { color: orange; }
        .low { color: green; }
        .timeline { margin-top: 30px; border-left: 3px solid #0066cc; padding-left: 20px; }
        .event { margin-bottom: 15px; padding: 10px; border-radius: 5px; }
        .high-event { background-color: #ffeeee; border-left: 5px solid red; }
        .medium-event { background-color: #fff8ee; border-left: 5px solid orange; }
        .low-event { background-color: #f0f8ff; border-left: 5px solid green; }
        .timestamp { font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <h1>$LogType Event Log Analysis</h1>
    <p>Report generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    <p>Analyzing logs from the past $DaysBack days</p>
    <h2>Summary</h2>
    <p>Total events found: $($Events.Count)</p>
</body>
</html>
"@

        # Create the event table HTML
        $TableHTML = @"
<h2>Events Table</h2>
<table>
    <tr>
        <th>Time</th>
        <th>Event ID</th>
        <th>Source</th>
        <th>Severity</th>
        <th>Username</th>
        <th>Message</th>
    </tr>
"@

        # Add each event to the table with appropriate color coding
        foreach ($Event in $Events) {
            $SeverityClass = $Event.Severity.ToLower()
            $TableHTML += @"
    <tr>
        <td>$($Event.TimeCreated)</td>
        <td>$($Event.EventID)</td>
        <td>$($Event.Source)</td>
        <td class="$SeverityClass">$($Event.Severity)</td>
        <td>$($Event.Username)</td>
        <td>$($Event.Message)</td>
    </tr>
"@
        }

        # Close the table
        $TableHTML += "</table>"

        # Create the timeline HTML section
        $TimelineHTML = @"
<h2>Events Timeline</h2>
<div class="timeline">
"@

        # Sort events by time
        $SortedEvents = $Events | Sort-Object -Property TimeCreated

        # Add each event to the timeline with appropriate styling
        foreach ($Event in $SortedEvents) {
            $SeverityClass = "$($Event.Severity.ToLower())-event"
            $TimelineHTML += @"
    <div class="event $SeverityClass">
        <div class="timestamp">$($Event.TimeCreated)</div>
        <strong>$($Event.Source) - Event ID: $($Event.EventID) - $($Event.Severity) Severity</strong>
        <p>$($Event.Message)</p>
        <p>Username: $($Event.Username)</p>
    </div>
"@
        }

        # Close the timeline div
        $TimelineHTML += "</div>"

        # Combine all HTML parts
        $FullHTML = $HTMLHeader.Replace("</body>", "$TableHTML`n$TimelineHTML`n</body>")

        # Write the HTML content to file
        $FullHTML | Out-File -FilePath $HTMLFile -Force

        Write-Log -Message "Successfully exported events to HTML file: $HTMLFile" -Level INFO
        return $HTMLFile
    }
    catch {
        Write-Log -Message "Error exporting to HTML: $_" -Level ERROR
        return $null
    }
}

# Main script execution
try {
    Write-Log -Message "Starting script execution with LogType: $LogType, DaysBack: $DaysBack, OutputFormat: $OutputFormat" -Level INFO
    
    # Validate OutputPath when not using Console-only output
    if ($OutputFormat -ne "Console" -and -not $OutputPath) {
        throw "OutputPath parameter is required when OutputFormat is not 'Console'"
    }
    
    # Get suspicious events
    $Events = Get-SuspiciousEvents -LogType $LogType -DaysBack $DaysBack
    
    if ($null -eq $Events -or $Events.Count -eq 0) {
        Write-Log -Message "No suspicious events found in the $LogType log for the past $DaysBack days" -Level WARNING
        if ($OutputFormat -eq "Console" -or $OutputFormat -eq "All") {
            Write-Host "No suspicious events found in the $LogType log for the past $DaysBack days." -ForegroundColor Yellow
        }
        return
    }
    
    # Output according to requested format
    switch -Regex ($OutputFormat) {
        "Console|All" {
            Show-ColoredResults -Events $Events
        }
        "CSV|All" {
            $CSVPath = Export-EventsToCSV -Events $Events -OutputPath $OutputPath -LogType $LogType
            if ($CSVPath) {
                Write-Host "CSV export completed successfully: $CSVPath" -ForegroundColor Green
            }
        }
        "HTML|All" {
            $HTMLPath = Export-EventsToHTML -Events $Events -OutputPath $OutputPath -LogType $LogType
            if ($HTMLPath) {
                Write-Host "HTML export completed successfully: $HTMLPath" -ForegroundColor Green
            }
        }
    }
    
    Write-Log -Message "Script execution completed successfully" -Level INFO
    Write-Host "`nAnalysis completed. Found $($Events.Count) suspicious events in the $LogType log." -ForegroundColor Cyan
    
    # Return the events object for potential pipeline usage
    return $Events
}
catch {
    Write-Log -Message "Script execution failed: $_" -Level ERROR
    Write-Host "ERROR: $($_)" -ForegroundColor Red
    return $null
}
finally {
    Write-Host "`nLog file created at: $LogFile" -ForegroundColor DarkGray
}
