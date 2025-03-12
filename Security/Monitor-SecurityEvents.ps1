#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Monitors Windows security events and generates detailed reports.

.DESCRIPTION
    This script monitors various Windows security events, including failed login attempts,
    account modifications, security policy changes, system integrity changes, privilege usage,
    object access, and security audit events. It supports real-time monitoring, event filtering,
    and can generate detailed reports in multiple formats.

.PARAMETER EventTypes
    Specifies which types of security events to monitor.
    Valid values: All, FailedLogins, AccountChanges, PolicyChanges, IntegrityChanges, PrivilegeUsage, ObjectAccess, AuditEvents
    Default: All

.PARAMETER MaxEvents
    Specifies the maximum number of events to retrieve.
    Default: 100

.PARAMETER OutputFormat
    Specifies the output format for reports.
    Valid values: Console, CSV, HTML, JSON, XML
    Default: Console

.PARAMETER OutputPath
    Specifies the path where reports will be saved.
    Default: Current directory

.PARAMETER StartTime
    Specifies the start time for event retrieval.
    Default: 24 hours ago

.PARAMETER EndTime
    Specifies the end time for event retrieval.
    Default: Current time

.PARAMETER RealTime
    Enables real-time monitoring of security events.

.PARAMETER AlertThreshold
    Specifies the number of events that will trigger an alert.
    Default: 5

.PARAMETER AlertAction
    Specifies the action to take when an alert is triggered.
    Valid values: Console, Email, Event, All
    Default: Console

.PARAMETER EmailTo
    Specifies the email address to send alerts to when AlertAction is Email or All.

.PARAMETER LogPath
    Specifies the path where the script's log file will be created.
    Default: Current directory

.PARAMETER Verbose
    Provides detailed information about script execution.

.EXAMPLE
    .\Monitor-SecurityEvents.ps1
    Monitors all security events from the past 24 hours and displays them in the console.

.EXAMPLE
    .\Monitor-SecurityEvents.ps1 -EventTypes FailedLogins,AccountChanges -MaxEvents 50 -OutputFormat HTML -OutputPath "C:\Reports"
    Monitors failed logins and account changes, retrieves up to 50 events, and saves an HTML report to C:\Reports.

.EXAMPLE
    .\Monitor-SecurityEvents.ps1 -RealTime -AlertThreshold 3 -AlertAction Email -EmailTo "admin@example.com"
    Monitors security events in real-time and sends an email alert when 3 or more events occur.

.EXAMPLE
    .\Monitor-SecurityEvents.ps1 -EventTypes PolicyChanges -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date)
    Monitors security policy changes from the past week and displays them in the console.

.NOTES
    File Name      : Monitor-SecurityEvents.ps1
    Prerequisite   : PowerShell 5.1 or later
                     Administrator rights
    Author         : Your Name
    Version        : 1.0
    Creation Date  : 2023-05-20
#>

[CmdletBinding(DefaultParameterSetName = 'Standard')]
param (
    [Parameter(Position = 0)]
    [ValidateSet('All', 'FailedLogins', 'AccountChanges', 'PolicyChanges', 'IntegrityChanges', 
                'PrivilegeUsage', 'ObjectAccess', 'AuditEvents')]
    [string[]]$EventTypes = @('All'),
    
    [Parameter(Position = 1)]
    [ValidateRange(1, 10000)]
    [int]$MaxEvents = 100,
    
    [Parameter(Position = 2)]
    [ValidateSet('Console', 'CSV', 'HTML', 'JSON', 'XML')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Position = 3)]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Position = 4)]
    [datetime]$StartTime = (Get-Date).AddHours(-24),
    
    [Parameter(Position = 5)]
    [datetime]$EndTime = (Get-Date),
    
    [Parameter(ParameterSetName = 'RealTime')]
    [switch]$RealTime,
    
    [Parameter(ParameterSetName = 'RealTime')]
    [ValidateRange(1, 100)]
    [int]$AlertThreshold = 5,
    
    [Parameter(ParameterSetName = 'RealTime')]
    [ValidateSet('Console', 'Email', 'Event', 'All')]
    [string]$AlertAction = 'Console',
    
    [Parameter(ParameterSetName = 'RealTime')]
    [ValidatePattern('^[\w\.-]+@[\w\.-]+\.[A-Za-z]{2,}$')]
    [string]$EmailTo,
    
    [Parameter()]
    [ValidateScript({Test-Path $_ -IsValid})]
    [string]$LogPath = (Get-Location).Path
)

# Initialize script variables
$script:EventCount = 0
$script:AlertCount = 0
$script:LogFile = Join-Path -Path $LogPath -ChildPath "SecurityMonitor_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:ReportFile = Join-Path -Path $OutputPath -ChildPath "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Event IDs to monitor for each event type
$EventIDMap = @{
    FailedLogins     = @(4625, 4771, 4776)
    AccountChanges   = @(4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781)
    PolicyChanges    = @(4739, 4904, 4905, 4906, 4907, 4912, 4713)
    IntegrityChanges = @(4612, 4614, 4616, 4657, 5038, 6281)
    PrivilegeUsage   = @(4673, 4674, 4985, 4986)
    ObjectAccess     = @(4656, 4658, 4660, 4663, 4670)
    AuditEvents      = @(1102, 4715, 4719, 4907, 4946, 5124, 5376)
}

# Function to write to log file
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $script:LogFile -Value $LogEntry -ErrorAction Stop
        
        # If verbose is enabled, write to console as well
        if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
            $ColorMap = @{
                Information = 'White'
                Warning = 'Yellow'
                Error = 'Red'
            }
            Write-Host $LogEntry -ForegroundColor $ColorMap[$Level]
        }
    }
    catch {
        Write-Error "Failed to write to log file: $_"
    }
}

# Function to initialize script environment
function Initialize-SecurityMonitor {
    [CmdletBinding()]
    param()
    
    try {
        # Create output directory if it doesn't exist
        if (!(Test-Path -Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Log -Message "Created output directory: $OutputPath"
        }
        
        # Create log directory if it doesn't exist
        if (!(Test-Path -Path (Split-Path -Path $script:LogFile -Parent))) {
            New-Item -Path (Split-Path -Path $script:LogFile -Parent) -ItemType Directory -Force | Out-Null
            Write-Log -Message "Created log directory: $(Split-Path -Path $script:LogFile -Parent)"
        }
        
        Write-Log -Message "Security Monitor initialized."
        Write-Log -Message "Parameters: Event Types=$($EventTypes -join ',') MaxEvents=$MaxEvents OutputFormat=$OutputFormat RealTime=$RealTime"
        
        # Check if running as administrator
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log -Message "Script is not running with administrator privileges. Some events may not be accessible." -Level Warning
        }
    }
    catch {
        Write-Log -Message "Error initializing Security Monitor: $_" -Level Error
        throw $_
    }
}

# Function to get security events based on selected event types
function Get-SecurityEvents {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Types,
        
        [Parameter()]
        [int]$MaxEvents,
        
        [Parameter()]
        [datetime]$Start,
        
        [Parameter()]
        [datetime]$End
    )
    
    $EventIDs = @()
    
    try {
        # Determine which event IDs to query
        if ($Types -contains 'All') {
            foreach ($type in $EventIDMap.Keys) {
                $EventIDs += $EventIDMap[$type]
            }
        }
        else {
            foreach ($type in $Types) {
                if ($EventIDMap.ContainsKey($type)) {
                    $EventIDs += $EventIDMap[$type]
                }
            }
        }
        
        $EventIDs = $EventIDs | Select-Object -Unique
        
        Write-Log -Message "Querying for event IDs: $($EventIDs -join ', ')"
        Write-Log -Message "Time range: $($Start.ToString('yyyy-MM-dd HH:mm:ss')) to $($End.ToString('yyyy-MM-dd HH:mm:ss'))"
        
        # Create a filter for the events
        $FilterXPath = "(System.EventID=$($EventIDs -join ' or System.EventID='))"
        $FilterXPath += " and System.TimeCreated[@SystemTime>='$($Start.ToUniversalTime().ToString("o"))']"
        $FilterXPath += " and System.TimeCreated[@SystemTime<='$($End.ToUniversalTime().ToString("o"))']"
        
        # Display progress bar
        Write-Progress -Activity "Retrieving Security Events" -Status "Querying event log..." -PercentComplete 0
        
        # Get the events
        $Events = Get-WinEvent -LogName Security -FilterXPath $FilterXPath -MaxEvents $MaxEvents -ErrorAction Stop
        
        Write-Progress -Activity "Retrieving Security Events" -Status "Complete" -PercentComplete 100 -Completed
        
        Write-Log -Message "Retrieved $($Events.Count) security events."
        return $Events
    }
    catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
        Write-Log -Message "Security event log not found." -Level Error
        Write-Progress -Activity "Retrieving Security Events" -Status "Error" -PercentComplete 100 -Completed
        return @()
    }
    catch [System.ArgumentException] {
        # No events found matching criteria
        Write-Log -Message "No events found matching the specified criteria." -Level Warning
        Write-Progress -Activity "Retrieving Security Events" -Status "Complete" -PercentComplete 100 -Completed
        return @()
    }
    catch {
        Write-Log -Message "Error retrieving security events: $_" -Level Error
        Write-Progress -Activity "Retrieving Security Events" -Status "Error" -PercentComplete 100 -Completed
        return @()
    }
}

# Function to format events for different output types
function Format-SecurityEvents {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$Events,
        
        [Parameter(Mandatory = $true)]
        [string]$Format,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )
    
    try {
        # Create a more useful representation of the events
        $formattedEvents = foreach ($event in $Events) {
            # Convert the event message to an object with properties
            $eventData = @{
                TimeCreated = $event.TimeCreated
                EventID = $event.Id
                Level = [string]$event.LevelDisplayName
                Source = $event.ProviderName
                Description = $event.Message
                EventType = GetEventType -EventID $event.Id
                Computer = $event.MachineName
                UserName = ''
                ProcessName = ''
                IpAddress = ''
            }
            
            # Try to extract common properties from the event message
            try {
                if ($event.Message -match "Account Name:\s+([^\r\n]+)") {
                    $eventData.UserName = $matches[1].Trim()
                }
                
                if ($event.Message -match "Process Name:\s+([^\r\n]+)") {
                    $eventData.ProcessName = $matches[1].Trim()
                }
                
                if ($event.Message -match "Source Network Address:\s+([^\r\n]+)") {
                    $eventData.IpAddress = $matches[1].Trim()
                }
            }
            catch {
                # Ignore parsing errors and just use the basic event data
            }
            
            [PSCustomObject]$eventData
        }
        
        # Output the events in the desired format
        switch ($Format) {
            'Console' {
                return $formattedEvents
            }
            'CSV' {
                $outputFilePath = "$OutputFile.csv"
                $formattedEvents | Export-Csv -Path $outputFilePath -NoTypeInformation
                Write-Log -Message "Exported events to CSV file: $outputFilePath"
                return $outputFilePath
            }
            'HTML' {
                $outputFilePath = "$OutputFile.html"
                
                $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Events Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th { background-color: #0066cc; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
        .error { background-color: #ffe6e6; }
        .warning { background-color: #fffae6; }
        .summary { margin-top: 20px; padding: 10px; background-color: #e6f2ff; border-radius

