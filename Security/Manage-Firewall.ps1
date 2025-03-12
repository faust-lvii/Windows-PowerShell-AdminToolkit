#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Advanced Windows Firewall management script with comprehensive capabilities.

.DESCRIPTION
    This script provides a comprehensive set of functions to manage Windows Firewall,
    including viewing, adding, removing, and modifying firewall rules, configuring
    firewall profiles, importing/exporting rules, monitoring firewall activity,
    and generating reports.

.PARAMETER Action
    Specifies the action to perform. Valid values are:
    - ViewRules: Display current firewall rules
    - ViewStatus: Display firewall status
    - AddRule: Add a new firewall rule
    - RemoveRule: Remove an existing firewall rule
    - EnableRule: Enable a firewall rule
    - DisableRule: Disable a firewall rule
    - ConfigureProfile: Configure a firewall profile
    - ExportRules: Export firewall rules
    - ImportRules: Import firewall rules
    - Monitor: Monitor firewall activity
    - Backup: Backup firewall configuration
    - Restore: Restore firewall configuration
    - Report: Generate firewall reports

.PARAMETER Name
    Specifies the name of the firewall rule. Required for AddRule, RemoveRule, EnableRule, and DisableRule actions.

.PARAMETER Direction
    Specifies the direction of the rule. Valid values are "Inbound" and "Outbound". Used with AddRule.

.PARAMETER Action
    Specifies the action of the rule. Valid values are "Allow" and "Block". Used with AddRule.

.PARAMETER Protocol
    Specifies the protocol for the rule. Common values are "TCP", "UDP", "Any". Used with AddRule.

.PARAMETER LocalPort
    Specifies the local port for the rule. Used with AddRule.

.PARAMETER RemotePort
    Specifies the remote port for the rule. Used with AddRule.

.PARAMETER LocalAddress
    Specifies the local address for the rule. Used with AddRule.

.PARAMETER RemoteAddress
    Specifies the remote address for the rule. Used with AddRule.

.PARAMETER Program
    Specifies the program path for the rule. Used with AddRule.

.PARAMETER Service
    Specifies the service name for the rule. Used with AddRule.

.PARAMETER Description
    Provides a description for the rule. Used with AddRule.

.PARAMETER Enabled
    Specifies whether the rule is enabled. Valid values are $true and $false. Used with AddRule.

.PARAMETER Profile
    Specifies the profile name to configure. Valid values are "Domain", "Private", "Public", "All". Used with ConfigureProfile.

.PARAMETER Status
    Specifies the status to set for a profile. Valid values are "Enabled" and "Disabled". Used with ConfigureProfile.

.PARAMETER Path
    Specifies the file path for import/export operations or backup/restore operations.

.PARAMETER OutputFormat
    Specifies the output format for reports. Valid values are "Console", "CSV", "HTML", "JSON", "XML".

.PARAMETER LogPath
    Specifies the path where log files will be stored.

.PARAMETER Detailed
    Indicates whether to show detailed information in reports.

.PARAMETER Force
    Indicates whether to force the operation without confirmation.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action ViewRules
    Shows all firewall rules currently configured.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action ViewRules -OutputFormat HTML -Path "C:\Reports\FirewallRules.html"
    Exports all firewall rules to an HTML file.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action AddRule -Name "Allow RDP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 -Description "Allow Remote Desktop"
    Adds a new firewall rule to allow RDP connections.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action RemoveRule -Name "Allow RDP"
    Removes the firewall rule named "Allow RDP".

.EXAMPLE
    .\Manage-Firewall.ps1 -Action EnableRule -Name "Allow RDP"
    Enables the firewall rule named "Allow RDP".

.EXAMPLE
    .\Manage-Firewall.ps1 -Action ConfigureProfile -Profile Public -Status Enabled
    Enables the Public firewall profile.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action Backup -Path "C:\Backup\FirewallConfig.wfw"
    Backs up the current firewall configuration to a file.

.EXAMPLE
    .\Manage-Firewall.ps1 -Action Report -OutputFormat CSV -Path "C:\Reports\FirewallReport.csv" -Detailed
    Generates a detailed firewall report in CSV format.

.NOTES
    File Name      : Manage-Firewall.ps1
    Author         : 
    Prerequisite   : PowerShell V5.1, Administrative privileges
    Copyright      : 

.LINK
    https://docs.microsoft.com/en-us/powershell/module/netsecurity/
#>

[CmdletBinding(DefaultParameterSetName = "ViewRules")]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet("ViewRules", "ViewStatus", "AddRule", "RemoveRule", "EnableRule", "DisableRule", "ConfigureProfile", "ExportRules", "ImportRules", "Monitor", "Backup", "Restore", "Report")]
    [string]$Action,

    [Parameter(ParameterSetName = "AddRule", Mandatory = $true)]
    [Parameter(ParameterSetName = "RemoveRule", Mandatory = $true)]
    [Parameter(ParameterSetName = "EnableRule", Mandatory = $true)]
    [Parameter(ParameterSetName = "DisableRule", Mandatory = $true)]
    [string]$Name,

    [Parameter(ParameterSetName = "AddRule")]
    [ValidateSet("Inbound", "Outbound")]
    [string]$Direction = "Inbound",

    [Parameter(ParameterSetName = "AddRule")]
    [ValidateSet("Allow", "Block")]
    [string]$RuleAction = "Allow",

    [Parameter(ParameterSetName = "AddRule")]
    [string]$Protocol = "TCP",

    [Parameter(ParameterSetName = "AddRule")]
    [string]$LocalPort,

    [Parameter(ParameterSetName = "AddRule")]
    [string]$RemotePort,

    [Parameter(ParameterSetName = "AddRule")]
    [string]$LocalAddress,

    [Parameter(ParameterSetName = "AddRule")]
    [string]$RemoteAddress,

    [Parameter(ParameterSetName = "AddRule")]
    [string]$Program,

    [Parameter(ParameterSetName = "AddRule")]
    [string]$Service,

    [Parameter(ParameterSetName = "AddRule")]
    [string]$Description,

    [Parameter(ParameterSetName = "AddRule")]
    [bool]$Enabled = $true,

    [Parameter(ParameterSetName = "ConfigureProfile", Mandatory = $true)]
    [ValidateSet("Domain", "Private", "Public", "All")]
    [string]$Profile,

    [Parameter(ParameterSetName = "ConfigureProfile", Mandatory = $true)]
    [ValidateSet("Enabled", "Disabled")]
    [string]$Status,

    [Parameter(ParameterSetName = "ExportRules")]
    [Parameter(ParameterSetName = "ImportRules", Mandatory = $true)]
    [Parameter(ParameterSetName = "Backup", Mandatory = $true)]
    [Parameter(ParameterSetName = "Restore", Mandatory = $true)]
    [Parameter(ParameterSetName = "Report")]
    [string]$Path,

    [Parameter(ParameterSetName = "ViewRules")]
    [Parameter(ParameterSetName = "ViewStatus")]
    [Parameter(ParameterSetName = "Report")]
    [ValidateSet("Console", "CSV", "HTML", "JSON", "XML")]
    [string]$OutputFormat = "Console",

    [string]$LogPath = "$env:USERPROFILE\Documents\FirewallLogs",

    [switch]$Detailed,

    [switch]$Force
)

#Region Functions

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logFile = Join-Path -Path $LogPath -ChildPath "Firewall_$(Get-Date -Format 'yyyyMMdd').log"
    
    # Create directory if it doesn't exist
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $logFile -Value $logEntry -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $_"
    }
    
    # Output to console based on level
    switch ($Level) {
        "INFO" { Write-Verbose $logEntry }
        "WARNING" { Write-Warning $logEntry }
        "ERROR" { Write-Error $logEntry }
        "DEBUG" { Write-Debug $logEntry }
    }
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Show-Progress {
    param (
        [int]$PercentComplete,
        [string]$Status,
        [int]$Id = 0
    )
    
    Write-Progress -Activity "Firewall Management Operation" -Status $Status -PercentComplete $PercentComplete -Id $Id
}

function Get-FirewallRules {
    [CmdletBinding()]
    param(
        [string]$Name = "*",
        [switch]$Detailed
    )
    
    Write-Log "Retrieving firewall rules matching: $Name"
    Show-Progress -PercentComplete 10 -Status "Retrieving firewall rules..."
    
    try {
        if ($Detailed) {
            $rules = Get-NetFirewallRule -Name $Name -ErrorAction Stop | 
                ForEach-Object {
                    Show-Progress -PercentComplete 50 -Status "Processing rule details..."
                    
                    $rule = $_
                    $ports = $null
                    $appFilter = $null
                    $serviceFilter = $null
                    $addressFilter = $null
                    
                    try {
                        $addressFilter = $rule | Get-NetFirewallAddressFilter
                        $portFilter = $rule | Get-NetFirewallPortFilter
                        $appFilter = $rule | Get-NetFirewallApplicationFilter
                        $serviceFilter = $rule | Get-NetFirewallServiceFilter
                    }
                    catch {
                        Write-Log "Error retrieving details for rule $($rule.Name): $_" -Level "WARNING"
                    }
                    
                    [PSCustomObject]@{
                        Name = $rule.Name
                        DisplayName = $rule.DisplayName
                        Description = $rule.Description
                        Direction = $rule.Direction
                        Action = $rule.Action
                        Enabled = $rule.Enabled
                        Profile = $rule.Profile
                        Protocol = $portFilter.Protocol
                        LocalPort = $portFilter.LocalPort -join ','
                        RemotePort = $portFilter.RemotePort -join ','
                        LocalAddress = $addressFilter.LocalAddress -join ','
                        RemoteAddress = $addressFilter.RemoteAddress -join ','
                        Program = $appFilter.Program
                        Service = $serviceFilter.Service
                        Group = $rule.Group
                    }
                }
        }
        else {
            $rules = Get-NetFirewallRule -Name $Name -ErrorAction Stop | 
                Select-Object Name, DisplayName, Description, Direction, Action, Enabled, Profile, Group
        }
        
        Show-Progress -PercentComplete 100 -Status "Retrieved firewall rules"
        Write-Log "Successfully retrieved $($rules.Count) firewall rules"
        return $rules
    }
    catch {
        Write-Log "Error retrieving firewall rules: $_" -Level "ERROR"
        throw "Failed to retrieve firewall rules: $_"
    }
}

function Get-FirewallStatus {
    [CmdletBinding()]
    param()
    
    Write-Log "Retrieving firewall profile status"
    Show-Progress -PercentComplete 10 -Status "Retrieving firewall profile status..."
    
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        Show-Progress -PercentComplete 100 -Status "Retrieved firewall profile status"
        Write-Log "Successfully retrieved firewall profile status"
        return $profiles
    }
    catch {
        Write-Log "Error retrieving firewall profile status: $_" -Level "ERROR"
        throw "Failed to retrieve firewall profile status: $_"
    }
}

function Add-FirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [ValidateSet("Inbound", "Outbound")]
        [string]$Direction = "Inbound",
        
        [ValidateSet("Allow", "Block")]
        [string]$RuleAction = "Allow",
        
        [string]$Protocol = "TCP",
        
        [string]$LocalPort,
        
        [string]$RemotePort,
        
        [string]$LocalAddress,
        
        [string]$RemoteAddress,
        
        [string]$Program,
        
        [string]$Service,
        
        [string]$Description,
        
        [bool]$Enabled = $true,
        
        [ValidateSet("Domain", "Private", "Public", "Any")]
        [string[]]$ProfileType = @("Any")
    )
    
    Write-Log "Adding new firewall rule: $Name"
    Show-Progress -PercentComplete 10 -Status "Validating rule parameters..."
    
    # Parameter validation
    $params = @{
        Name = $Name
        DisplayName = $Name
        Direction = $Direction
        Action = $RuleAction
        Enabled = $Enabled
    }
    
    if ($Description) {
        $params.Add("Description", $Description)
    }
    
    if ($Protocol -ne "Any") {
        $params.Add("Protocol", $Protocol)
    }
    
    if ($LocalPort) {
        $params.Add("LocalPort", $LocalPort)
    }
    
    if ($RemotePort) {
        $params.Add("RemotePort", $RemotePort)
    }
    
    if ($LocalAddress) {
        $params.Add("LocalAddress", $LocalAddress)
    }
    
    if ($RemoteAddress) {
        $params.Add("RemoteAddress", $RemoteAddress)
    }
    
    if ($Program) {
        $params.Add("Program", $Program)
    }
    
    if ($Service) {
        $params.Add("Service",

