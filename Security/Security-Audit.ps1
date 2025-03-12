<#
.SYNOPSIS
    Performs a comprehensive security audit on Windows systems.

.DESCRIPTION
    The Invoke-SecurityAudit script performs a detailed security assessment of a Windows system.
    It checks user accounts, password policies, system security settings, firewall configurations,
    service security, file permissions, registry security, and analyzes event logs for security issues.
    The script generates detailed reports in multiple formats and provides security recommendations.

.PARAMETER ComputerName
    Specifies the target computer name. Defaults to the local computer.

.PARAMETER OutputPath
    Specifies the path where the report will be saved. Defaults to the current directory.

.PARAMETER OutputFormat
    Specifies the output format(s) for the report. Valid options are "HTML", "CSV", "JSON", and "XML".
    You can specify multiple formats separated by commas.

.PARAMETER CheckUserAccounts
    Performs user account security checks.

.PARAMETER CheckPasswordPolicies
    Performs password policy checks.

.PARAMETER CheckSystemSecurity
    Performs system security settings checks.

.PARAMETER CheckFirewall
    Performs firewall configuration checks.

.PARAMETER CheckServices
    Performs service security checks.

.PARAMETER CheckFilePermissions
    Performs file permission audits.

.PARAMETER FilePaths
    Specifies the paths to check for file permissions. Only used with -CheckFilePermissions.

.PARAMETER CheckRegistry
    Performs registry security checks.

.PARAMETER CheckEventLogs
    Performs event log security analysis.

.PARAMETER EventLogAge
    Specifies how many days of event logs to analyze. Defaults to 7 days.

.PARAMETER BaselinePath
    Path to a security baseline file to compare against.

.PARAMETER Severity
    Filter results by minimum severity level. Options are "Low", "Medium", "High", "Critical". Defaults to "Low".

.PARAMETER EnableLogging
    Enables logging of audit actions.

.PARAMETER LogPath
    Specifies the path for the log file. Defaults to "SecurityAudit.log" in the current directory.

.EXAMPLE
    .\Invoke-SecurityAudit.ps1
    Performs a full security audit on the local computer using default settings.

.EXAMPLE
    .\Invoke-SecurityAudit.ps1 -ComputerName "Server01" -OutputFormat "HTML,CSV" -OutputPath "C:\Reports"
    Performs a full security audit on Server01 and generates reports in HTML and CSV formats in C:\Reports.

.EXAMPLE
    .\Invoke-SecurityAudit.ps1 -CheckUserAccounts -CheckPasswordPolicies -Severity "High"
    Performs only user account and password policy checks, filtering for high severity issues.

.EXAMPLE
    .\Invoke-SecurityAudit.ps1 -CheckFilePermissions -FilePaths "C:\Sensitive","C:\Program Files"
    Audits file permissions only for the specified directories.

.EXAMPLE
    .\Invoke-SecurityAudit.ps1 -BaselinePath "C:\Baselines\Baseline.json" -OutputFormat "JSON"
    Compares audit results against a baseline and outputs the results in JSON format.

.NOTES
    Author: Security Team
    Version: 1.0
    Date: [Current Date]
    Requires: PowerShell 5.1 or later, and administrative privileges for most checks.
#>

[CmdletBinding(DefaultParameterSetName="All")]
param (
    [Parameter(Position=0)]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter()]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter()]
    [ValidateSet("HTML", "CSV", "JSON", "XML")]
    [string[]]$OutputFormat = @("HTML"),
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckUserAccounts,
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckPasswordPolicies,
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckSystemSecurity,
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckFirewall,
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckServices,
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckFilePermissions,
    
    [Parameter()]
    [string[]]$FilePaths = @("C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)"),
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckRegistry,
    
    [Parameter(ParameterSetName="Selected")]
    [switch]$CheckEventLogs,
    
    [Parameter()]
    [int]$EventLogAge = 7,
    
    [Parameter()]
    [string]$BaselinePath = "",
    
    [Parameter()]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$Severity = "Low",
    
    [Parameter()]
    [switch]$EnableLogging,
    
    [Parameter()]
    [string]$LogPath = "SecurityAudit.log"
)

#region Helper Functions

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    if (-not $EnableLogging) {
        return
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $LogPath -Value $logMessage -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Write-StatusMessage {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $colors = @{
        "INFO" = "White"
        "WARNING" = "Yellow"
        "ERROR" = "Red"
        "SUCCESS" = "Green"
    }
    
    Write-Host $Message -ForegroundColor $colors[$Level]
    Write-Log -Message $Message -Level $Level
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Convert-SeverityToInt {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$SeverityLevel
    )
    
    switch ($SeverityLevel) {
        "Low" { return 1 }
        "Medium" { return 2 }
        "High" { return 3 }
        "Critical" { return 4 }
        default { return 0 }
    }
}

function Should-IncludeFinding {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$FindingSeverity
    )
    
    $minSeverityInt = Convert-SeverityToInt -SeverityLevel $Severity
    $findingSeverityInt = Convert-SeverityToInt -SeverityLevel $FindingSeverity
    
    return $findingSeverityInt -ge $minSeverityInt
}

function New-Finding {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$Severity,
        
        [Parameter(Mandatory=$true)]
        [bool]$Compliant,
        
        [Parameter()]
        [string]$Recommendation = "",
        
        [Parameter()]
        [object]$Data = $null
    )
    
    if (-not (Should-IncludeFinding -FindingSeverity $Severity)) {
        return $null
    }
    
    return [PSCustomObject]@{
        Category = $Category
        Title = $Title
        Description = $Description
        Severity = $Severity
        Compliant = $Compliant
        Recommendation = $Recommendation
        Data = $Data
        Timestamp = Get-Date
    }
}

function Get-SeverityColor {
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$Severity
    )
    
    switch ($Severity) {
        "Low" { return "#4CAF50" } # Green
        "Medium" { return "#FF9800" } # Orange
        "High" { return "#F44336" } # Red
        "Critical" { return "#9C27B0" } # Purple
        default { return "#2196F3" } # Blue
    }
}

#endregion

#region Audit Functions

function Invoke-UserAccountSecurityCheck {
    [CmdletBinding()]
    param()
    
    Write-StatusMessage -Message "Starting user account security checks..." -Level "INFO"
    $findings = @()
    
    try {
        # Check local administrators
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        if ($adminGroup.Count -gt 3) {
            $findings += New-Finding -Category "User Accounts" -Title "Excessive Administrator Accounts" `
                -Description "There are $($adminGroup.Count) administrator accounts on the system." `
                -Severity "Medium" -Compliant $false `
                -Recommendation "Review administrator accounts and remove unnecessary privileges." `
                -Data $adminGroup
        }
        
        # Check for accounts with never expiring passwords
        $neverExpiringAccounts = Get-LocalUser | Where-Object { $_.PasswordNeverExpires -eq $true }
        if ($neverExpiringAccounts.Count -gt 0) {
            $findings += New-Finding -Category "User Accounts" -Title "Accounts With Non-Expiring Passwords" `
                -Description "$($neverExpiringAccounts.Count) accounts have passwords that never expire." `
                -Severity "Medium" -Compliant $false `
                -Recommendation "Configure password expiration for all accounts unless specifically exempted." `
                -Data $neverExpiringAccounts
        }
        
        # Check for disabled accounts
        $disabledAccounts = Get-LocalUser | Where-Object { -not $_.Enabled }
        if ($disabledAccounts.Count -gt 0) {
            $findings += New-Finding -Category "User Accounts" -Title "Disabled User Accounts" `
                -Description "$($disabledAccounts.Count) accounts are disabled." `
                -Severity "Low" -Compliant $true `
                -Recommendation "Review disabled accounts and remove if no longer needed." `
                -Data $disabledAccounts
        }
        
        # Check for accounts with no password required
        $noPasswordAccounts = Get-LocalUser | Where-Object { -not $_.PasswordRequired }
        if ($noPasswordAccounts.Count -gt 0) {
            $findings += New-Finding -Category "User Accounts" -Title "Accounts Without Password Requirements" `
                -Description "$($noPasswordAccounts.Count) accounts do not require passwords." `
                -Severity "Critical" -Compliant $false `
                -Recommendation "Configure password requirements for all accounts." `
                -Data $noPasswordAccounts
        }
        
        # Check for guest account status
        $guestAccount = Get-LocalUser | Where-Object { $_.Name -eq "Guest" }
        if ($guestAccount -and $guestAccount.Enabled) {
            $findings += New-Finding -Category "User Accounts" -Title "Guest Account Enabled" `
                -Description "The Guest account is currently enabled." `
                -Severity "High" -Compliant $false `
                -Recommendation "Disable the Guest account." `
                -Data $guestAccount
        }
        
        Write-StatusMessage -Message "User account security checks completed." -Level "SUCCESS"
    }
    catch {
        Write-StatusMessage -Message "Error during user account security checks: $($_.Exception.Message)" -Level "ERROR"
    }
    
    return $findings
}

function Invoke-PasswordPolicyCheck {
    [CmdletBinding()]
    param()
    
    Write-StatusMessage -Message "Starting password policy checks..." -Level "INFO"
    $findings = @()
    
    try {
        # Get password policy
        $passwordPolicy = net accounts | Out-String
        
        # Check minimum password length
        if ($passwordPolicy -match "Minimum password length\s+\((\d+)\)") {
            $minLength = [int]$Matches[1]
            if ($minLength -lt 12) {
                $findings += New-Finding -Category "Password Policy" -Title "Insufficient Password Length" `
                    -Description "Minimum password length is set to $minLength characters." `
                    -Severity "Medium" -Compliant $false `
                    -Recommendation "Set minimum password length to at least 12 characters." `
                    -Data $passwordPolicy
            }
        }
        
        # Check password complexity
        try {
            $securitySettings = secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
            $securityPolicy = Get-Content "$env:TEMP\secpol.cfg" | Out-String
            
            if ($securityPolicy -match "PasswordComplexity\s+=\s+(\d+)") {
                $complexityEnabled = [int]$Matches[1] -eq 1
                if (-not $complexityEnabled) {
                    $findings += New-Finding -Category "Password Policy" -Title "Password Complexity Disabled" `
                        -Description "Password complexity requirements are not enabled." `
                        -Severity "High" -Compliant $false `
                        -Recommendation "Enable password complexity requirements." `
                        -Data $securityPolicy
                }
            }
            
            # Clean up temp file
            Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-StatusMessage -Message "Error checking password complexity: $($_.Exception.Message)" -Level "ERROR"
        }
        
        # Check password age
        if ($passwordPolicy -match "Maximum password age\s+\((\d+)\)") {
            $maxAge = [int]$Matches[1]
            if ($maxAge -eq 0 -or $maxAge -gt 90) {
                $findings += New-Finding -Category "Password Policy" -Title "Password Age Policy Issues" `
                    -Description "Maximum password age is set to $($maxAge) days." `
                    -Severity "Medium" -Compliant $false `
                    -Recommendation "Set maximum password age to 90 days or less." `
                    -Data $passwordPolicy
            }
        }
        
        # Check password history
        if ($passwordPolicy -match "Length of password history maintained\s+\((\d+)\)") {
            $historyCount = [int]$Matches[1]
            if ($historyCount -lt 10) {
                $findings += New-Finding -Category "Password Policy" -Title "Insufficient Password History" `
                    -Description "Password history is

