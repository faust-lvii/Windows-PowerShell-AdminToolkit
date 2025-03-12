<#
.SYNOPSIS
    Comprehensive file permission auditor for Windows systems.
    
.DESCRIPTION
    Audit-FilePermissions.ps1 is a PowerShell script that provides comprehensive auditing and 
    management of file and folder permissions. It scans specified paths to identify improper
    permissions, inheritance settings, and security vulnerabilities. The script can generate
    detailed reports in various formats, track changes over time, compare against security
    baselines, and provide remediation recommendations or automatically apply fixes.
    
.PARAMETER Path
    The file or folder path to audit. Accepts pipeline input.
    
.PARAMETER Recurse
    If specified, scans subfolders recursively.
    
.PARAMETER ExcludePath
    Specifies paths to exclude from the audit.
    
.PARAMETER OutputFormat
    Specifies the report output format. Valid values are: Console, CSV, HTML, XML, JSON.
    Default is Console.
    
.PARAMETER OutputPath
    Specifies the path where reports will be saved.
    
.PARAMETER LogPath
    Specifies the path where logs will be saved.
    
.PARAMETER BaselinePath
    Path to a permissions baseline file to compare against.
    
.PARAMETER SaveBaseline
    If specified, saves the current permissions as a baseline.
    
.PARAMETER BaselineName
    Name for the saved baseline file.
    
.PARAMETER FixPermissions
    If specified, attempts to fix identified permission issues.
    
.PARAMETER WhatIf
    Shows what would happen if the script runs. No changes are made.
    
.PARAMETER SeverityThreshold
    Filter results by minimum severity level. Valid values are: Low, Medium, High, Critical.
    
.EXAMPLE
    PS> .\Audit-FilePermissions.ps1 -Path C:\Data -Recurse -OutputFormat HTML -OutputPath C:\Reports
    
    Performs a recursive audit of the C:\Data directory and outputs results as HTML to C:\Reports
    
.EXAMPLE
    PS> .\Audit-FilePermissions.ps1 -Path C:\Web -BaselinePath C:\Baselines\web_baseline.json -OutputFormat CSV
    
    Audits the C:\Web directory and compares the results against a baseline, then exports to CSV
    
.EXAMPLE
    PS> Get-ChildItem -Path C:\ImportantData | .\Audit-FilePermissions.ps1 -FixPermissions
    
    Audits all items in C:\ImportantData via pipeline and automatically applies permission fixes
    
.NOTES
    Author: System Administrator
    Version: 1.0
    Created: 2023-10-31
    Requirements: Windows PowerShell 5.1 or PowerShell 7+, elevated permissions for certain operations
    
.LINK
    https://github.com/YourUsername/Windows-PowerShell-AdminToolkit
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias("FullName")]
    [string[]]$Path,
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludePath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Console", "CSV", "HTML", "XML", "JSON")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$env:TEMP\FilePermissionAudit",
    
    [Parameter(Mandatory=$false)]
    [string]$BaselinePath,
    
    [Parameter(Mandatory=$false)]
    [switch]$SaveBaseline,
    
    [Parameter(Mandatory=$false)]
    [string]$BaselineName = "permissions_baseline_$(Get-Date -Format 'yyyyMMdd')",
    
    [Parameter(Mandatory=$false)]
    [switch]$FixPermissions,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Low", "Medium", "High", "Critical")]
    [string]$SeverityThreshold = "Low"
)

begin {
    #region Initialize Script
    
    # Script version
    $ScriptVersion = "1.0"
    
    # Start timestamp
    $StartTime = Get-Date
    
    # Severity levels mapping
    $SeverityLevels = @{
        "Low" = 1
        "Medium" = 2
        "High" = 3
        "Critical" = 4
    }
    
    $SeverityThresholdValue = $SeverityLevels[$SeverityThreshold]
    
    # Create output directory if it doesn't exist
    if ($OutputPath -and -not (Test-Path -Path $OutputPath)) {
        try {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created output directory: $OutputPath"
        }
        catch {
            Write-Error "Failed to create output directory: $_"
            exit 1
        }
    }
    
    # Initialize logging
    $LogFileName = "PermissionAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    $LogFilePath = Join-Path -Path $LogPath -ChildPath $LogFileName
    
    # Create log directory if it doesn't exist
    if (-not (Test-Path -Path $LogPath)) {
        try {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }
        catch {
            Write-Error "Failed to create log directory: $_"
            exit 1
        }
    }
    
    # Log function
    function Write-Log {
        param (
            [Parameter(Mandatory=$true)]
            [string]$Message,
            
            [Parameter(Mandatory=$false)]
            [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
            [string]$Level = "INFO"
        )
        
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        # Write to log file
        try {
            Add-Content -Path $LogFilePath -Value $LogEntry -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to write to log file: $_"
        }
        
        # Output to console with appropriate color
        switch ($Level) {
            "INFO"    { Write-Verbose $Message }
            "WARNING" { Write-Warning $Message }
            "ERROR"   { Write-Error $Message }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        }
    }
    
    # Initialize results array
    $AuditResults = @()
    
    # Import baseline if specified
    $Baseline = $null
    if ($BaselinePath -and (Test-Path -Path $BaselinePath)) {
        try {
            $Baseline = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
            Write-Log -Message "Loaded baseline from $BaselinePath" -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to load baseline from $BaselinePath: $_" -Level "ERROR"
        }
    }
    
    # Check if running as administrator
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $IsAdmin) {
        Write-Log -Message "Script is not running with administrator privileges. Some functions may be limited." -Level "WARNING"
    }
    
    # Known risky permissions
    $RiskyPermissions = @(
        "FullControl",
        "Write",
        "Modify"
    )
    
    # Known secure principals (modify as needed for your environment)
    $SecurePrincipals = @(
        "NT AUTHORITY\SYSTEM",
        "BUILTIN\Administrators"
    )
    
    # Initialize progress counter
    $TotalItems = 0
    $ProcessedItems = 0
    
    Write-Log -Message "Starting file permission audit - Script version $ScriptVersion" -Level "INFO"
    Write-Log -Message "Parameters: Path=$Path, Recurse=$Recurse, OutputFormat=$OutputFormat" -Level "INFO"
    
    #endregion Initialize Script
}

process {
    #region Process Files
    
    foreach ($CurrentPath in $Path) {
        # Validate path exists
        if (-not (Test-Path -Path $CurrentPath)) {
            Write-Log -Message "Path does not exist: $CurrentPath" -Level "ERROR"
            continue
        }
        
        # Get items to process
        try {
            $Items = Get-ChildItem -Path $CurrentPath -Recurse:$Recurse -Force -ErrorAction Stop
            
            # Filter excluded paths
            if ($ExcludePath) {
                $Items = $Items | Where-Object {
                    $Item = $_
                    -not ($ExcludePath | Where-Object { $Item.FullName -like $_ })
                }
            }
            
            $TotalItems = $Items.Count
            Write-Log -Message "Found $TotalItems items to audit in $CurrentPath" -Level "INFO"
        }
        catch {
            Write-Log -Message "Failed to get items from $CurrentPath`: $_" -Level "ERROR"
            continue
        }
        
        # Process each item
        foreach ($Item in $Items) {
            # Update progress
            $ProcessedItems++
            $ProgressPercentage = [math]::Min(100, [math]::Round(($ProcessedItems / $TotalItems) * 100))
            
            Write-Progress -Activity "Auditing File Permissions" -Status "Processing $($Item.FullName)" `
                -PercentComplete $ProgressPercentage -CurrentOperation "$ProcessedItems of $TotalItems items ($ProgressPercentage%)"
            
            # Get ACL
            try {
                $Acl = Get-Acl -Path $Item.FullName -ErrorAction Stop
                Write-Log -Message "Processing item: $($Item.FullName)" -Level "INFO"
            }
            catch {
                Write-Log -Message "Failed to get ACL for $($Item.FullName): $_" -Level "ERROR"
                
                # Add to results with error status
                $AuditResults += [PSCustomObject]@{
                    Path = $Item.FullName
                    ItemType = $Item.PSIsContainer ? "Directory" : "File"
                    AccessRules = $null
                    IsInherited = $null
                    InheritanceEnabled = $null
                    Owner = $null
                    Issues = @("Failed to get ACL information")
                    Severity = "Critical"
                    SeverityValue = 4
                    Recommendations = @("Investigate permission issues on this item")
                    Timestamp = Get-Date
                    Status = "Error"
                }
                
                continue
            }
            
            # Initialize issues and recommendations arrays
            $Issues = @()
            $Recommendations = @()
            $MaxSeverity = "Low"
            $MaxSeverityValue = 1
            
            # Check inheritance
            $InheritanceEnabled = -not $Acl.AreAccessRulesProtected
            if (-not $InheritanceEnabled -and $Item.PSIsContainer) {
                $Issues += "Inheritance disabled on directory"
                $Recommendations += "Review inheritance settings and consider enabling inheritance if appropriate"
                $MaxSeverity = "Medium"
                $MaxSeverityValue = 2
            }
            
            # Check owner
            $Owner = $Acl.Owner
            if (-not $SecurePrincipals.Contains($Owner)) {
                $Issues += "Owner not in list of secure principals: $Owner"
                $Recommendations += "Review ownership and consider transferring to a secure principal"
                $MaxSeverity = [Math]::Max($MaxSeverityValue, 2)
                $MaxSeverityValue = 2
            }
            
            # Check access rules
            $AccessRuleInfo = @()
            foreach ($AccessRule in $Acl.Access) {
                $IsInherited = $AccessRule.IsInherited
                $IdentityReference = $AccessRule.IdentityReference.Value
                $AccessControlType = $AccessRule.AccessControlType.ToString()
                $FileSystemRights = $AccessRule.FileSystemRights.ToString()
                
                # Add to access rule info
                $AccessRuleInfo += [PSCustomObject]@{
                    Principal = $IdentityReference
                    Rights = $FileSystemRights
                    Type = $AccessControlType
                    Inherited = $IsInherited
                }
                
                # Check for risky permissions
                if ($AccessControlType -eq "Allow") {
                    foreach ($RiskyPermission in $RiskyPermissions) {
                        if ($FileSystemRights -match $RiskyPermission) {
                            # Check if principal is in secure list
                            if (-not $SecurePrincipals.Contains($IdentityReference)) {
                                $CurrentSeverity = "Medium"
                                $CurrentSeverityValue = 2
                                
                                # Increase severity for Everyone, Authenticated Users with broad permissions
                                if ($IdentityReference -match "Everyone|Authenticated Users" -and 
                                    $FileSystemRights -match "FullControl|Modify") {
                                    $CurrentSeverity = "Critical"
                                    $CurrentSeverityValue = 4
                                }
                                # High severity for non-inherited permissions
                                elseif (-not $IsInherited) {
                                    $CurrentSeverity = "High"
                                    $CurrentSeverityValue = 3
                                }
                                
                                $Issues += "$IdentityReference has $RiskyPermission permission ($CurrentSeverity)"
                                $Recommendations += "Review and restrict $IdentityReference's $RiskyPermission permission"
                                
                                if ($CurrentSeverityValue -gt $MaxSeverityValue) {
                                    $MaxSeverity = $CurrentSeverity
                                    $MaxSeverityValue = $CurrentSeverityValue
                                }
                            }
                        }
                    }
                }
            }
            
            # Compare with baseline if provided
            if ($Baseline) {
                $BaselineItem = $Baseline | Where-Object { $_.Path -eq $Item.FullName }
                if ($BaselineItem) {
                    # Compare access rules
                    foreach ($CurrentRule in $AccessRuleInfo) {
                        $MatchingRule = $BaselineItem.AccessRules | Where-Object { 
                            $_.Principal -eq $CurrentRule.Principal -and 
                            $_.Rights -eq $CurrentRule.Rights -and 
                            $_.Type -eq $CurrentRule.Type 
                        }
                        
                        if (-not $MatchingRule) {
                            $Issues += "New permission rule found: $($CurrentRule.Principal) has $($CurrentRule.Rights) ($($CurrentRule.Type))"
                            $Recommendations += "Verify if the new permission is authorized"
                            
                            if ($MaxSeverityValue -lt 3) {
                                $MaxSeverity = "High"
                                $MaxSeverityValue = 3
                            }
                        }
                    }
                    
                    # Check for removed rules
                    foreach ($BaselineRule in $BaselineItem.AccessRules) {
                        $MatchingRule = $AccessRuleInfo | Where-Object { 

