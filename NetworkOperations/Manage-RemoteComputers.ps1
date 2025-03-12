#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Manages remote computers with various remote operation capabilities.

.DESCRIPTION
    The Manage-RemoteComputers script provides a comprehensive toolset for remote computer management.
    It supports various remote operations including PowerShell sessions, WMI/CIM queries, file operations,
    process management, service control, and registry modifications. The script includes credential 
    management, progress tracking, report generation, logging, and robust error handling.

.PARAMETER ComputerName
    Specifies the name(s) of remote computers to manage. Accepts pipeline input.

.PARAMETER Credential
    Specifies the credentials to use for remote operations. If not provided, current user credentials are used.

.PARAMETER Operation
    Specifies the operation to perform. Valid values are:
    - TestConnection: Test connectivity to remote computers
    - PSSession: Create PowerShell remote sessions
    - ExecuteCommand: Execute commands remotely
    - GetProcesses: Get process information from remote computers
    - GetServices: Get service information from remote computers
    - ManageService: Start, stop, or restart services on remote computers
    - FileOperation: Perform file operations on remote computers
    - RegistryOperation: Perform registry operations on remote computers
    - GetSystemInfo: Get system information from remote computers

.PARAMETER Protocol
    Specifies the protocol to use for remote operations. Valid values are:
    - WinRM (Default): Uses Windows Remote Management
    - DCOM: Uses Distributed COM
    - SSH: Uses Secure Shell (requires PowerShell 6.0+)

.PARAMETER ServiceName
    Specifies the name of the service when using the ManageService operation.

.PARAMETER ServiceAction
    Specifies the action to perform on services. Valid values are Start, Stop, Restart, Query.

.PARAMETER Command
    Specifies the command to execute when using the ExecuteCommand operation.

.PARAMETER SourcePath
    Specifies the source path for file operations.

.PARAMETER DestinationPath
    Specifies the destination path for file operations.

.PARAMETER FileOperation
    Specifies the file operation to perform. Valid values are Copy, Move, Delete.

.PARAMETER RegistryPath
    Specifies the registry path for registry operations.

.PARAMETER RegistryKey
    Specifies the registry key for registry operations.

.PARAMETER RegistryValue
    Specifies the registry value for registry operations.

.PARAMETER RegistryOperation
    Specifies the registry operation to perform. Valid values are Read, Write, Delete.

.PARAMETER OutputPath
    Specifies the path where reports will be saved.

.PARAMETER LogPath
    Specifies the path where logs will be saved. Default is "$env:TEMP\RemoteManagement.log".

.PARAMETER Parallel
    Specifies whether to perform operations in parallel using jobs.

.PARAMETER Timeout
    Specifies the timeout in seconds for remote operations. Default is 120 seconds.

.PARAMETER Force
    Forces the operation without prompting for confirmation.

.EXAMPLE
    PS> .\Manage-RemoteComputers.ps1 -ComputerName Server01, Server02 -Operation TestConnection
    
    Tests connectivity to Server01 and Server02.

.EXAMPLE
    PS> .\Manage-RemoteComputers.ps1 -ComputerName Server01 -Operation GetServices -Credential (Get-Credential)
    
    Gets services from Server01 using specified credentials.

.EXAMPLE
    PS> .\Manage-RemoteComputers.ps1 -ComputerName Server01 -Operation ManageService -ServiceName Spooler -ServiceAction Restart
    
    Restarts the Spooler service on Server01.

.EXAMPLE
    PS> .\Manage-RemoteComputers.ps1 -ComputerName Server01 -Operation FileOperation -FileOperation Copy -SourcePath C:\source.txt -DestinationPath C:\destination.txt
    
    Copies source.txt to destination.txt on Server01.

.EXAMPLE
    PS> .\Manage-RemoteComputers.ps1 -ComputerName Server01 -Operation RegistryOperation -RegistryOperation Read -RegistryPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
    
    Reads the registry values from the specified path on Server01.

.EXAMPLE
    PS> Get-Content computers.txt | .\Manage-RemoteComputers.ps1 -Operation GetSystemInfo -OutputPath C:\Reports
    
    Gets system information from computers listed in computers.txt and saves reports to C:\Reports.

.NOTES
    Author: PowerShell Administrator
    Date: $(Get-Date -Format "yyyy-MM-dd")
    Version: 1.0
    
    Requirements:
    - PowerShell 5.1 or higher
    - Administrative privileges on remote computers
    - WinRM enabled on remote computers for PowerShell remoting
    - Appropriate firewall rules

.LINK
    https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands
#>

[CmdletBinding(DefaultParameterSetName = 'Default')]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateSet('TestConnection', 'PSSession', 'ExecuteCommand', 'GetProcesses', 'GetServices', 'ManageService', 'FileOperation', 'RegistryOperation', 'GetSystemInfo')]
    [string]$Operation,

    [Parameter(Mandatory = $false)]
    [ValidateSet('WinRM', 'DCOM', 'SSH')]
    [string]$Protocol = 'WinRM',

    [Parameter(Mandatory = $false, ParameterSetName = 'Service')]
    [string]$ServiceName,

    [Parameter(Mandatory = $false, ParameterSetName = 'Service')]
    [ValidateSet('Start', 'Stop', 'Restart', 'Query')]
    [string]$ServiceAction = 'Query',

    [Parameter(Mandatory = $false, ParameterSetName = 'Command')]
    [string]$Command,

    [Parameter(Mandatory = $false, ParameterSetName = 'File')]
    [string]$SourcePath,

    [Parameter(Mandatory = $false, ParameterSetName = 'File')]
    [string]$DestinationPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'File')]
    [ValidateSet('Copy', 'Move', 'Delete')]
    [string]$FileOperation = 'Copy',

    [Parameter(Mandatory = $false, ParameterSetName = 'Registry')]
    [string]$RegistryPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Registry')]
    [string]$RegistryKey,

    [Parameter(Mandatory = $false, ParameterSetName = 'Registry')]
    [object]$RegistryValue,

    [Parameter(Mandatory = $false, ParameterSetName = 'Registry')]
    [ValidateSet('Read', 'Write', 'Delete')]
    [string]$RegistryOperation = 'Read',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\RemoteManagement.log",

    [Parameter(Mandatory = $false)]
    [switch]$Parallel,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 120,

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Begin {
    #region Initialize Script
    $ErrorActionPreference = 'Stop'
    $startTime = Get-Date
    $scriptName = $MyInvocation.MyCommand.Name
    $scriptVersion = '1.0'
    $results = @()

    # Create a synchronized hashtable for parallel processing
    $syncHash = [System.Collections.Hashtable]::Synchronized(@{})
    $syncHash.Results = New-Object System.Collections.ArrayList
    $syncHash.CurrentOperation = $Operation

    # Create PSSessionOption for more reliable remoting
    $sessionOption = New-PSSessionOption -IdleTimeout (1000 * 60 * 15) -OpenTimeout (1000 * 60) -OperationTimeout (1000 * 60)

    # Initialize Logging
    function Write-Log {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [string]$Message,
            
            [Parameter(Mandatory = $false)]
            [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
            [string]$Level = 'Info',
            
            [Parameter(Mandatory = $false)]
            [switch]$NoConsole
        )
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        
        switch ($Level) {
            'Info'    { $color = 'White'; $prefix = 'INFO:'; break }
            'Warning' { $color = 'Yellow'; $prefix = 'WARNING:'; break }
            'Error'   { $color = 'Red'; $prefix = 'ERROR:'; break }
            'Debug'   { $color = 'Cyan'; $prefix = 'DEBUG:'; break }
        }
        
        # Always write to log file
        Add-Content -Path $LogPath -Value $logMessage
        
        # Write to console unless suppressed
        if (-not $NoConsole) {
            Write-Host "$prefix $Message" -ForegroundColor $color
        }
    }

    # Create log file if it doesn't exist
    if (-not (Test-Path -Path $LogPath)) {
        $null = New-Item -Path $LogPath -ItemType File -Force
    }

    # Initialize Report
    function Initialize-Report {
        param (
            [string]$Title,
            [string]$FilePath
        )
        
        $report = @"
<!DOCTYPE html>
<html>
<head>
    <title>$Title</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #0066cc; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .timestamp { color: #666; font-size: 0.8em; }
    </style>
</head>
<body>
    <h1>$Title</h1>
    <p class="timestamp">Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <div class="summary">
        <p>Operation: $Operation</p>
        <p>Total Computers: $($ComputerName.Count)</p>
    </div>
"@
        Set-Content -Path $FilePath -Value $report
    }

    function Add-ReportContent {
        param (
            [string]$FilePath,
            [string]$Content
        )
        
        Add-Content -Path $FilePath -Value $Content
    }

    function Complete-Report {
        param (
            [string]$FilePath,
            [System.Collections.ArrayList]$Results
        )
        
        $footer = @"
    <div class="summary">
        <p>Total operation time: $((Get-Date) - $startTime)</p>
        <p>Successfully completed: $($Results.Where{$_.Success -eq $true}.Count) / $($Results.Count)</p>
    </div>
</body>
</html>
"@
        Add-Content -Path $FilePath -Value $footer
    }

    # Define helper function for testing WinRM connectivity
    function Test-WinRMConnectivity {
        param ([string]$ComputerName)
        
        try {
            $options = New-CimSessionOption -Protocol WSMan
            $session = New-CimSession -ComputerName $ComputerName -SessionOption $options -ErrorAction Stop
            Remove-CimSession -CimSession $session
            return $true
        }
        catch {
            Write-Log -Message "WinRM connection to $ComputerName failed: $_" -Level Warning
            return $false
        }
    }

    # Define function to test general connectivity
    function Test-RemoteConnectivity {
        param (
            [string]$ComputerName,
            [ValidateSet('WinRM', 'DCOM', 'SSH')]
            [string]$Protocol = 'WinRM',
            [int]$Timeout = 3000
        )
        
        $result = [PSCustomObject]@{
            ComputerName = $ComputerName
            PingSuccess = $false
            PortSuccess = $false
            WinRMSuccess = $false
            Success = $false
            ErrorMessage = $null
        }
        
        try {
            # Step 1: Test ICMP ping
            $pingResult = Test-Connection -ComputerName $ComputerName -Count 2 -Quiet
            $result.PingSuccess = $pingResult
            
            # Step 2: Test appropriate port based on protocol
            switch ($Protocol) {
                'WinRM' {
                    $port = 5985  # HTTP port for WinRM
                    $portTest = Test-NetConnection -ComputerName $ComputerName -Port $port -WarningAction SilentlyContinue
                    $result.PortSuccess = $portTest.TcpTestSucceeded
                    
                    # Step 3: Test WinRM specifically
                    if ($result.PortSuccess) {
                        $result.WinRMSuccess = Test-WinRMConnectivity -ComputerName $ComputerName
                    }
                }
                'DCOM' {
                    $port = 135  # RPC endpoint mapper
                    $portTest = Test-NetConnection -ComputerName $ComputerName -Port $port -WarningAction SilentlyContinue
                    $result.PortSuccess = $portTest.TcpTestSucceeded
                }
                'SSH' {
                    $port = 22  # SSH port
                    $portTest = Test-NetConnection -ComputerName $ComputerName -Port $port -WarningAction SilentlyContinue
                    $result.PortSuccess = $portTest.TcpTestSucceeded
                }
            }
            
            # Determine overall success
            switch ($Protocol) {
                'WinRM' { $result.Success = $result.PingSuccess -and $result.PortSuccess -and $result.WinRMSuccess }
                default { $result.Success = $result.PingSuccess -and $result.PortSuccess }
            }
        }
        catch {
            $result.Success = $false
            $result.ErrorMessage = $_.Exception.Message
            Write-

