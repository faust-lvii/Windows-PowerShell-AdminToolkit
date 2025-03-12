#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Advanced IP Address and Network Configuration Management Tool

.DESCRIPTION
    This script provides comprehensive IP address and network adapter management capabilities.
    It allows viewing, configuring, backing up, and restoring network settings including:
    - IP address configuration (static/DHCP)
    - DNS server settings
    - Network adapter management
    - Configuration backups and restores
    - Network validation and connectivity testing

.PARAMETER Action
    Specifies the action to perform:
    - View: Display current network configurations
    - SetStatic: Configure static IP address
    - SetDHCP: Configure adapter to use DHCP
    - SetDNS: Configure DNS servers
    - Backup: Backup current network settings
    - Restore: Restore network settings from backup
    - Test: Test network connectivity
    - Report: Generate network configuration report

.PARAMETER AdapterName
    Specifies the network adapter name to configure. If not specified, shows a selection menu.

.PARAMETER IPAddress
    Specifies the static IP address to set (used with SetStatic action).

.PARAMETER SubnetMask
    Specifies the subnet mask (used with SetStatic action).

.PARAMETER Gateway
    Specifies the default gateway (used with SetStatic action).

.PARAMETER DNSServers
    Specifies the DNS servers as a comma-separated list (used with SetDNS action).

.PARAMETER BackupPath
    Specifies the path for backup files (used with Backup and Restore actions).

.PARAMETER BackupName
    Specifies the backup name to restore (used with Restore action).

.PARAMETER ReportPath
    Specifies the path for the report output (used with Report action).

.PARAMETER ReportFormat
    Specifies the report format: CSV, HTML, or Text (used with Report action).

.PARAMETER LogPath
    Specifies the log file path. Default is "$env:TEMP\NetworkManagement.log".

.PARAMETER Verbose
    Provides detailed progress information.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action View
    Displays all network adapter configurations.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action SetStatic -AdapterName "Ethernet" -IPAddress "192.168.1.100" -SubnetMask "255.255.255.0" -Gateway "192.168.1.1"
    Sets a static IP configuration for the Ethernet adapter.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action SetDHCP -AdapterName "Wi-Fi"
    Configures the Wi-Fi adapter to use DHCP.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action SetDNS -AdapterName "Ethernet" -DNSServers "8.8.8.8,8.8.4.4"
    Sets Google DNS servers for the Ethernet adapter.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action Backup -BackupPath "C:\Backups"
    Backs up all network configurations to the specified folder.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action Restore -BackupPath "C:\Backups" -BackupName "NetworkBackup_20220815_120000"
    Restores network configurations from the specified backup.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action Test -AdapterName "Ethernet"
    Tests connectivity for the Ethernet adapter.

.EXAMPLE
    .\Manage-IPAddresses.ps1 -Action Report -ReportPath "C:\Reports" -ReportFormat HTML
    Generates an HTML report of all network configurations.

.NOTES
    File Name      : Manage-IPAddresses.ps1
    Prerequisite   : PowerShell 5.1 or later
    Administrator privileges required for network configuration changes

.LINK
    https://github.com/YourUsername/Windows-PowerShell-AdminToolkit
#>

[CmdletBinding(DefaultParameterSetName = "View")]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet("View", "SetStatic", "SetDHCP", "SetDNS", "Backup", "Restore", "Test", "Report")]
    [string]$Action,

    [Parameter(ParameterSetName = "SetStatic")]
    [Parameter(ParameterSetName = "SetDHCP")]
    [Parameter(ParameterSetName = "SetDNS")]
    [Parameter(ParameterSetName = "Test")]
    [string]$AdapterName,

    [Parameter(Mandatory = $true, ParameterSetName = "SetStatic")]
    [ValidateScript({ IsValidIP $_ })]
    [string]$IPAddress,

    [Parameter(Mandatory = $true, ParameterSetName = "SetStatic")]
    [ValidateScript({ IsValidSubnetMask $_ })]
    [string]$SubnetMask,

    [Parameter(ParameterSetName = "SetStatic")]
    [ValidateScript({ IsValidIP $_ })]
    [string]$Gateway,

    [Parameter(Mandatory = $true, ParameterSetName = "SetDNS")]
    [ValidateScript({ ValidateDNSServers $_ })]
    [string]$DNSServers,

    [Parameter(Mandatory = $true, ParameterSetName = "Backup")]
    [Parameter(Mandatory = $true, ParameterSetName = "Restore")]
    [string]$BackupPath,

    [Parameter(ParameterSetName = "Restore")]
    [string]$BackupName,

    [Parameter(ParameterSetName = "Report")]
    [string]$ReportPath = "$env:USERPROFILE\Documents",

    [Parameter(ParameterSetName = "Report")]
    [ValidateSet("CSV", "HTML", "Text")]
    [string]$ReportFormat = "HTML",

    [string]$LogPath = "$env:TEMP\NetworkManagement.log"
)

#region Functions

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        "INFO" { Write-Host $logMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file
    try {
        $logMessage | Out-File -FilePath $LogPath -Append -ErrorAction Stop
    }
    catch {
        Write-Host "Failed to write to log file: $_" -ForegroundColor Red
    }
}

function Show-Progress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $true)]
        [int]$PercentComplete,
        
        [Parameter()]
        [string]$Status = "Processing..."
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

function Get-NetworkAdapter {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$AdapterName
    )
    
    try {
        if ([string]::IsNullOrEmpty($AdapterName)) {
            # Get all enabled network adapters
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            
            if ($adapters.Count -eq 0) {
                Write-Log "No enabled network adapters found." -Level WARNING
                return $null
            }
            
            # If only one adapter, return it
            if ($adapters.Count -eq 1) {
                return $adapters
            }
            
            # Display menu for adapter selection
            Write-Host "`nAvailable Network Adapters:" -ForegroundColor Green
            $menu = @{}
            for ($i = 1; $i -le $adapters.Count; $i++) {
                Write-Host "$i. $($adapters[$i-1].Name) ($($adapters[$i-1].InterfaceDescription))"
                $menu.Add($i, $adapters[$i-1])
            }
            
            [int]$selection = 0
            while ($selection -lt 1 -or $selection -gt $adapters.Count) {
                Write-Host "`nSelect an adapter (1-$($adapters.Count)):" -ForegroundColor Yellow -NoNewline
                $input = Read-Host
                [int]::TryParse($input, [ref]$selection)
            }
            
            return $menu[$selection]
        }
        else {
            # Get specified adapter
            $adapter = Get-NetAdapter -Name $AdapterName -ErrorAction Stop
            if ($adapter.Status -ne "Up") {
                Write-Log "The selected adapter '$AdapterName' is not enabled." -Level WARNING
            }
            return $adapter
        }
    }
    catch {
        Write-Log "Error retrieving network adapter: $_" -Level ERROR
        return $null
    }
}

function IsValidIP {
    param ([string]$ip)
    
    $ipRegex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return $ip -match $ipRegex
}

function IsValidSubnetMask {
    param ([string]$mask)
    
    if (!(IsValidIP $mask)) {
        return $false
    }
    
    $octets = $mask -split '\.'
    $binary = [convert]::ToString([int]$octets[0], 2).PadLeft(8, '0') + 
              [convert]::ToString([int]$octets[1], 2).PadLeft(8, '0') + 
              [convert]::ToString([int]$octets[2], 2).PadLeft(8, '0') + 
              [convert]::ToString([int]$octets[3], 2).PadLeft(8, '0')
    
    # Check for valid subnet mask (continuous 1s followed by continuous 0s)
    return ($binary -match "^1+0*$")
}

function ValidateDNSServers {
    param ([string]$servers)
    
    $dnsServers = $servers -split ','
    foreach ($dns in $dnsServers) {
        if (!(IsValidIP $dns.Trim())) {
            return $false
        }
    }
    return $true
}

function View-NetworkConfigurations {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$AdapterName
    )
    
    try {
        $adapters = if ([string]::IsNullOrEmpty($AdapterName)) {
            Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        }
        else {
            Get-NetAdapter -Name $AdapterName -ErrorAction Stop
        }
        
        if ($null -eq $adapters -or $adapters.Count -eq 0) {
            Write-Log "No network adapters found." -Level WARNING
            return
        }
        
        foreach ($adapter in $adapters) {
            $ipConfig = Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex
            $ipAddresses = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
            
            Write-Host "`n==== $($adapter.Name) Configuration ====" -ForegroundColor Green
            Write-Host "Interface Description : $($adapter.InterfaceDescription)"
            Write-Host "Status                : $($adapter.Status)"
            Write-Host "Link Speed            : $($adapter.LinkSpeed)"
            Write-Host "MAC Address           : $($adapter.MacAddress)"
            
            foreach ($ip in $ipAddresses) {
                Write-Host "`nIP Configuration:" -ForegroundColor Cyan
                Write-Host "IP Address            : $($ip.IPAddress)"
                Write-Host "Subnet Mask           : $($ip.PrefixLength) ($(ConvertTo-SubnetMask $ip.PrefixLength))"
                Write-Host "DHCP Enabled          : $(if ($ip.PrefixOrigin -eq 'Dhcp') { 'Yes' } else { 'No' })"
            }
            
            if ($null -ne $ipConfig.IPv4DefaultGateway) {
                Write-Host "Default Gateway       : $($ipConfig.IPv4DefaultGateway.NextHop)"
            }
            else {
                Write-Host "Default Gateway       : None"
            }
            
            if ($null -ne $ipConfig.DNSServer) {
                Write-Host "`nDNS Configuration:" -ForegroundColor Cyan
                $dnsServers = $ipConfig.DNSServer.ServerAddresses
                if ($dnsServers.Count -gt 0) {
                    for ($i = 0; $i -lt $dnsServers.Count; $i++) {
                        Write-Host "DNS Server $($i+1)        : $($dnsServers[$i])"
                    }
                }
                else {
                    Write-Host "DNS Servers           : None"
                }
            }
            else {
                Write-Host "`nDNS Configuration:" -ForegroundColor Cyan
                Write-Host "DNS Servers           : None"
            }
        }
    }
    catch {
        Write-Log "Error viewing network configurations: $_" -Level ERROR
    }
}

function ConvertTo-SubnetMask {
    param ([int]$PrefixLength)
    
    try {
        $mask = [IPAddress]([UInt32]::MaxValue -shl (32 - $PrefixLength) -shr (32 - $PrefixLength))
        return $mask.ToString()
    }
    catch {
        Write-Log "Error converting prefix length to subnet mask: $_" -Level ERROR
        return "255.255.255.0" # Return default on error
    }
}

function ConvertTo-PrefixLength {
    param ([string]$SubnetMask)
    
    try {
        $octets = $SubnetMask -split '\.'
        $binary = [convert]::ToString([int]$octets[0], 2).PadLeft(8, '0') + 
                  [convert]::ToString([int]$octets[1], 2).PadLeft(8, '0') + 
                  [convert]::ToString([int]$octets[2], 2).PadLeft(8, '0') + 
                  [convert]::ToString([int]$octets[3], 2).PadLeft(8, '0')
        
        return ($binary -replace "0", "").Length
    }
    catch {
        Write-Log "Error converting subnet mask to prefix length: $_" -Level ERROR
        return 24 # Default /24
    }
}

function Set-StaticIPAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Adapter,
        
        [Parameter(Mandatory = $true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$SubnetMask,
        
        

