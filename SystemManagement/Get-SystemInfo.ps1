#Requires -Version 5.1
<#
.SYNOPSIS
    Collects and displays detailed system information.

.DESCRIPTION
    The Get-SystemInfo script collects comprehensive system information including OS details,
    hardware information, memory status, disk information, network adapters, and installed software.
    It supports various output formats and provides colorized console output with progress indicators.

.PARAMETER OutputFormat
    Specifies the output format for the results.
    Accepted values: Console, CSV, HTML, JSON
    Default: Console

.PARAMETER OutputPath
    Specifies the path where the output file will be saved when using CSV, HTML, or JSON formats.
    If not specified, the current directory will be used.

.PARAMETER SkipSoftware
    When specified, skips the collection of installed software information, which can be time-consuming.

.PARAMETER NoProgress
    When specified, disables the progress bar display.

.EXAMPLE
    .\Get-SystemInfo.ps1
    Collects system information and displays it in the console with colored output.

.EXAMPLE
    .\Get-SystemInfo.ps1 -OutputFormat HTML -OutputPath "C:\Reports"
    Collects system information and saves it as an HTML file in the C:\Reports directory.

.EXAMPLE
    .\Get-SystemInfo.ps1 -OutputFormat CSV -SkipSoftware
    Collects system information (excluding installed software) and saves it as a CSV file in the current directory.

.EXAMPLE
    .\Get-SystemInfo.ps1 -OutputFormat JSON -NoProgress
    Collects system information without showing progress bars and saves it as a JSON file in the current directory.

.NOTES
    Author: System Administrator
    Last Updated: 2023-11-24
    Version: 1.0
#>

[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet('Console', 'CSV', 'HTML', 'JSON')]
    [string]$OutputFormat = 'Console',
    
    [Parameter(Position = 1)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter()]
    [switch]$SkipSoftware,
    
    [Parameter()]
    [switch]$NoProgress
)

#region Functions

function Write-ColorOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 
                     'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [string]$ForegroundColor = 'White',
        
        [Parameter()]
        [switch]$NoNewLine
    )
    
    $params = @{
        Object = $Message
        ForegroundColor = $ForegroundColor
    }
    
    if ($NoNewLine) {
        $params.Add('NoNewLine', $true)
    }
    
    Write-Host @params
}

function Write-SectionHeader {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Title
    )
    
    $separator = "=" * 80
    Write-ColorOutput -Message "`n$separator" -ForegroundColor Cyan
    Write-ColorOutput -Message "  $Title" -ForegroundColor Yellow
    Write-ColorOutput -Message "$separator" -ForegroundColor Cyan
}

function Get-OSInfo {
    [CmdletBinding()]
    param()
    
    try {
        $osInfo = Get-ComputerInfo
        $osProperties = [ordered]@{
            'Computer Name' = $env:COMPUTERNAME
            'OS Name' = $osInfo.WindowsProductName
            'OS Version' = $osInfo.OsVersion
            'OS Build' = $osInfo.OsBuildNumber
            'OS Architecture' = $osInfo.OsArchitecture
            'OS Installation Date' = $osInfo.OsInstallDate
            'OS Last Boot Time' = $osInfo.OsLastBootUpTime
            'OS Uptime' = if ($null -ne $osInfo.OsUptime) { $osInfo.OsUptime.ToString() } else { 'Unknown' }
            'Registered Owner' = $osInfo.WindowsRegisteredOwner
            'Registered Organization' = $osInfo.WindowsRegisteredOrganization
            'System Locale' = $osInfo.CsCurrentTimeZone
            'Time Zone' = $osInfo.TimeZone
            'System Directory' = $env:SystemRoot
            'Boot Device' = $osInfo.OsBootDevice
        }
        
        return [PSCustomObject]$osProperties
    }
    catch {
        Write-Error "Error retrieving OS information: $_"
        return $null
    }
}

function Get-HardwareInfo {
    [CmdletBinding()]
    param()
    
    try {
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -ClassName Win32_BIOS
        $processors = Get-CimInstance -ClassName Win32_Processor
        
        $processorInfo = foreach ($processor in $processors) {
            [PSCustomObject]@{
                'Name' = $processor.Name
                'Manufacturer' = $processor.Manufacturer
                'Description' = $processor.Description
                'Cores' = $processor.NumberOfCores
                'Logical Processors' = $processor.NumberOfLogicalProcessors
                'Max Clock Speed (MHz)' = $processor.MaxClockSpeed
                'L2 Cache (KB)' = $processor.L2CacheSize
                'L3 Cache (KB)' = $processor.L3CacheSize
                'Socket' = $processor.SocketDesignation
                'Status' = $processor.Status
            }
        }
        
        $motherboard = Get-CimInstance -ClassName Win32_BaseBoard
        $computerSystemInfo = [PSCustomObject]@{
            'Manufacturer' = $computerSystem.Manufacturer
            'Model' = $computerSystem.Model
            'System Type' = $computerSystem.SystemType
            'Total Physical Memory (GB)' = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
            'BIOS Manufacturer' = $bios.Manufacturer
            'BIOS Version' = $bios.SMBIOSBIOSVersion
            'BIOS Release Date' = $bios.ReleaseDate
            'BIOS Serial Number' = $bios.SerialNumber
            'Motherboard Manufacturer' = $motherboard.Manufacturer
            'Motherboard Model' = $motherboard.Product
            'Motherboard Serial' = $motherboard.SerialNumber
        }
        
        return @{
            'System' = $computerSystemInfo
            'Processors' = $processorInfo
        }
    }
    catch {
        Write-Error "Error retrieving hardware information: $_"
        return $null
    }
}

function Get-MemoryInfo {
    [CmdletBinding()]
    param()
    
    try {
        $physicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory
        $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
        
        $memoryModules = foreach ($module in $physicalMemory) {
            [PSCustomObject]@{
                'Manufacturer' = $module.Manufacturer
                'Description' = $module.Description
                'Capacity (GB)' = [math]::Round($module.Capacity / 1GB, 2)
                'Bank Label' = $module.BankLabel
                'Device Locator' = $module.DeviceLocator
                'Form Factor' = switch ($module.FormFactor) {
                    7 { 'DIMM' }
                    8 { 'SODIMM' }
                    default { "Unknown ($($module.FormFactor))" }
                }
                'Memory Type' = switch ($module.MemoryType) {
                    0 { 'Unknown' }
                    21 { 'DDR2' }
                    22 { 'DDR2 FB-DIMM' }
                    24 { 'DDR3' }
                    26 { 'DDR4' }
                    default { "Unknown ($($module.MemoryType))" }
                }
                'Speed (MHz)' = $module.Speed
                'Serial Number' = $module.SerialNumber
            }
        }
        
        $memoryPerformance = [PSCustomObject]@{
            'Total Physical Memory (GB)' = [math]::Round($operatingSystem.TotalVisibleMemorySize / 1MB, 2)
            'Available Physical Memory (GB)' = [math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
            'Used Physical Memory (GB)' = [math]::Round(($operatingSystem.TotalVisibleMemorySize - $operatingSystem.FreePhysicalMemory) / 1MB, 2)
            'Memory Usage %' = [math]::Round(100 - (($operatingSystem.FreePhysicalMemory / $operatingSystem.TotalVisibleMemorySize) * 100), 2)
            'Total Virtual Memory (GB)' = [math]::Round($operatingSystem.TotalVirtualMemorySize / 1MB, 2)
            'Available Virtual Memory (GB)' = [math]::Round($operatingSystem.FreeVirtualMemory / 1MB, 2)
            'Used Virtual Memory (GB)' = [math]::Round(($operatingSystem.TotalVirtualMemorySize - $operatingSystem.FreeVirtualMemory) / 1MB, 2)
        }
        
        return @{
            'Memory Modules' = $memoryModules
            'Memory Performance' = $memoryPerformance
        }
    }
    catch {
        Write-Error "Error retrieving memory information: $_"
        return $null
    }
}

function Get-DiskInfo {
    [CmdletBinding()]
    param()
    
    try {
        $diskDrives = Get-CimInstance -ClassName Win32_DiskDrive
        $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3"
        
        $physicalDisks = foreach ($disk in $diskDrives) {
            $partitions = $disk | Get-CimAssociatedInstance -ResultClassName Win32_DiskPartition
            
            [PSCustomObject]@{
                'Model' = $disk.Model
                'Manufacturer' = $disk.Manufacturer
                'Description' = $disk.Description
                'Serial Number' = $disk.SerialNumber
                'Size (GB)' = [math]::Round($disk.Size / 1GB, 2)
                'Interface Type' = $disk.InterfaceType
                'Media Type' = $disk.MediaType
                'Status' = $disk.Status
                'Partitions' = $partitions.Count
            }
        }
        
        $volumes = foreach ($logicalDisk in $logicalDisks) {
            [PSCustomObject]@{
                'Drive Letter' = $logicalDisk.DeviceID
                'Volume Name' = $logicalDisk.VolumeName
                'File System' = $logicalDisk.FileSystem
                'Size (GB)' = [math]::Round($logicalDisk.Size / 1GB, 2)
                'Free Space (GB)' = [math]::Round($logicalDisk.FreeSpace / 1GB, 2)
                'Used Space (GB)' = [math]::Round(($logicalDisk.Size - $logicalDisk.FreeSpace) / 1GB, 2)
                'Percent Free' = [math]::Round(($logicalDisk.FreeSpace / $logicalDisk.Size) * 100, 2)
            }
        }
        
        return @{
            'Physical Disks' = $physicalDisks
            'Volumes' = $volumes
        }
    }
    catch {
        Write-Error "Error retrieving disk information: $_"
        return $null
    }
}

function Get-NetworkInfo {
    [CmdletBinding()]
    param()
    
    try {
        $networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }
        $networkAdapterConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        $adapters = foreach ($adapter in $networkAdapters) {
            $adapterConfig = $networkAdapterConfigs | Where-Object { $_.Index -eq $adapter.Index }
            if ($adapterConfig) {
                [PSCustomObject]@{
                    'Name' = $adapter.Name
                    'Description' = $adapter.Description
                    'MAC Address' = $adapterConfig.MACAddress
                    'DHCP Enabled' = $adapterConfig.DHCPEnabled
                    'IP Address(es)' = $adapterConfig.IPAddress -join ', '
                    'Subnet Mask(s)' = $adapterConfig.IPSubnet -join ', '
                    'Default Gateway' = $adapterConfig.DefaultIPGateway -join ', '
                    'DNS Servers' = $adapterConfig.DNSServerSearchOrder -join ', '
                    'Speed (Mbps)' = if ($adapter.Speed) { [math]::Round($adapter.Speed / 1000000, 2) } else { 'Unknown' }
                    'Connection Status' = $adapter.NetConnectionStatus -replace '^(\d+)$', {
                        switch ($matches[1]) {
                            0 { 'Disconnected' }
                            1 { 'Connecting' }
                            2 { 'Connected' }
                            3 { 'Disconnecting' }
                            4 { 'Hardware not present' }
                            5 { 'Hardware disabled' }
                            6 { 'Hardware malfunction' }
                            7 { 'Media disconnected' }
                            8 { 'Authenticating' }
                            9 { 'Authentication succeeded' }
                            10 { 'Authentication failed' }
                            11 { 'Invalid address' }
                            12 { 'Credentials required' }
                            default { "Unknown ($($matches[1]))" }
                        }
                    }
                }
            }
        }
        
        return $adapters
    }
    catch {
        Write-Error "Error retrieving network information: $_"
        return $null
    }
}

function Get-InstalledSoftware {
    [CmdletBinding()]
    param()
    
    try {
        $software = @()
        
        # 64-bit software
        $software += Get-ItemProperty "HKL

