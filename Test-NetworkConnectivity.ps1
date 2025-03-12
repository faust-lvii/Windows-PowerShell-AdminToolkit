<#
.SYNOPSIS
    Comprehensive network connectivity testing tool.

.DESCRIPTION
    Test-NetworkConnectivity performs various network connectivity tests including ping,
    port testing, DNS resolution, traceroute, speed tests, and service availability.
    The script supports multiple target hosts and provides detailed reporting in various formats.

.PARAMETER TargetHosts
    One or more hostnames or IP addresses to test.

.PARAMETER PingCount
    Number of ping requests to send. Default is 4.

.PARAMETER PingTimeout
    Timeout in milliseconds for ping requests. Default is 1000ms.

.PARAMETER Ports
    Array of ports to test. Default is 80,443,22,3389.

.PARAMETER PortTimeout
    Timeout in milliseconds for port connection tests. Default is 1000ms.

.PARAMETER EnableDNS
    Switch to enable DNS resolution tests.

.PARAMETER EnableTraceroute
    Switch to enable traceroute tests.

.PARAMETER EnableSpeedTest
    Switch to enable network speed tests.

.PARAMETER EnableLatencyMonitoring
    Switch to enable continuous latency monitoring.

.PARAMETER MonitoringDuration
    Duration in seconds for latency monitoring. Default is 60 seconds.

.PARAMETER MonitoringInterval
    Interval in seconds between latency tests. Default is 1 second.

.PARAMETER TestServices
    Switch to enable testing of network services (HTTP, HTTPS, etc.).

.PARAMETER ServicesToTest
    Array of services to test. Default is HTTP,HTTPS.

.PARAMETER OutputPath
    Path where output reports will be saved. Default is current directory.

.PARAMETER OutputFormat
    Output format for reports. Valid values are Console, CSV, HTML, or All. Default is Console.

.PARAMETER LogPath
    Path where log file will be created. Default is "$OutputPath\NetworkTest_Log.txt".

.EXAMPLE
    Test-NetworkConnectivity -TargetHosts "google.com","8.8.8.8" -EnableDNS -EnableTraceroute
    Tests connectivity to google.com and 8.8.8.8 including DNS resolution and traceroute.

.EXAMPLE
    Test-NetworkConnectivity -TargetHosts "server01.contoso.com" -Ports 80,443,3389,22 -OutputFormat HTML
    Tests connectivity to specific ports on server01.contoso.com and outputs an HTML report.

.EXAMPLE
    Test-NetworkConnectivity -TargetHosts "10.0.0.1" -EnableLatencyMonitoring -MonitoringDuration 300 -MonitoringInterval 5
    Monitors latency to 10.0.0.1 for 5 minutes with readings every 5 seconds.

.EXAMPLE
    Test-NetworkConnectivity -TargetHosts "webserver.contoso.com" -TestServices -ServicesToTest "HTTP","HTTPS","FTP"
    Tests HTTP, HTTPS, and FTP services on webserver.contoso.com.

.NOTES
    Author: PowerShell AdminToolkit
    Version: 1.0
    Date: 2023-11-10
    Requirements: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string[]]$TargetHosts,
    
    [Parameter(Mandatory = $false)]
    [int]$PingCount = 4,
    
    [Parameter(Mandatory = $false)]
    [int]$PingTimeout = 1000,
    
    [Parameter(Mandatory = $false)]
    [int[]]$Ports = @(80, 443, 22, 3389),
    
    [Parameter(Mandatory = $false)]
    [int]$PortTimeout = 1000,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableDNS,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableTraceroute,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableSpeedTest,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableLatencyMonitoring,
    
    [Parameter(Mandatory = $false)]
    [int]$MonitoringDuration = 60,
    
    [Parameter(Mandatory = $false)]
    [int]$MonitoringInterval = 1,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestServices,
    
    [Parameter(Mandatory = $false)]
    [string[]]$ServicesToTest = @("HTTP", "HTTPS"),
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Console", "CSV", "HTML", "All")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$((Get-Location).Path)\NetworkTest_Log.txt"
)

# Initialize script
$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$global:results = @()
$global:latencyData = @()
$servicePortMap = @{
    "HTTP" = 80
    "HTTPS" = 443
    "FTP" = 21
    "SSH" = 22
    "TELNET" = 23
    "SMTP" = 25
    "DNS" = 53
    "POP3" = 110
    "IMAP" = 143
    "RDP" = 3389
    "SMB" = 445
    "MSSQL" = 1433
    "MySQL" = 3306
    "PostgreSQL" = 5432
    "MongoDB" = 27017
}

#region Helper Functions

function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Add color coding for console output
    switch ($Level) {
        "INFO" { Write-Host $logEntry -ForegroundColor Cyan }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
    }
    
    # Write to log file
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Unable to write to log file: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-Progress {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $true)]
        [int]$PercentComplete,
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "",
        
        [Parameter(Mandatory = $false)]
        [int]$Id = 0
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -Id $Id
}

function Test-HostPing {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        
        [Parameter(Mandatory = $false)]
        [int]$Count = 4,
        
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 1000
    )
    
    Write-Log -Message "Starting ping test for $Target" -Level "INFO"
    $pingResults = @()
    
    try {
        for ($i = 1; $i -le $Count; $i++) {
            Show-Progress -Activity "Ping Test for $Target" -Status "Sending ping $i of $Count" -PercentComplete (($i / $Count) * 100)
            $ping = Test-Connection -ComputerName $Target -Count 1 -Quiet
            
            if ($ping) {
                $pingDetails = Test-Connection -ComputerName $Target -Count 1 -ErrorAction SilentlyContinue
                $pingResults += [PSCustomObject]@{
                    Attempt = $i
                    Success = $true
                    ResponseTime = if ($pingDetails) { $pingDetails.ResponseTime } else { 0 }
                    TTL = if ($pingDetails) { $pingDetails.ResponseTimeToLive } else { 0 }
                }
                Write-Log -Message "Ping $i successful to $Target (ResponseTime: $($pingDetails.ResponseTime)ms)" -Level "SUCCESS"
            }
            else {
                $pingResults += [PSCustomObject]@{
                    Attempt = $i
                    Success = $false
                    ResponseTime = 0
                    TTL = 0
                }
                Write-Log -Message "Ping $i failed to $Target" -Level "WARNING"
            }
        }
        
        # Calculate statistics
        $successCount = ($pingResults | Where-Object { $_.Success -eq $true }).Count
        $successRate = ($successCount / $Count) * 100
        $avgResponseTime = if ($successCount -gt 0) { ($pingResults | Where-Object { $_.Success -eq $true } | Measure-Object -Property ResponseTime -Average).Average } else { 0 }
        $minResponseTime = if ($successCount -gt 0) { ($pingResults | Where-Object { $_.Success -eq $true } | Measure-Object -Property ResponseTime -Minimum).Minimum } else { 0 }
        $maxResponseTime = if ($successCount -gt 0) { ($pingResults | Where-Object { $_.Success -eq $true } | Measure-Object -Property ResponseTime -Maximum).Maximum } else { 0 }
        
        return [PSCustomObject]@{
            Target = $Target
            TestType = "Ping"
            SuccessRate = $successRate
            SuccessCount = $successCount
            TotalTests = $Count
            AverageResponseTime = $avgResponseTime
            MinimumResponseTime = $minResponseTime
            MaximumResponseTime = $maxResponseTime
            DetailedResults = $pingResults
        }
    }
    catch {
        Write-Log -Message "Error performing ping test for $Target`: $($_.Exception.Message)" -Level "ERROR"
        return [PSCustomObject]@{
            Target = $Target
            TestType = "Ping"
            SuccessRate = 0
            SuccessCount = 0
            TotalTests = $Count
            AverageResponseTime = 0
            MinimumResponseTime = 0
            MaximumResponseTime = 0
            DetailedResults = $pingResults
            Error = $_.Exception.Message
        }
    }
    finally {
        Write-Progress -Activity "Ping Test for $Target" -Completed
    }
}

function Test-PortConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target,
        
        [Parameter(Mandatory = $true)]
        [int[]]$Ports,
        
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 1000
    )
    
    Write-Log -Message "Starting port test for $Target on ports $($Ports -join ', ')" -Level "INFO"
    $portResults = @()
    $totalPorts = $Ports.Count
    $portCounter = 0
    
    try {
        foreach ($port in $Ports) {
            $portCounter++
            $progressPercent = ($portCounter / $totalPorts) * 100
            Show-Progress -Activity "Port Test for $Target" -Status "Testing port $port ($portCounter of $totalPorts)" -PercentComplete $progressPercent
            
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $connectionTask = $tcpClient.ConnectAsync($Target, $port)
            
            # Wait for the task to complete or timeout
            $connectionResult = $connectionTask.Wait($Timeout)
            
            if ($connectionResult -and $tcpClient.Connected) {
                $portResults += [PSCustomObject]@{
                    Port = $port
                    Open = $true
                    Service = if ($servicePortMap.ContainsValue($port)) { ($servicePortMap.GetEnumerator() | Where-Object { $_.Value -eq $port } | Select-Object -First 1).Key } else { "Unknown" }
                    ResponseTime = $Timeout # We don't have an accurate measurement
                }
                Write-Log -Message "Port $port is open on $Target" -Level "SUCCESS"
                $tcpClient.Close()
            }
            else {
                $portResults += [PSCustomObject]@{
                    Port = $port
                    Open = $false
                    Service = if ($servicePortMap.ContainsValue($port)) { ($servicePortMap.GetEnumerator() | Where-Object { $_.Value -eq $port } | Select-Object -First 1).Key } else { "Unknown" }
                    ResponseTime = 0
                }
                Write-Log -Message "Port $port is closed on $Target" -Level "WARNING"
            }
            
            $tcpClient.Dispose()
        }
        
        # Calculate statistics
        $openCount = ($portResults | Where-Object { $_.Open -eq $true }).Count
        $openRate = ($openCount / $totalPorts) * 100
        
        return [PSCustomObject]@{
            Target = $Target
            TestType = "Port Scan"
            SuccessRate = $openRate
            SuccessCount = $openCount
            TotalTests = $totalPorts
            DetailedResults = $portResults
        }
    }
    catch {
        Write-Log -Message "Error performing port test for $Target`: $($_.Exception.Message)" -Level "ERROR"
        return [PSCustomObject]@{
            Target = $Target
            TestType = "Port Scan"
            SuccessRate = 0
            SuccessCount = 0
            TotalTests = $totalPorts
            DetailedResults = $portResults
            Error = $_.Exception.Message
        }
    }
    finally {
        Write-Progress -Activity "Port Test for $Target" -Completed
    }
}

function Test-DNSResolution {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Target
    )
    
    Write-Log -Message "Starting DNS resolution test for $Target" -Level "INFO"
    $dnsResults = @()
    
    try {
        Show-Progress -Activity "DNS Resolution Test for $Target" -Status "Resolving DNS" -PercentComplete 50
        
        $ipv4Results = [System.Net.Dns]::GetHostAddresses($Target) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
        $ipv6Results = [System.Net.Dns]::GetHostAddresses($Target) | Where-Object { $_.AddressFamily -eq 'InterNetworkV6' }
        
        if ($ipv4Results) {
            foreach ($ip in $ipv4Results) {
                $dnsResults += [PSCustomObject]@{
                    IPVersion = "IPv4"
                    Address = $ip.IPAddressToString
                    Success = $true
                }
                Write-Log -Message "Successfully resolved $Target to IPv4 address: $($ip.IPAddressToString)" -Level "SUCCESS"
            }
        }
        else {
            $dnsResults += [PSCustomObject]@{

