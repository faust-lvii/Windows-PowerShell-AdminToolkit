#Requires -Version 5.1

<#
.SYNOPSIS
    Advanced port scanner with multiple scan types, service identification, and detailed reporting.

.DESCRIPTION
    Scan-Ports is a comprehensive PowerShell port scanning utility that supports TCP and UDP scanning,
    custom port ranges, service identification, banner grabbing, parallel scanning, and multiple output formats.
    
    Features include:
    - Multiple scan types (TCP, UDP)
    - Custom port ranges and lists
    - Common service identification
    - Banner grabbing for open ports
    - Stealth scanning options
    - Parallel scanning for improved performance
    - Progress tracking
    - Detailed scan reports
    - Multiple output formats (Text, CSV, HTML, JSON)
    - Timeout and retry options
    - Comprehensive logging

.PARAMETER ComputerName
    Specifies the target computer name or IP address. Accepts multiple values or from pipeline.

.PARAMETER ScanType
    Specifies the scan type to perform. Valid values are TCP, UDP, or Both.
    
.PARAMETER Ports
    Specifies the port or ports to scan. Can be individual ports, ranges, or a combination.
    Examples: 80, 22-25, 80,443,3389, 1-1024

.PARAMETER CommonPorts
    A switch to scan common ports instead of custom ports.
    Common ports include well-known services like HTTP (80), HTTPS (443), SSH (22), etc.

.PARAMETER Timeout
    Specifies the timeout in milliseconds for each port scan attempt.

.PARAMETER Retries
    Specifies the number of retries for failed scan attempts.

.PARAMETER Threads
    Specifies the number of concurrent threads to use for parallel scanning.

.PARAMETER BannerGrab
    Switch to enable banner grabbing for open ports.

.PARAMETER StealthScan
    Switch to enable stealth scanning techniques.

.PARAMETER OutputFormat
    Specifies the format for the scan results. Valid values: Text, CSV, HTML, JSON.

.PARAMETER OutputPath
    Specifies the path to write the scan results.

.PARAMETER LogPath
    Specifies the path to write the scan logs.

.PARAMETER ShowProgress
    Switch to show or hide progress information during scanning.

.EXAMPLE
    PS> Scan-Ports -ComputerName 192.168.1.1 -ScanType TCP -Ports 80,443

    Scans TCP ports 80 and 443 on 192.168.1.1

.EXAMPLE
    PS> Scan-Ports -ComputerName server01 -ScanType Both -Ports 1-1024 -BannerGrab -OutputFormat HTML -OutputPath "C:\Reports\PortScan.html"

    Scans TCP and UDP ports 1-1024 on server01, attempts banner grabbing, and outputs results to an HTML file.

.EXAMPLE
    PS> "server01","server02" | Scan-Ports -ScanType TCP -CommonPorts -Threads 50 -ShowProgress

    Scans common TCP ports on server01 and server02 using 50 threads and displays progress.

.NOTES
    Author: PowerShell Administrator
    Version: 1.0
    Last Updated: 2023-01-01
    
    Requires PowerShell 5.1 or later
    For UDP scanning, elevated privileges may be required
    Excessive port scanning may be considered suspicious activity by network monitoring tools
#>

[CmdletBinding(DefaultParameterSetName="CustomPorts")]
param (
    [Parameter(Mandatory=$true, 
               Position=0, 
               ValueFromPipeline=$true,
               ValueFromPipelineByPropertyName=$true)]
    [Alias("Host", "Server", "Computer", "IP")]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("TCP", "UDP", "Both")]
    [string]$ScanType,
    
    [Parameter(Mandatory=$true, ParameterSetName="CustomPorts")]
    [string]$Ports,
    
    [Parameter(Mandatory=$true, ParameterSetName="CommonPortsSet")]
    [switch]$CommonPorts,
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 1000,
    
    [Parameter(Mandatory=$false)]
    [int]$Retries = 1,
    
    [Parameter(Mandatory=$false)]
    [int]$Threads = 25,
    
    [Parameter(Mandatory=$false)]
    [switch]$BannerGrab,
    
    [Parameter(Mandatory=$false)]
    [switch]$StealthScan,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Text", "CSV", "HTML", "JSON")]
    [string]$OutputFormat = "Text",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowProgress
)

begin {
    # Script initialization
    $ErrorActionPreference = 'Stop'
    $startTime = Get-Date
    
    # Initialize logger
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [string]$Message,
            
            [Parameter(Mandatory=$false)]
            [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
            [string]$Level = "INFO"
        )
        
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        
        if ($LogPath) {
            try {
                Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
            }
            catch {
                Write-Warning "Failed to write to log file: $_"
            }
        }
        
        switch ($Level) {
            "INFO"    { Write-Verbose $logEntry }
            "WARNING" { Write-Warning $logEntry }
            "ERROR"   { Write-Error $logEntry }
            "DEBUG"   { Write-Debug $logEntry }
            default   { Write-Verbose $logEntry }
        }
    }
    
    # Define common ports and services
    $commonPortsMap = @{
        20 = "FTP Data"
        21 = "FTP Control"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        53 = "DNS"
        80 = "HTTP"
        110 = "POP3"
        135 = "RPC"
        139 = "NetBIOS"
        143 = "IMAP"
        161 = "SNMP"
        389 = "LDAP"
        443 = "HTTPS"
        445 = "SMB"
        636 = "LDAPS"
        993 = "IMAP SSL"
        995 = "POP3 SSL"
        1433 = "MSSQL"
        1521 = "Oracle"
        3306 = "MySQL"
        3389 = "RDP"
        5060 = "SIP"
        5432 = "PostgreSQL"
        5900 = "VNC"
        8080 = "HTTP Proxy"
        8443 = "HTTPS Alt"
    }
    
    # Function to parse port input
    function Parse-PortInput {
        param (
            [string]$PortInput
        )
        
        $portList = New-Object System.Collections.Generic.List[int]
        
        if ($CommonPorts) {
            return $commonPortsMap.Keys
        }
        
        $segments = $PortInput -split ','
        
        foreach ($segment in $segments) {
            if ($segment -match "^\d+$") {
                # Single port
                $portList.Add([int]$segment)
            }
            elseif ($segment -match "^(\d+)-(\d+)$") {
                # Port range
                $start = [int]$Matches[1]
                $end = [int]$Matches[2]
                
                if ($start -gt $end) {
                    Write-Log -Message "Invalid port range: $segment (start > end)" -Level "ERROR"
                    throw "Invalid port range: $segment. Start port cannot be greater than end port."
                }
                
                if (($end - $start) -gt 1000) {
                    Write-Log -Message "Large port range detected: $segment" -Level "WARNING"
                    Write-Warning "Large port range detected ($($end - $start + 1) ports). This may take a significant amount of time to scan."
                }
                
                $start..$end | ForEach-Object { $portList.Add($_) }
            }
            else {
                Write-Log -Message "Invalid port format: $segment" -Level "ERROR"
                throw "Invalid port format: $segment. Use single ports (80), ranges (1-1024), or combinations (22,80,443,1000-2000)."
            }
        }
        
        return $portList
    }
    
    # Function to get service name for a port
    function Get-ServiceName {
        param (
            [int]$Port
        )
        
        if ($commonPortsMap.ContainsKey($Port)) {
            return $commonPortsMap[$Port]
        }
        else {
            return "Unknown"
        }
    }
    
    # Function to grab banner from open port
    function Get-PortBanner {
        param (
            [string]$ComputerName,
            [int]$Port,
            [int]$Timeout
        )
        
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $connection = $client.BeginConnect($ComputerName, $Port, $null, $null)
            $wait = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
            
            if (!$wait) {
                $client.Close()
                return $null
            }
            
            try {
                $client.EndConnect($connection)
                $stream = $client.GetStream()
                $stream.ReadTimeout = $Timeout
                
                # Send a generic request to trigger a response
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.WriteLine("HEAD / HTTP/1.1`r`nHost: $ComputerName`r`n`r`n")
                $writer.Flush()
                
                # Read response
                $reader = New-Object System.IO.StreamReader($stream)
                $banner = $reader.ReadLine()
                
                if ([string]::IsNullOrEmpty($banner)) {
                    # Try another method for non-HTTP services
                    $buffer = New-Object byte[] 1024
                    $read = $stream.Read($buffer, 0, 1024)
                    if ($read -gt 0) {
                        $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
                    }
                }
                
                return $banner
            }
            finally {
                if ($stream) { $stream.Close() }
                if ($client) { $client.Close() }
            }
        }
        catch {
            Write-Log -Message "Error grabbing banner for $ComputerName port $Port : $_" -Level "WARNING"
            return $null
        }
    }
    
    # Function to scan a TCP port
    function Test-TcpPort {
        param (
            [string]$ComputerName,
            [int]$Port,
            [int]$Timeout,
            [int]$Retries,
            [bool]$Stealth,
            [bool]$GrabBanner
        )
        
        $result = [PSCustomObject]@{
            ComputerName = $ComputerName
            Port = $Port
            Protocol = "TCP"
            Status = "Closed"
            Service = Get-ServiceName -Port $Port
            Banner = $null
            ResponseTime = $null
        }
        
        $successfulScan = $false
        $retryCount = 0
        
        while (-not $successfulScan -and $retryCount -le $Retries) {
            try {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                
                if ($Stealth) {
                    # SYN scan simulation - for real SYN scans, specialized tools like nmap would be needed
                    $client = New-Object System.Net.Sockets.TcpClient
                    $connection = $client.BeginConnect($ComputerName, $Port, $null, $null)
                    $wait = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
                    
                    if ($wait) {
                        try {
                            $client.EndConnect($connection)
                            $result.Status = "Open"
                            $successfulScan = $true
                        }
                        finally {
                            $client.Close()
                        }
                    }
                    else {
                        $client.Close()
                        $result.Status = "Filtered"
                    }
                }
                else {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $connectionTask = $tcpClient.ConnectAsync($ComputerName, $Port)
                    
                    if ($connectionTask.Wait($Timeout)) {
                        if ($tcpClient.Connected) {
                            $result.Status = "Open"
                            $successfulScan = $true
                            
                            if ($GrabBanner) {
                                $result.Banner = Get-PortBanner -ComputerName $ComputerName -Port $Port -Timeout $Timeout
                            }
                        }
                    }
                    
                    $tcpClient.Close()
                }
                
                $stopwatch.Stop()
                $result.ResponseTime = $stopwatch.ElapsedMilliseconds
            }
            catch [System.Net.Sockets.SocketException] {
                if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
                    $result.Status = "Closed"
                    $successfulScan = $true
                }
                else {
                    $result.Status = "Filtered"
                    $retryCount++
                }
            }
            catch {
                Write-Log -Message "Error scanning TCP port $Port on $ComputerName : $_" -Level "WARNING"
                $retryCount++
            }
        }
        
        return $result
    }
    
    # Function to scan a UDP port
    function Test-UdpPort {
        param (
            [string]$ComputerName,
            [int]$Port,
            [int]$Timeout,
            [int]$Retries
        )
        
        $result = [PSCustomObject]@{
            ComputerName = $ComputerName
            Port = $Port
            Protocol = "UDP"
            Status = "Unknown"
            Service = Get-ServiceName -Port $Port
            Banner = $null
            ResponseTime = $null
        }
        
        $successfulScan = $false
        $retryCount = 0
        
        while (-not $successfulScan -and $retryCount -le $Retries) {
            try {
                #

