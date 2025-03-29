<#
.SYNOPSIS
    Tests network connectivity to specified targets using TCP, ICMP, or both protocols.

.DESCRIPTION
    The Test-NetworkConnection script provides comprehensive network connectivity testing capabilities.
    It can test multiple targets and ports in parallel, measure latency, and simulate traceroute operations.
    Results are formatted in a readable format with detailed statistics.

.PARAMETER Target
    Specifies an array of IP addresses or hostnames to test connectivity to.

.PARAMETER Ports
    Specifies an array of TCP port numbers to test. Used when Protocol is set to TCP or Both.

.PARAMETER Protocol
    Specifies the protocol to use for connectivity testing. Valid values are TCP, ICMP, or Both.

.PARAMETER Timeout
    Specifies the timeout in milliseconds for connection attempts. Default is 1000ms.

.PARAMETER Count
    Specifies the number of packets or connection attempts to make. Default is 4.

.PARAMETER RunParallel
    Enables parallel execution of tests for faster results with multiple targets or ports.

.PARAMETER TraceRoute
    Enables traceroute simulation to map the network path to the target.

.EXAMPLE
    .\Test-NetworkConnection.ps1 -Target 192.168.1.1 -Protocol ICMP
    Tests ICMP connectivity to 192.168.1.1 with default settings.

.EXAMPLE
    .\Test-NetworkConnection.ps1 -Target server1.contoso.com, server2.contoso.com -Ports 80, 443 -Protocol TCP -RunParallel
    Tests TCP connectivity to ports 80 and 443 on both servers in parallel.

.EXAMPLE
    .\Test-NetworkConnection.ps1 -Target 8.8.8.8 -Protocol Both -Count 10 -Timeout 2000 -TraceRoute
    Tests both TCP and ICMP connectivity to 8.8.8.8, performs 10 attempts with 2 second timeout, and shows traceroute.

.NOTES
    Author: AdminToolkit Team
    Version: 1.0
    Date: [Current Date]
    Requirements: PowerShell 5.1 or higher
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0, 
               HelpMessage = "IP addresses or hostnames to test")]
    [string[]]$Target,
    
    [Parameter(HelpMessage = "Port numbers to test when using TCP")]
    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(80, 443),
    
    [Parameter(HelpMessage = "Protocol to use for testing")]
    [ValidateSet("TCP", "ICMP", "Both")]
    [string]$Protocol = "Both",
    
    [Parameter(HelpMessage = "Connection timeout in milliseconds")]
    [ValidateRange(100, 60000)]
    [int]$Timeout = 1000,
    
    [Parameter(HelpMessage = "Number of attempts/packets")]
    [ValidateRange(1, 100)]
    [int]$Count = 4,
    
    [Parameter(HelpMessage = "Run tests in parallel")]
    [switch]$RunParallel,
    
    [Parameter(HelpMessage = "Perform traceroute simulation")]
    [switch]$TraceRoute
)

#region Functions

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "Info"    { Write-Host $logMessage -ForegroundColor Cyan }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
        "Success" { Write-Host $logMessage -ForegroundColor Green }
    }
}

function Test-TcpConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter(Mandatory = $true)]
        [int]$Port,
        
        [Parameter()]
        [int]$Timeout = 1000,
        
        [Parameter()]
        [int]$Count = 1
    )
    
    $results = @()
    
    for ($i = 1; $i -le $Count; $i++) {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connection = $null
        $isSuccess = $false
        $latency = $null
        $error = $null
        
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $connection = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
            $isSuccess = $connection.AsyncWaitHandle.WaitOne($Timeout, $false)
            $stopwatch.Stop()
            $latency = $stopwatch.ElapsedMilliseconds
            
            if ($isSuccess) {
                $tcpClient.EndConnect($connection)
            } else {
                $error = "Connection timed out after $Timeout ms"
                $latency = $Timeout
            }
        }
        catch {
            $isSuccess = $false
            $error = $_.Exception.Message
            $stopwatch.Stop()
            $latency = $stopwatch.ElapsedMilliseconds
        }
        finally {
            if ($tcpClient -ne $null) {
                $tcpClient.Close()
                $tcpClient.Dispose()
            }
        }
        
        $result = [PSCustomObject]@{
            ComputerName = $ComputerName
            Port = $Port
            Protocol = "TCP"
            Success = $isSuccess
            Latency = $latency
            Attempt = $i
            Error = $error
            Timestamp = Get-Date
        }
        
        $results += $result
    }
    
    return $results
}

function Test-IcmpConnection {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter()]
        [int]$Timeout = 1000,
        
        [Parameter()]
        [int]$Count = 4
    )
    
    $results = @()
    
    try {
        # First check if Test-Connection cmdlet supports -Count parameter
        $pingParams = @{
            ComputerName = $ComputerName
            Count = $Count
            ErrorAction = "Stop"
        }
        
        # Add timeout parameter if supported in current PowerShell version
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $pingParams.Add("TimeoutSeconds", [math]::Ceiling($Timeout / 1000))
        } else {
            # PowerShell 5.1 doesn't support timeout parameter for Test-Connection
            # We'll handle this differently
            $pingParams.Add("ErrorAction", "Stop")
        }
        
        # Execute the ping test
        $pingResults = Test-Connection @pingParams
        
        # Process the results
        foreach ($ping in $pingResults) {
            $isSuccess = $true
            $latency = $null
            $error = $null
            
            # Extract latency based on PowerShell version
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $latency = $ping.Latency
            } else {
                $latency = $ping.ResponseTime
            }
            
            $result = [PSCustomObject]@{
                ComputerName = $ComputerName
                Protocol = "ICMP"
                Success = $isSuccess
                Latency = $latency
                Attempt = [array]::IndexOf($pingResults, $ping) + 1
                Error = $error
                Timestamp = Get-Date
            }
            
            $results += $result
        }
    }
    catch {
        for ($i = 1; $i -le $Count; $i++) {
            $result = [PSCustomObject]@{
                ComputerName = $ComputerName
                Protocol = "ICMP"
                Success = $false
                Latency = $null
                Attempt = $i
                Error = $_.Exception.Message
                Timestamp = Get-Date
            }
            
            $results += $result
        }
    }
    
    return $results
}

function Test-TraceRoute {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,
        
        [Parameter()]
        [int]$MaxHops = 30,
        
        [Parameter()]
        [int]$Timeout = 1000
    )
    
    $results = @()
    $currentHop = 1
    $reachedDestination = $false
    
    Write-Log -Message "Starting traceroute to $ComputerName (maximum $MaxHops hops)" -Level Info
    
    while (-not $reachedDestination -and $currentHop -le $MaxHops) {
        $pingResult = $null
        $latency = $null
        $hopAddress = $null
        $error = $null
        $isSuccess = $false
        
        try {
            # Build parameters for Test-Connection
            $params = @{
                ComputerName = $ComputerName
                Count = 1
                TTL = $currentHop
                ErrorAction = "Stop"
            }
            
            # Add timeout parameter if supported in current PowerShell version
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $params.Add("TimeoutSeconds", [math]::Ceiling($Timeout / 1000))
            }
            
            $pingResult = Test-Connection @params
            
            # Process the result
            if ($pingResult) {
                $isSuccess = $true
                
                # Extract latency based on PowerShell version
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $latency = $pingResult.Latency
                    $hopAddress = $pingResult.Reply.Address.IPAddressToString
                } else {
                    $latency = $pingResult.ResponseTime
                    $hopAddress = $pingResult.Address.IPAddressToString
                }
                
                # Check if we've reached the destination
                if ($hopAddress -eq $ComputerName) {
                    $reachedDestination = $true
                }
            }
        }
        catch [System.Net.NetworkInformation.PingException] {
            # TTL exceeded exception indicates we found a hop
            $isSuccess = $true
            $error = "TTL Exceeded"
            $hopAddress = "Unknown"
        }
        catch {
            $isSuccess = $false
            $error = $_.Exception.Message
        }
        
        $result = [PSCustomObject]@{
            Hop = $currentHop
            ComputerName = $ComputerName
            HopAddress = $hopAddress
            Success = $isSuccess
            Latency = $latency
            Error = $error
            Timestamp = Get-Date
        }
        
        $results += $result
        
        # Display hop information
        if ($isSuccess) {
            if ($latency) {
                Write-Host ("{0,-3} {1,-15} {2,5} ms" -f $currentHop, $hopAddress, $latency)
            } else {
                Write-Host ("{0,-3} {1,-15} (No response)" -f $currentHop, $hopAddress)
            }
        } else {
            Write-Host ("{0,-3} * * * Request timed out." -f $currentHop)
        }
        
        $currentHop++
    }
    
    return $results
}

function Format-ConnectionSummary {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Results
    )
    
    Write-Host "`n===== Connection Test Summary =====" -ForegroundColor Cyan
    
    $resultsGrouped = $Results | Group-Object -Property ComputerName, Protocol, Port
    
    foreach ($group in $resultsGrouped) {
        $groupInfo = $group.Name -split ", "
        $target = $groupInfo[0]
        $protocol = $groupInfo[1]
        
        # For TCP connections, we include port information
        if ($protocol -eq "TCP") {
            $port = $groupInfo[2]
            $header = "$target - $protocol Port $port"
        } else {
            $header = "$target - $protocol"
        }
        
        # Calculate statistics
        $attempts = $group.Group.Count
        $successful = ($group.Group | Where-Object { $_.Success -eq $true }).Count
        $failedCount = $attempts - $successful
        $successRate = [math]::Round(($successful / $attempts) * 100, 2)
        
        # Calculate latency statistics for successful attempts
        $successfulAttempts = $group.Group | Where-Object { $_.Success -eq $true -and $_.Latency -ne $null }
        
        if ($successfulAttempts.Count -gt 0) {
            $minLatency = ($successfulAttempts | Measure-Object -Property Latency -Minimum).Minimum
            $maxLatency = ($successfulAttempts | Measure-Object -Property Latency -Maximum).Maximum
            $avgLatency = [math]::Round(($successfulAttempts | Measure-Object -Property Latency -Average).Average, 2)
        } else {
            $minLatency = $null
            $maxLatency = $null
            $avgLatency = $null
        }
        
        # Set color based on success rate
        $statusColor = "Red"
        if ($successRate -eq 100) {
            $statusColor = "Green"
        } elseif ($successRate -ge 75) {
            $statusColor = "Yellow"
        } elseif ($successRate -ge 50) {
            $statusColor = "Yellow"
        }
        
        # Display summary
        Write-Host "`n$header" -ForegroundColor Cyan
        Write-Host "Status: " -NoNewline
        Write-Host "$successful/$attempts succeeded ($successRate%)" -ForegroundColor $statusColor
        
        if ($successfulAttempts.Count -gt 0) {
            Write-Host "Latency: Min=${minLatency}ms, Max=${maxLatency}ms, Avg=${avgLatency}ms"
        } else {
            Write-Host "Latency: N/A (No successful connections)"
        }
        
        # Display specific errors if any
        if ($failedCount -gt 0) {
            $errors = $group.Group | Where-Object { $_.Success -eq $false } | Select-Object -ExpandProperty Error -Unique
            Write-Host "Errors encountered:" -ForegroundColor Yellow
            foreach ($err in $errors) {
                Write-Host "  - $err" -ForegroundColor Yellow
            }
        }
    }
}

function Invoke-ParallelNetworkTest {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Targets,
        
        [Parameter()]
        [array]$Ports,
        
        [Parameter()]
        [string]$Protocol,
        
        [Parameter()]
        [int]$Timeout,
        
        [Parameter()]
        [int]$Count
    )
    
    $results = @()
    $jobs = @()
    
    Write-Log -Message "Starting parallel network tests for $($Targets.Count) targets..." -Level Info
    
    # Create a runspace pool
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, [Environment]::ProcessorCount, $sessionState, $Host)
    $pool.Open()
    
    # PowerShell script to run in parallel for each target
    $scriptBlock = {
        param($target, $ports, $protocol, $timeout, $count, $functions)
        
        # Import the functions
        foreach ($function in $functions.Keys) {
            Invoke-Expression $functions[$function]
        }
        
        $targetResults = @()
        
        if ($protocol -eq "TCP" -or $protocol -eq "Both") {
            foreach ($port in $ports) {
                $targetResults += Test-TcpConnection -ComputerName $target -Port $port -Timeout $timeout -Count $count
            }
        }
        
        if ($protocol -eq "ICMP" -or $protocol -eq "Both") {
            $targetResults += Test-IcmpConnection -ComputerName $target -Timeout $timeout -Count $count
        }
        
        return $targetResults
    }
    
    # Export function definitions to be used in each runspace
    $functionDefinitions = @{
        "Test-TcpConnection" = ${function:Test-TcpConnection}.ToString()
        "Test-IcmpConnection" = ${function:Test-IcmpConnection}.ToString()
        "Write-Log" = ${function:Write-Log}.ToString()
    }
    
    # Create and invoke jobs for each target
    foreach ($target in $Targets) {
        Write-Verbose "Creating parallel job for target: $target"
        
        $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($target).AddArgument($Ports).AddArgument($Protocol).AddArgument($Timeout).AddArgument($Count).AddArgument($functionDefinitions)
        $powershell.RunspacePool = $pool
        
        $jobInfo = [PSCustomObject]@{
            PowerShell = $powershell
            Handle = $powershell.BeginInvoke()
            Target = $target
            StartTime = Get-Date
        }
        
        $jobs += $jobInfo
    }
    
    # Wait for all jobs to complete and collect results
    $totalJobs = $jobs.Count
    $completedJobs = 0
    
    while ($jobs.Handle.IsCompleted -contains $false) {
        $completedJobsNow = ($jobs.Handle.IsCompleted -eq $true).Count
        
        if ($completedJobsNow -gt $completedJobs) {
            $completedJobs = $completedJobsNow
            Write-Progress -Activity "Running Network Tests" -Status "Processing $completedJobs of $totalJobs targets" -PercentComplete (($completedJobs / $totalJobs) * 100)
        }
        
        Start-Sleep -Milliseconds 100
    }
    
    Write-Progress -Activity "Running Network Tests" -Status "Completed" -PercentComplete 100 -Completed
    
    # Collect the results from all jobs
    foreach ($job in $jobs) {
        try {
            $jobResults = $job.PowerShell.EndInvoke($job.Handle)
            if ($jobResults) {
                $results += $jobResults
            }
        }
        catch {
            Write-Log -Message "Error retrieving results for target '$($job.Target)': $_" -Level Error
        }
        finally {
            $job.PowerShell.Dispose()
        }
    }
    
    # Clean up
    $pool.Close()
    $pool.Dispose()
    
    return $results
}

#endregion Functions

#region Main Script Execution

# Script banner
Write-Host "`n===== Network Connection Testing Tool =====" -ForegroundColor Cyan
Write-Host "Testing $($Target.Count) target(s) with protocol: $Protocol`n"

# Validate input parameters
if ($Protocol -eq "TCP" -or $Protocol -eq "Both") {
    if (-not $Ports -or $Ports.Count -eq 0) {
        Write-Log -Message "No TCP ports specified. Using default ports 80 and 443." -Level Warning
        $Ports = @(80, 443)
    }
    
    # Validate port numbers
    foreach ($port in $Ports) {
        if ($port -lt 1 -or $port -gt 65535) {
            Write-Log -Message "Invalid port number: $port. Port must be between 1-65535." -Level Error
            exit 1
        }
    }
    
    Write-Host "TCP Ports to test: $($Ports -join ", ")" -ForegroundColor Cyan
}

# Initialize results array
$allResults = @()

# Execute the tests
try {
    if ($RunParallel) {
        Write-Log -Message "Running tests in parallel mode." -Level Info
        $allResults = Invoke-ParallelNetworkTest -Targets $Target -Ports $Ports -Protocol $Protocol -Timeout $Timeout -Count $Count
    }
    else {
        Write-Log -Message "Running tests in sequential mode." -Level Info
        
        # Sequential testing
        foreach ($computerName in $Target) {
            Write-Host "`nTesting connection to: $computerName" -ForegroundColor Cyan
            
            # TCP tests
            if ($Protocol -eq "TCP" -or $Protocol -eq "Both") {
                foreach ($port in $Ports) {
                    Write-Host "Testing TCP port $port... " -NoNewline
                    
                    $tcpResults = Test-TcpConnection -ComputerName $computerName -Port $port -Timeout $Timeout -Count $Count
                    $allResults += $tcpResults
                    
                    # Display immediate result
                    $successCount = ($tcpResults | Where-Object { $_.Success -eq $true }).Count
                    if ($successCount -eq $Count) {
                        Write-Host "Success" -ForegroundColor Green
                    }
                    elseif ($successCount -gt 0) {
                        Write-Host "Partial ($successCount/$Count successful)" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "Failed" -ForegroundColor Red
                    }
                }
            }
            
            # ICMP tests
            if ($Protocol -eq "ICMP" -or $Protocol -eq "Both") {
                Write-Host "Testing ICMP ping... " -NoNewline
                
                $icmpResults = Test-IcmpConnection -ComputerName $computerName -Timeout $Timeout -Count $Count
                $allResults += $icmpResults
                
                # Display immediate result
                $successCount = ($icmpResults | Where-Object { $_.Success -eq $true }).Count
                if ($successCount -eq $Count) {
                    Write-Host "Success" -ForegroundColor Green
                }
                elseif ($successCount -gt 0) {
                    Write-Host "Partial ($successCount/$Count successful)" -ForegroundColor Yellow
                }
                else {
                    Write-Host "Failed" -ForegroundColor Red
                }
            }
            
            # Traceroute
            if ($TraceRoute) {
                Write-Host "`nPerforming traceroute to $computerName:" -ForegroundColor Cyan
                $traceResults = Test-TraceRoute -ComputerName $computerName -Timeout $Timeout
                # Traceroute results are displayed in the function itself
            }
        }
    }
    
    # Display the summary results
    if ($allResults.Count -gt 0) {
        Format-ConnectionSummary -Results $allResults
    }
    else {
        Write-Log -Message "No results were returned from the network tests." -Level Warning
    }
}
catch {
    Write-Log -Message "Error executing network tests: $_" -Level Error
    Write-Log -Message $_.ScriptStackTrace -Level Error
}

Write-Host "`n===== Test Completed =====" -ForegroundColor Cyan

#endregion Main Script Execution
