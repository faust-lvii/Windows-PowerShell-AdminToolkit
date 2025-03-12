<#
.SYNOPSIS
    Archives files and directories with multiple compression formats, encryption, and verification options.

.DESCRIPTION
    This PowerShell script provides comprehensive file archiving capabilities with support for:
    - Multiple compression formats (ZIP, 7Z)
    - Encryption and password protection
    - Split archive capability for large archives
    - Archive testing and verification
    - Progress reporting
    - File filtering options
    - Comprehensive logging
    - Incremental archiving
    - Archive management and cleanup

.PARAMETER Path
    Specifies the path to files or directories to archive.

.PARAMETER DestinationPath
    Specifies the output path for the archive file.

.PARAMETER Format
    Specifies the archive format. Valid values are: ZIP, 7Z.
    Default is ZIP.

.PARAMETER CompressionLevel
    Specifies the compression level. Valid values are: Normal, Fast, Ultra.
    Default is Normal.

.PARAMETER Password
    Specifies a password to encrypt the archive.

.PARAMETER SplitSize
    Specifies the size in MB to split the archive into multiple parts.

.PARAMETER Filter
    Specifies a filter to include only specific files.

.PARAMETER Exclude
    Specifies patterns to exclude files from the archive.

.PARAMETER Incremental
    Specifies that only files modified since the last archive should be included.

.PARAMETER LogPath
    Specifies the path to write log files.
    Default is "$env:TEMP\ArchiveOperations.log"

.PARAMETER Test
    Performs a test of the archive after creation.

.PARAMETER CleanupDays
    Removes archives older than the specified number of days.

.PARAMETER NoProgress
    Suppresses progress information.

.EXAMPLE
    PS> .\Archive-Files.ps1 -Path C:\Data -DestinationPath C:\Backups\data.zip

    Archives the Data folder as a ZIP file in the Backups directory.

.EXAMPLE
    PS> .\Archive-Files.ps1 -Path C:\Projects -DestinationPath C:\Backups\projects.7z -Format 7Z -Password "SecurePass123" -Test

    Archives the Projects folder as a password-protected 7Z file and tests the archive after creation.

.EXAMPLE
    PS> .\Archive-Files.ps1 -Path C:\Logs -DestinationPath C:\Backups\logs.zip -Filter "*.log" -Incremental -CleanupDays 30

    Archives only log files that changed since the last backup and removes archives older than 30 days.

.EXAMPLE
    PS> .\Archive-Files.ps1 -Path C:\LargeData -DestinationPath C:\Backups\large-data.7z -Format 7Z -SplitSize 100 -CompressionLevel Ultra

    Archives the LargeData folder as a 7Z file with ultra compression, split into 100MB parts.

.NOTES
    Author: PowerShell AdminToolkit
    Version: 1.0
    Required Dependencies: 7-Zip (for 7Z format support)
    Optional Dependencies: None
#>

[CmdletBinding(DefaultParameterSetName = "Default")]
param (
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter(Mandatory = $true, Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("ZIP", "7Z")]
    [string]$Format = "ZIP",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Normal", "Fast", "Ultra")]
    [string]$CompressionLevel = "Normal",

    [Parameter(Mandatory = $false)]
    [string]$Password,

    [Parameter(Mandatory = $false)]
    [int]$SplitSize,

    [Parameter(Mandatory = $false)]
    [string[]]$Filter,

    [Parameter(Mandatory = $false)]
    [string[]]$Exclude,

    [Parameter(Mandatory = $false)]
    [switch]$Incremental,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:TEMP\ArchiveOperations.log",

    [Parameter(Mandatory = $false)]
    [switch]$Test,

    [Parameter(Mandatory = $false)]
    [int]$CleanupDays,

    [Parameter(Mandatory = $false)]
    [switch]$NoProgress
)

begin {
    # Define error action preference
    $ErrorActionPreference = "Stop"

    # Initialize logging function
    function Write-Log {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Message,

            [Parameter(Mandatory = $false)]
            [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
            [string]$Level = "INFO"
        )

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logEntry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $LogPath -Value $logEntry -Encoding UTF8

        # Also write to console with appropriate color
        switch ($Level) {
            "INFO"    { Write-Host $logEntry -ForegroundColor Gray }
            "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $logEntry -ForegroundColor Red }
            "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        }
    }

    # Check for required dependencies
    function Test-Dependencies {
        if ($Format -eq "7Z") {
            try {
                $7zPath = "$env:ProgramFiles\7-Zip\7z.exe"
                if (-not (Test-Path $7zPath)) {
                    $7zPath = "${env:ProgramFiles(x86)}\7-Zip\7z.exe"
                    if (-not (Test-Path $7zPath)) {
                        throw "7-Zip is not installed or not found in the default locations."
                    }
                }
                return $7zPath
            }
            catch {
                Write-Log "Error: 7-Zip is required for 7Z format but was not found." -Level "ERROR"
                Write-Log "Please install 7-Zip from https://www.7-zip.org/" -Level "INFO"
                throw
            }
        }
        return $null
    }

    # Create a backup record for incremental backups
    function Update-BackupRecord {
        param (
            [string]$sourcePath,
            [string]$archivePath,
            [datetime]$backupTime
        )

        $backupRecordPath = "$env:APPDATA\PowerShell-AdminToolkit\BackupRecords"
        if (-not (Test-Path $backupRecordPath)) {
            New-Item -Path $backupRecordPath -ItemType Directory -Force | Out-Null
        }

        # Create a unique ID based on source path
        $sourcePathHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sourcePath))
        $sourcePathId = [System.BitConverter]::ToString($sourcePathHash).Replace("-", "").ToLower().Substring(0, 16)
        
        $recordFile = Join-Path $backupRecordPath "$sourcePathId.json"
        $record = @{
            SourcePath = $sourcePath
            LastBackupPath = $archivePath
            LastBackupTime = $backupTime.ToString("o")
            BackupHistory = @()
        }

        if (Test-Path $recordFile) {
            $existingRecord = Get-Content $recordFile -Raw | ConvertFrom-Json
            if ($existingRecord.BackupHistory -eq $null) {
                $existingRecord | Add-Member -MemberType NoteProperty -Name "BackupHistory" -Value @()
            }
            
            # Add current backup to history (limited to last 10)
            $backupInfo = @{
                Path = $archivePath
                Time = $backupTime.ToString("o")
                Type = if ($Incremental) { "Incremental" } else { "Full" }
            }
            
            $history = @($existingRecord.BackupHistory)
            if ($history.Count -ge 10) {
                $history = $history[0..8]  # Keep only the last 9
            }
            $history = @($backupInfo) + $history
            
            $record = @{
                SourcePath = $sourcePath
                LastBackupPath = $archivePath
                LastBackupTime = $backupTime.ToString("o")
                BackupHistory = $history
            }
        }

        $record | ConvertTo-Json | Set-Content $recordFile
        return $record
    }

    # Get the last backup time for a path
    function Get-LastBackupTime {
        param (
            [string]$sourcePath
        )

        $backupRecordPath = "$env:APPDATA\PowerShell-AdminToolkit\BackupRecords"
        if (-not (Test-Path $backupRecordPath)) {
            return $null
        }

        $sourcePathHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sourcePath))
        $sourcePathId = [System.BitConverter]::ToString($sourcePathHash).Replace("-", "").ToLower().Substring(0, 16)
        
        $recordFile = Join-Path $backupRecordPath "$sourcePathId.json"
        if (Test-Path $recordFile) {
            $record = Get-Content $recordFile -Raw | ConvertFrom-Json
            return [datetime]::Parse($record.LastBackupTime)
        }
        
        return $null
    }

    # Create a verification report
    function New-VerificationReport {
        param (
            [string]$sourcePath,
            [string]$archivePath,
            [string]$reportPath,
            [bool]$testResult,
            [int]$fileCount,
            [long]$totalSize,
            [long]$compressedSize
        )

        $compressionRatio = if ($totalSize -gt 0) { 
            [math]::Round(100 - (($compressedSize / $totalSize) * 100), 2) 
        } else { 
            0 
        }

        $report = @"
# Archive Verification Report
- **Generated**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
- **Source Path**: $sourcePath
- **Archive Path**: $archivePath

## Archive Information
- **Format**: $Format
- **Compression Level**: $CompressionLevel
- **Encrypted**: $($Password -ne $null -and $Password -ne '')
- **Split Archive**: $($SplitSize -gt 0)

## Content Summary
- **Total Files**: $fileCount
- **Original Size**: $([math]::Round($totalSize / 1MB, 2)) MB
- **Compressed Size**: $([math]::Round($compressedSize / 1MB, 2)) MB
- **Compression Ratio**: $compressionRatio%

## Verification Results
- **Test Performed**: $Test
- **Test Result**: $($testResult ? "Passed ✓" : "Failed ✗")
- **Verification Date**: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Archive Details
- **Created By**: $([Environment]::UserName)
- **Computer**: $([Environment]::MachineName)
- **Incremental**: $Incremental
"@

        $report | Out-File -FilePath $reportPath -Encoding UTF8
        return $reportPath
    }

    # Initialize script
    try {
        # Verify the destination directory exists
        $destinationDir = Split-Path -Path $DestinationPath -Parent
        if (-not (Test-Path $destinationDir)) {
            New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
            Write-Log "Created destination directory: $destinationDir" -Level "INFO"
        }

        # Ensure the log directory exists
        $logDir = Split-Path -Path $LogPath -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }

        Write-Log "Starting archive operation" -Level "INFO"
        Write-Log "Format: $Format, Compression: $CompressionLevel, Incremental: $Incremental" -Level "INFO"

        # Check for 7-Zip if required
        $7zPath = Test-Dependencies

        # Cleanup old archives if specified
        if ($CleanupDays -gt 0) {
            $cleanupDate = (Get-Date).AddDays(-$CleanupDays)
            $archiveDir = Split-Path -Path $DestinationPath -Parent
            $archiveBaseName = [System.IO.Path]::GetFileNameWithoutExtension($DestinationPath)
            $archiveExt = [System.IO.Path]::GetExtension($DestinationPath)
            
            $oldArchives = Get-ChildItem -Path $archiveDir -Filter "$archiveBaseName*$archiveExt" |
                Where-Object { $_.LastWriteTime -lt $cleanupDate }
            
            if ($oldArchives.Count -gt 0) {
                Write-Log "Cleaning up $($oldArchives.Count) old archives older than $CleanupDays days" -Level "INFO"
                $oldArchives | ForEach-Object {
                    Remove-Item $_.FullName -Force
                    Write-Log "Removed old archive: $($_.FullName)" -Level "INFO"
                }
            }
        }

        # Initialize stats
        $fileCount = 0
        $totalSize = 0
        $compressedSize = 0
    }
    catch {
        Write-Log "Initialization error: $_" -Level "ERROR"
        throw
    }
}

process {
    try {
        # Process each path
        foreach ($sourcePath in $Path) {
            Write-Log "Processing source path: $sourcePath" -Level "INFO"
            
            # Verify the source path exists
            if (-not (Test-Path $sourcePath)) {
                Write-Log "Source path not found: $sourcePath" -Level "ERROR"
                continue
            }

            # Get file list based on filters
            $files = @()
            if ($Filter) {
                foreach ($f in $Filter) {
                    if (Test-Path $sourcePath -PathType Container) {
                        $files += Get-ChildItem -Path $sourcePath -Recurse -File -Filter $f
                    }
                    else {
                        if ($sourcePath -like $f) {
                            $files += Get-Item -Path $sourcePath
                        }
                    }
                }
            }
            else {
                if (Test-Path $sourcePath -PathType Container) {
                    $files += Get-ChildItem -Path $sourcePath -Recurse -File
                }
                else {
                    $files += Get-Item -Path $sourcePath
                }
            }

            # Apply exclude filters if specified
            if ($Exclude) {
                foreach ($e in $Exclude) {
                    $files = $files | Where-Object { $_.FullName -notlike $e }
                }
            }
            
            # For incremental backups, filter by last modifie

