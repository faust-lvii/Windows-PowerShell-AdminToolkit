<#
.SYNOPSIS
    Advanced file backup utility with multiple backup modes, compression, and validation.

.DESCRIPTION
    This script provides comprehensive file backup functionality including full, 
    incremental, and differential backup modes. It supports compression, file filtering, 
    progress tracking, backup validation, and email notifications.

.PARAMETER SourcePath
    Specifies the path to the source directory to back up.

.PARAMETER DestinationPath
    Specifies the path where the backup will be stored.

.PARAMETER BackupType
    Specifies the type of backup to perform.
    Valid values: Full, Incremental, Differential
    Default: Full

.PARAMETER CompressionLevel
    Specifies the compression level to use.
    Valid values: None, Fastest, Optimal, SmallestSize
    Default: Optimal

.PARAMETER Include
    Specifies an array of file patterns to include in the backup.
    Example: "*.txt", "*.docx"

.PARAMETER Exclude
    Specifies an array of file patterns to exclude from the backup.
    Example: "*.tmp", "*.log"

.PARAMETER EnableLogging
    Enables detailed logging of the backup process.

.PARAMETER LogPath
    Specifies the path where log files will be stored.
    Default: ".\Logs"

.PARAMETER Validate
    Performs validation of the backup after completion.

.PARAMETER SendEmail
    Sends an email notification after the backup is complete.

.PARAMETER SmtpServer
    Specifies the SMTP server to use for email notifications.

.PARAMETER EmailFrom
    Specifies the sender email address.

.PARAMETER EmailTo
    Specifies the recipient email address(es).

.PARAMETER EmailSubject
    Specifies the subject line for email notifications.
    Default: "Backup Operation Report"

.EXAMPLE
    .\Backup-Files.ps1 -SourcePath "C:\Data" -DestinationPath "D:\Backups"
    
    Performs a full backup of C:\Data to D:\Backups with default settings.

.EXAMPLE
    .\Backup-Files.ps1 -SourcePath "C:\Data" -DestinationPath "D:\Backups" -BackupType Incremental -Include "*.docx","*.xlsx" -Exclude "*.tmp" -EnableLogging -Validate

    Performs an incremental backup of only .docx and .xlsx files, excluding .tmp files, with logging and validation.

.EXAMPLE
    .\Backup-Files.ps1 -SourcePath "C:\Data" -DestinationPath "\\Server\Backups" -BackupType Differential -CompressionLevel SmallestSize -SendEmail -SmtpServer "smtp.example.com" -EmailFrom "backup@example.com" -EmailTo "admin@example.com"

    Performs a differential backup with maximum compression to a network share and sends a notification email.

.NOTES
    File Name      : Backup-Files.ps1
    Prerequisite   : PowerShell 5.1 or later
    Required Modules: Microsoft.PowerShell.Archive (for compression)
    Author         : Your Name
    Version        : 1.0

.LINK
    https://github.com/YourUsername/Windows-PowerShell-AdminToolkit
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.PowerShell.Archive

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$SourcePath,

    [Parameter(Mandatory = $true)]
    [string]$DestinationPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Full", "Incremental", "Differential")]
    [string]$BackupType = "Full",

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Fastest", "Optimal", "SmallestSize")]
    [string]$CompressionLevel = "Optimal",

    [Parameter(Mandatory = $false)]
    [string[]]$Include,

    [Parameter(Mandatory = $false)]
    [string[]]$Exclude,

    [Parameter(Mandatory = $false)]
    [switch]$EnableLogging,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = ".\Logs",

    [Parameter(Mandatory = $false)]
    [switch]$Validate,

    [Parameter(Mandatory = $false)]
    [switch]$SendEmail,

    [Parameter(Mandatory = $false)]
    [string]$SmtpServer,

    [Parameter(Mandatory = $false)]
    [string]$EmailFrom,

    [Parameter(Mandatory = $false)]
    [string[]]$EmailTo,

    [Parameter(Mandatory = $false)]
    [string]$EmailSubject = "Backup Operation Report"
)

# Script variables
$Script:ErrorCount = 0
$Script:StartTime = Get-Date
$Script:BackupHistoryFile = Join-Path $DestinationPath "BackupHistory.xml"
$Script:BackupLogFile = Join-Path (New-Item -ItemType Directory -Path $LogPath -Force) "Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Script:BackupSummary = @{
    StartTime = $Script:StartTime
    EndTime   = $null
    BackupType = $BackupType
    SourcePath = $SourcePath
    DestinationPath = $DestinationPath
    FilesProcessed = 0
    FilesSkipped = 0
    FilesFailed = 0
    TotalSize = 0
    Status = "In Progress"
    ErrorMessages = @()
}

# Function to write log messages
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$TimeStamp] [$Level] $Message"
    
    # Output to console with color
    switch ($Level) {
        "INFO"    { Write-Host $LogMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
    
    # Write to log file if logging is enabled
    if ($EnableLogging) {
        $LogMessage | Out-File -FilePath $Script:BackupLogFile -Append
    }
}

# Function to get backup history
function Get-BackupHistory {
    if (Test-Path $Script:BackupHistoryFile) {
        try {
            [xml]$history = Get-Content $Script:BackupHistoryFile
            return $history
        }
        catch {
            Write-Log "Error reading backup history file: $_" -Level "ERROR"
            return $null
        }
    }
    else {
        # Create a new history file
        $xml = New-Object System.Xml.XmlDocument
        $declaration = $xml.CreateXmlDeclaration("1.0", "UTF-8", $null)
        $xml.AppendChild($declaration) | Out-Null
        
        $rootElement = $xml.CreateElement("BackupHistory")
        $xml.AppendChild($rootElement) | Out-Null
        
        return $xml
    }
}

# Function to update backup history
function Update-BackupHistory {
    param (
        [Parameter(Mandatory = $true)]
        [xml]$History,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$BackupInfo
    )
    
    $backupElement = $History.CreateElement("Backup")
    $backupElement.SetAttribute("Type", $BackupInfo.BackupType)
    $backupElement.SetAttribute("StartTime", $BackupInfo.StartTime.ToString("o"))
    $backupElement.SetAttribute("EndTime", $BackupInfo.EndTime.ToString("o"))
    $backupElement.SetAttribute("Status", $BackupInfo.Status)
    $backupElement.SetAttribute("FilesProcessed", $BackupInfo.FilesProcessed.ToString())
    $backupElement.SetAttribute("TotalSize", $BackupInfo.TotalSize.ToString())
    
    $sourceElement = $History.CreateElement("Source")
    $sourceElement.InnerText = $BackupInfo.SourcePath
    $backupElement.AppendChild($sourceElement) | Out-Null
    
    $destinationElement = $History.CreateElement("Destination")
    $destinationElement.InnerText = $BackupInfo.DestinationPath
    $backupElement.AppendChild($destinationElement) | Out-Null
    
    if ($BackupInfo.ErrorMessages.Count -gt 0) {
        $errorsElement = $History.CreateElement("Errors")
        foreach ($error in $BackupInfo.ErrorMessages) {
            $errorElement = $History.CreateElement("Error")
            $errorElement.InnerText = $error
            $errorsElement.AppendChild($errorElement) | Out-Null
        }
        $backupElement.AppendChild($errorsElement) | Out-Null
    }
    
    $History.DocumentElement.AppendChild($backupElement) | Out-Null
    
    try {
        $History.Save($Script:BackupHistoryFile)
    }
    catch {
        Write-Log "Error saving backup history: $_" -Level "ERROR"
    }
}

# Function to get the last successful backup date
function Get-LastBackupDate {
    param (
        [Parameter(Mandatory = $true)]
        [string]$BackupType
    )
    
    $history = Get-BackupHistory
    if ($null -eq $history) {
        return $null
    }
    
    $lastSuccessfulBackup = $null
    
    # For Incremental, we need the last successful backup of any type
    if ($BackupType -eq "Incremental") {
        $lastSuccessfulBackup = $history.BackupHistory.Backup | 
            Where-Object { $_.Status -eq "Completed" } | 
            Sort-Object { [DateTime]$_.StartTime } -Descending | 
            Select-Object -First 1
    }
    # For Differential, we need the last full backup
    elseif ($BackupType -eq "Differential") {
        $lastSuccessfulBackup = $history.BackupHistory.Backup | 
            Where-Object { $_.Status -eq "Completed" -and $_.Type -eq "Full" } | 
            Sort-Object { [DateTime]$_.StartTime } -Descending | 
            Select-Object -First 1
    }
    
    if ($null -ne $lastSuccessfulBackup) {
        return [DateTime]$lastSuccessfulBackup.StartTime
    }
    else {
        return $null
    }
}

# Function to filter files based on inclusion/exclusion patterns
function Test-FileFilter {
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Include,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Exclude
    )
    
    $fileName = Split-Path $FilePath -Leaf
    
    # If include filter is specified and file doesn't match any include pattern, exclude it
    if ($Include -and $Include.Count -gt 0) {
        $includeMatch = $false
        foreach ($pattern in $Include) {
            if ($fileName -like $pattern) {
                $includeMatch = $true
                break
            }
        }
        if (-not $includeMatch) {
            return $false
        }
    }
    
    # If exclude filter is specified and file matches any exclude pattern, exclude it
    if ($Exclude -and $Exclude.Count -gt 0) {
        foreach ($pattern in $Exclude) {
            if ($fileName -like $pattern) {
                return $false
            }
        }
    }
    
    return $true
}

# Function to perform file backup
function Backup-FilesOperation {
    param (
        [Parameter(Mandatory = $true)]
        [string]$BackupName
    )
    
    try {
        # Create backup destination if it doesn't exist
        if (-not (Test-Path -Path $DestinationPath)) {
            New-Item -ItemType Directory -Path $DestinationPath -Force | Out-Null
            Write-Log "Created destination directory: $DestinationPath" -Level "INFO"
        }
        
        # Create backup directory
        $backupDir = Join-Path -Path $DestinationPath -ChildPath $BackupName
        if (-not (Test-Path -Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            Write-Log "Created backup directory: $backupDir" -Level "INFO"
        }
        
        # Determine which files to back up based on backup type
        $filesToBackup = @()
        $lastBackupDate = $null
        
        switch ($BackupType) {
            "Full" {
                Write-Log "Starting Full backup of $SourcePath" -Level "INFO"
                $filesToBackup = Get-ChildItem -Path $SourcePath -Recurse -File
            }
            "Incremental" {
                $lastBackupDate = Get-LastBackupDate -BackupType "Incremental"
                if ($lastBackupDate) {
                    Write-Log "Starting Incremental backup of $SourcePath (changes since $($lastBackupDate.ToString('yyyy-MM-dd HH:mm:ss')))" -Level "INFO"
                    $filesToBackup = Get-ChildItem -Path $SourcePath -Recurse -File | Where-Object { $_.LastWriteTime -gt $lastBackupDate }
                }
                else {
                    Write-Log "No previous backup found. Performing a Full backup instead." -Level "WARNING"
                    $filesToBackup = Get-ChildItem -Path $SourcePath -Recurse -File
                }
            }
            "Differential" {
                $lastBackupDate = Get-LastBackupDate -BackupType "Differential"
                if ($lastBackupDate) {
                    Write-Log "Starting Differential backup of $SourcePath (changes since last Full backup: $($lastBackupDate.ToString('yyyy-MM-dd HH:mm:ss')))" -Level "INFO"
                    $filesToBackup = Get-ChildItem -Path $SourcePath -Recurse -File | Where-Object { $_.LastWriteTime -gt $lastBackupDate }
                }
                else {
                    Write-Log "No previous Full backup found. Performing a Full backup instead." -Level "WARNING"
                    $filesToBackup = Get-ChildItem -Path $SourcePath -Recurse -File
                }
            }
        }
        
        # Apply file filters
        $filteredFiles = @()
        foreach ($file in $filesToBackup) {
            if (Test-FileFilter -FilePath $file.FullName -Include $Include -Exclude $Exclude) {
                $filteredFiles += $file
            }
            else {
                Write-Log "Skipping file (filtered out): $($file.FullName)" -Level "INFO"
                $Script:BackupSummary.FilesSkipped++
            }
        }
        

