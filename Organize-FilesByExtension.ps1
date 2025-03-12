<#
.SYNOPSIS
    Organizes files into folders based on extension, file type, or custom categories.

.DESCRIPTION
    The Organize-FilesByExtension script helps organize files by moving or copying them
    into folders based on file extension, file type (documents, images, videos, etc.),
    or custom categories defined by the user. It includes preview functionality,
    progress tracking, logging, error handling, and undo capabilities.

.PARAMETER SourcePath
    The path to the directory containing files to organize.

.PARAMETER DestinationPath
    The path to the directory where organized files will be placed.
    If not specified, a subfolder structure will be created in the source directory.

.PARAMETER OrganizeBy
    How to organize the files. Options are:
    - Extension (default): Organize by file extension
    - FileType: Organize by type (documents, images, videos, etc.)
    - Custom: Organize using custom rules defined in the CustomCategories parameter

.PARAMETER CustomCategories
    A hashtable defining custom categories and their file patterns.
    Example: @{"MyDocs"="*.doc,*.docx,*.pdf"; "MyData"="*.xls,*.xlsx,*.csv"}

.PARAMETER Operation
    The operation to perform. Options are:
    - Copy (default): Copy files to destination folders
    - Move: Move files to destination folders

.PARAMETER PreviewOnly
    If specified, only shows what would happen without actually moving/copying files.

.PARAMETER MaintainStructure
    If specified, maintains the original folder structure within destination folders.

.PARAMETER LogFile
    Path to the log file. If not specified, logs are created in a 'Logs' subfolder
    with a timestamp in the filename.

.PARAMETER Force
    If specified, overwrites existing files without prompting.

.PARAMETER ExcludePattern
    File pattern(s) to exclude from organization.

.PARAMETER UndoLastOperation
    If specified, undoes the last organization operation using the undo log.

.EXAMPLE
    .\Organize-FilesByExtension.ps1 -SourcePath "C:\Downloads" -OrganizeBy Extension
    
    Organizes all files in C:\Downloads by their file extension.

.EXAMPLE
    .\Organize-FilesByExtension.ps1 -SourcePath "C:\Users\User\Documents" -OrganizeBy FileType -Operation Move -PreviewOnly
    
    Shows a preview of moving and organizing files by type (documents, images, etc.) without actually moving them.

.EXAMPLE
    .\Organize-FilesByExtension.ps1 -SourcePath "C:\Data" -OrganizeBy Custom -CustomCategories @{"Work"="*.doc,*.xls,*.ppt"; "Personal"="*.jpg,*.mp3,*.mp4"}
    
    Organizes files into custom categories "Work" and "Personal" based on the defined patterns.

.EXAMPLE
    .\Organize-FilesByExtension.ps1 -UndoLastOperation
    
    Undoes the last file organization operation using the stored undo information.

.NOTES
    Author: PowerShell Script Author
    Last Update: $(Get-Date -Format "yyyy-MM-dd")
    Version: 1.0
#>

#requires -version 5.1

[CmdletBinding(DefaultParameterSetName="Organize")]
param (
    [Parameter(Mandatory=$true, ParameterSetName="Organize", Position=0)]
    [string]$SourcePath,
    
    [Parameter(ParameterSetName="Organize")]
    [string]$DestinationPath,
    
    [Parameter(ParameterSetName="Organize")]
    [ValidateSet("Extension", "FileType", "Custom")]
    [string]$OrganizeBy = "Extension",
    
    [Parameter(ParameterSetName="Organize")]
    [hashtable]$CustomCategories,
    
    [Parameter(ParameterSetName="Organize")]
    [ValidateSet("Copy", "Move")]
    [string]$Operation = "Copy",
    
    [Parameter(ParameterSetName="Organize")]
    [switch]$PreviewOnly,
    
    [Parameter(ParameterSetName="Organize")]
    [switch]$MaintainStructure,
    
    [Parameter(ParameterSetName="Organize")]
    [string]$LogFile,
    
    [Parameter(ParameterSetName="Organize")]
    [switch]$Force,
    
    [Parameter(ParameterSetName="Organize")]
    [string[]]$ExcludePattern,
    
    [Parameter(Mandatory=$true, ParameterSetName="Undo")]
    [switch]$UndoLastOperation
)

#--------------------
# SCRIPT VARIABLES
#--------------------
$script:ScriptName = $MyInvocation.MyCommand.Name
$script:ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$script:StartTime = Get-Date
$script:UndoLogFile = Join-Path $env:TEMP "OrganizeFiles_UndoLog.xml"
$script:OperationLog = [System.Collections.ArrayList]@()
$script:FilesMoved = 0
$script:FilesCopied = 0
$script:FilesSkipped = 0
$script:FilesError = 0
$script:TotalFiles = 0
$script:TotalSize = 0
$script:ProgressCount = 0

# Define file type mappings
$script:FileTypeMappings = @{
    "Documents" = @(".doc", ".docx", ".rtf", ".txt", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".tex", ".md", ".csv")
    "Images" = @(".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".webp", ".ico", ".raw", ".psd", ".ai", ".eps")
    "Videos" = @(".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpeg", ".mpg", ".3gp", ".m2ts")
    "Audio" = @(".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma", ".m4a", ".alac", ".aiff", ".dsd")
    "Archives" = @(".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso", ".tgz")
    "Code" = @(".py", ".js", ".html", ".css", ".java", ".c", ".cpp", ".cs", ".php", ".rb", ".go", ".swift", ".ts", ".json", ".xml", ".yaml", ".ps1", ".psm1", ".sh", ".bat", ".cmd", ".sql")
    "Executables" = @(".exe", ".msi", ".dll", ".app", ".bat", ".com", ".jar", ".apk", ".appx", ".deb", ".rpm")
    "Fonts" = @(".ttf", ".otf", ".woff", ".woff2", ".eot")
    "Ebooks" = @(".epub", ".mobi", ".azw", ".azw3")
    "Database" = @(".db", ".sqlite", ".mdb", ".accdb", ".dbf")
    "Spreadsheets" = @(".xls", ".xlsx", ".csv", ".ods", ".xlsm")
    "Presentations" = @(".ppt", ".pptx", ".odp", ".key")
    "Web" = @(".html", ".htm", ".css", ".js", ".php", ".asp", ".aspx", ".jsp")
    "3D" = @(".obj", ".fbx", ".3ds", ".blend", ".stl", ".dae", ".glb")
    "CAD" = @(".dwg", ".dxf", ".3dm", ".skp")
    "Vector" = @(".svg", ".ai", ".eps", ".cdr")
    "Other" = @()
}

#--------------------
# FUNCTIONS
#--------------------

function Initialize-Logger {
    param (
        [string]$LogFilePath
    )
    
    if ([string]::IsNullOrEmpty($LogFilePath)) {
        $logDir = Join-Path $script:ScriptPath "Logs"
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $LogFilePath = Join-Path $logDir "FileOrganizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }
    
    # Ensure log directory exists
    $logDirectory = Split-Path -Parent $LogFilePath
    if (-not (Test-Path $logDirectory)) {
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
    }
    
    return $LogFilePath
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        
        [Parameter()]
        [switch]$NoConsole
    )
    
    $timeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timeStamp] [$Level] $Message"
    
    # Add to log file
    Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue
    
    # Write to console with appropriate color if not suppressed
    if (-not $NoConsole) {
        $color = switch ($Level) {
            "INFO"    { "White" }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red" }
            "SUCCESS" { "Green" }
            default   { "White" }
        }
        Write-Host $logMessage -ForegroundColor $color
    }
}

function Get-FileCategory {
    param (
        [Parameter(Mandatory=$true)]
        [System.IO.FileInfo]$File,
        
        [Parameter(Mandatory=$true)]
        [string]$OrganizationMethod,
        
        [Parameter()]
        [hashtable]$CustomCategoryMap
    )
    
    $extension = $File.Extension.ToLower()
    
    switch ($OrganizationMethod) {
        "Extension" {
            # If no extension, use "NoExtension" as the category
            if ([string]::IsNullOrWhiteSpace($extension)) {
                return "NoExtension"
            }
            # Remove the dot and return the extension
            return $extension.TrimStart(".")
        }
        
        "FileType" {
            foreach ($type in $script:FileTypeMappings.Keys) {
                if ($script:FileTypeMappings[$type] -contains $extension) {
                    return $type
                }
            }
            return "Other"
        }
        
        "Custom" {
            if ($null -eq $CustomCategoryMap) {
                Write-Log "No custom categories provided. Using extension method." -Level WARNING
                return $extension.TrimStart(".")
            }
            
            foreach ($category in $CustomCategoryMap.Keys) {
                $patterns = $CustomCategoryMap[$category] -split ','
                foreach ($pattern in $patterns) {
                    $pattern = $pattern.Trim()
                    if ($File.Name -like $pattern) {
                        return $category
                    }
                }
            }
            return "Uncategorized"
        }
    }
}

function New-DestinationPath {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RootPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter()]
        [string]$RelativePath = "",
        
        [Parameter()]
        [switch]$MaintainFolderStructure
    )
    
    $categoryPath = Join-Path $RootPath $Category
    
    if ($MaintainFolderStructure -and ![string]::IsNullOrWhiteSpace($RelativePath)) {
        $finalPath = Join-Path $categoryPath $RelativePath
    } else {
        $finalPath = $categoryPath
    }
    
    if (-not (Test-Path $finalPath)) {
        New-Item -ItemType Directory -Path $finalPath -Force | Out-Null
    }
    
    return $finalPath
}

function Resolve-FileNameConflict {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter()]
        [switch]$Force
    )
    
    if (Test-Path $FilePath) {
        if ($Force) {
            return $FilePath
        }
        
        $directory = Split-Path -Parent $FilePath
        $fileName = Split-Path -Leaf $FilePath
        $fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        $extension = [System.IO.Path]::GetExtension($fileName)
        
        $counter = 1
        $newFilePath = $FilePath
        
        while (Test-Path $newFilePath) {
            $newFileName = "$fileNameWithoutExtension($counter)$extension"
            $newFilePath = Join-Path $directory $newFileName
            $counter++
        }
        
        return $newFilePath
    }
    
    return $FilePath
}

function Add-UndoEntry {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath,
        
        [Parameter(Mandatory=$true)]
        [string]$Operation
    )
    
    $undoEntry = [PSCustomObject]@{
        SourcePath = $SourcePath
        DestinationPath = $DestinationPath
        Operation = $Operation
        Timestamp = Get-Date
    }
    
    $script:OperationLog.Add($undoEntry) | Out-Null
}

function Save-UndoLog {
    $undoLog = [PSCustomObject]@{
        OperationLog = $script:OperationLog
        SourcePath = $SourcePath
        DestinationPath = $DestinationPath
        OrganizeBy = $OrganizeBy
        Operation = $Operation
        Timestamp = Get-Date
    }
    
    $undoLog | Export-Clixml -Path $script:UndoLogFile -Force
    Write-Log "Undo log saved to: $script:UndoLogFile" -Level INFO -NoConsole
}

function Invoke-UndoOperation {
    if (-not (Test-Path $script:UndoLogFile)) {
        Write-Log "Undo log file not found: $script:UndoLogFile" -Level ERROR
        return $false
    }
    
    try {
        $undoLog = Import-Clixml -Path $script:UndoLogFile
        $operationLog = $undoLog.OperationLog
        
        Write-Log "Starting undo operation for: $($undoLog.Operation) performed at $($undoLog.Timestamp)" -Level INFO
        Write-Log "Original source: $($undoLog.SourcePath)" -Level INFO
        Write-Log "Original destination: $($undoLog

