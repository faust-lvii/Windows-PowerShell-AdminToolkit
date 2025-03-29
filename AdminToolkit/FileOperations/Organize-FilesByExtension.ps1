<#
.SYNOPSIS
    Organizes files by their extensions into dedicated folders.

.DESCRIPTION
    This script organizes files from a source directory into a destination directory,
    creating folders based on file extensions. It offers options to preserve the original
    directory structure, include subdirectories, and delete empty source directories
    after organization.

.PARAMETER SourcePath
    Path to the directory containing files to organize.

.PARAMETER DestinationRoot
    Path where the organized files will be stored.

.PARAMETER DeleteEmptySource
    If specified, empty source directories will be deleted after files are moved.

.PARAMETER PreserveStructure
    If specified, the original directory structure will be preserved within each
    extension folder.

.PARAMETER Recurse
    If specified, files in subdirectories will also be organized.

.PARAMETER Force
    If specified, confirmations for large file operations will be skipped.

.EXAMPLE
    PS> .\Organize-FilesByExtension.ps1 -SourcePath "C:\Downloads" -DestinationRoot "D:\Organized"
    
    Organizes all files in C:\Downloads by their extensions into D:\Organized.

.EXAMPLE
    PS> .\Organize-FilesByExtension.ps1 -SourcePath "C:\Projects" -DestinationRoot "D:\Backup" -Recurse -PreserveStructure
    
    Organizes all files in C:\Projects including subdirectories, preserving the original directory structure.

.EXAMPLE
    PS> .\Organize-FilesByExtension.ps1 -SourcePath "C:\Temp" -DestinationRoot "D:\Sorted" -DeleteEmptySource -Force
    
    Organizes all files in C:\Temp, deletes empty directories, and skips confirmations.

.NOTES
    Author: System Administrator
    Date: $(Get-Date -Format "yyyy-MM-dd")
    Version: 1.0
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the directory containing files to organize")]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$SourcePath,

    [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Path where the organized files will be stored")]
    [string]$DestinationRoot,

    [Parameter(HelpMessage = "Delete empty source directories after organization")]
    [switch]$DeleteEmptySource,

    [Parameter(HelpMessage = "Maintain original directory structure")]
    [switch]$PreserveStructure,

    [Parameter(HelpMessage = "Include files in subdirectories")]
    [switch]$Recurse,

    [Parameter(HelpMessage = "Skip confirmations")]
    [switch]$Force
)

# Initialize logging
$LogFile = Join-Path -Path $PSScriptRoot -ChildPath "FileOrganize_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet("INFO", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Output to console with color coding
    switch ($Level) {
        "INFO" { Write-Host $LogEntry -ForegroundColor Green }
        "WARNING" { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $LogEntry -ForegroundColor Red }
    }
    
    # Append to log file
    Add-Content -Path $LogFile -Value $LogEntry
}

function Test-PathValidation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Source", "Destination")]
        [string]$Type
    )
    
    try {
        if ($Type -eq "Source") {
            if (-not (Test-Path -Path $Path -PathType Container)) {
                Write-Log -Message "Source path does not exist or is not a directory: $Path" -Level "ERROR"
                return $false
            }
        }
        else { # Destination
            if (-not (Test-Path -Path $Path -PathType Container)) {
                try {
                    New-Item -Path $Path -ItemType Directory -Force | Out-Null
                    Write-Log -Message "Created destination directory: $Path" -Level "INFO"
                }
                catch {
                    Write-Log -Message "Failed to create destination directory: $Path. Error: $_" -Level "ERROR"
                    return $false
                }
            }
        }
        return $true
    }
    catch {
        Write-Log -Message "Error validating path $Path. Error: $_" -Level "ERROR"
        return $false
    }
}

function Get-AllFiles {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter()]
        [switch]$Recurse
    )
    
    $getChildItemParams = @{
        Path = $Path
        File = $true
    }
    
    if ($Recurse) {
        $getChildItemParams.Add("Recurse", $true)
    }
    
    try {
        $files = Get-ChildItem @getChildItemParams
        Write-Log -Message "Found $($files.Count) files in $Path $(if ($Recurse) {"(including subdirectories)"})" -Level "INFO"
        return $files
    }
    catch {
        Write-Log -Message "Error retrieving files from $Path. Error: $_" -Level "ERROR"
        return @()
    }
}

function Confirm-LargeOperation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$FileCount,
        
        [Parameter()]
        [switch]$Force
    )
    
    $threshold = 100 # Define what counts as a large operation
    
    if ($FileCount -ge $threshold -and -not $Force) {
        Write-Log -Message "About to move $FileCount files. This is a large operation." -Level "WARNING"
        $confirmation = Read-Host "Are you sure you want to continue? (Y/N)"
        
        if ($confirmation -ne "Y") {
            Write-Log -Message "Operation cancelled by user" -Level "INFO"
            return $false
        }
    }
    
    return $true
}

function Move-FilesToExtensionFolders {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo[]]$Files,
        
        [Parameter(Mandatory = $true)]
        [string]$DestinationRoot,
        
        [Parameter()]
        [switch]$PreserveStructure,
        
        [Parameter()]
        [string]$SourceBasePath
    )
    
    $totalFiles = $Files.Count
    $processedFiles = 0
    $movedFiles = 0
    $errorFiles = 0
    
    foreach ($file in $Files) {
        $processedFiles++
        
        # Update progress bar
        $percentComplete = ($processedFiles / $totalFiles) * 100
        Write-Progress -Activity "Moving Files" -Status "$processedFiles of $totalFiles files processed" -PercentComplete $percentComplete
        
        # Get file extension (or use "NoExtension" if none exists)
        $extension = if ([string]::IsNullOrEmpty($file.Extension)) { "NoExtension" } else { $file.Extension.TrimStart(".") }
        
        # Create extension folder if it doesn't exist
        $extensionFolder = Join-Path -Path $DestinationRoot -ChildPath $extension
        if (-not (Test-Path -Path $extensionFolder -PathType Container)) {
            try {
                New-Item -Path $extensionFolder -ItemType Directory -Force | Out-Null
                Write-Log -Message "Created extension folder: $extensionFolder" -Level "INFO"
            }
            catch {
                Write-Log -Message "Failed to create extension folder: $extensionFolder. Error: $_" -Level "ERROR"
                $errorFiles++
                continue
            }
        }
        
        # Determine destination path based on PreserveStructure parameter
        $destinationPath = $extensionFolder
        
        if ($PreserveStructure) {
            # Get relative path from source
            $relativePath = $file.DirectoryName.Substring($SourceBasePath.Length).TrimStart('\', '/')
            if (-not [string]::IsNullOrEmpty($relativePath)) {
                $destinationPath = Join-Path -Path $extensionFolder -ChildPath $relativePath
                if (-not (Test-Path -Path $destinationPath -PathType Container)) {
                    try {
                        New-Item -Path $destinationPath -ItemType Directory -Force | Out-Null
                        Write-Log -Message "Created structure directory: $destinationPath" -Level "INFO"
                    }
                    catch {
                        Write-Log -Message "Failed to create structure directory: $destinationPath. Error: $_" -Level "ERROR"
                        $errorFiles++
                        continue
                    }
                }
            }
        }
        
        # Move the file
        $destinationFile = Join-Path -Path $destinationPath -ChildPath $file.Name
        
        try {
            # Check if destination file already exists
            if (Test-Path -Path $destinationFile -PathType Leaf) {
                $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $fileExt = if ([string]::IsNullOrEmpty($file.Extension)) { "" } else { $file.Extension }
                $newFileName = "$fileName`_$(Get-Date -Format 'yyyyMMddHHmmss')$fileExt"
                $destinationFile = Join-Path -Path $destinationPath -ChildPath $newFileName
                Write-Log -Message "Destination file already exists. Renaming to: $newFileName" -Level "WARNING"
            }
            
            Move-Item -Path $file.FullName -Destination $destinationFile -Force
            Write-Log -Message "Moved file: $($file.FullName) -> $destinationFile" -Level "INFO"
            $movedFiles++
        }
        catch {
            Write-Log -Message "Failed to move file: $($file.FullName). Error: $_" -Level "ERROR"
            $errorFiles++
        }
    }
    
    Write-Progress -Activity "Moving Files" -Completed
    return @{
        Moved = $movedFiles
        Errors = $errorFiles
        Total = $totalFiles
    }
}

function Remove-EmptyDirectories {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $deletedDirs = 0
    
    try {
        # Get all subdirectories
        $directories = Get-ChildItem -Path $Path -Directory -Recurse | Sort-Object -Property FullName -Descending
        
        foreach ($dir in $directories) {
            # Check if directory is empty
            $items = Get-ChildItem -Path $dir.FullName -Force
            
            if ($null -eq $items -or $items.Count -eq 0) {
                try {
                    Remove-Item -Path $dir.FullName -Force
                    Write-Log -Message "Deleted empty directory: $($dir.FullName)" -Level "INFO"
                    $deletedDirs++
                }
                catch {
                    Write-Log -Message "Failed to delete empty directory: $($dir.FullName). Error: $_" -Level "ERROR"
                }
            }
        }
        
        # Finally, check the root directory
        $rootItems = Get-ChildItem -Path $Path -Force
        if ($null -eq $rootItems -or $rootItems.Count -eq 0) {
            try {
                Remove-Item -Path $Path -Force
                Write-Log -Message "Deleted empty root directory: $Path" -Level "INFO"
                $deletedDirs++
            }
            catch {
                Write-Log -Message "Failed to delete empty root directory: $Path. Error: $_" -Level "ERROR"
            }
        }
        
        return $deletedDirs
    }
    catch {
        Write-Log -Message "Error removing empty directories from $Path. Error: $_" -Level "ERROR"
        return 0
    }
}

# Main script execution
Write-Log -Message "Starting file organization process" -Level "INFO"
Write-Log -Message "Source: $SourcePath" -Level "INFO"
Write-Log -Message "Destination: $DestinationRoot" -Level "INFO"
Write-Log -Message "Options: $(if($DeleteEmptySource){'DeleteEmptySource '})$(if($PreserveStructure){'PreserveStructure '})$(if($Recurse){'Recurse '})$(if($Force){'Force'})" -Level "INFO"

# Validate paths
$sourceValid = Test-PathValidation -Path $SourcePath -Type "Source"
$destinationValid = Test-PathValidation -Path $DestinationRoot -Type "Destination"

if (-not ($sourceValid -and $destinationValid)) {
    Write-Log -Message "Path validation failed. Exiting script." -Level "ERROR"
    exit 1
}

# Get files to organize
$allFiles = Get-AllFiles -Path $SourcePath -Recurse:$Recurse

if ($allFiles.Count -eq 0) {
    Write-Log -Message "No files found to organize. Exiting script." -Level "WARNING"
    exit 0
}

# Confirm operation if moving a large number of files
if (-not (Confirm-LargeOperation -FileCount $allFiles.Count -Force:$Force)) {
    Write-Log -Message "Operation cancelled. Exiting script." -Level "INFO"
    exit 0
}

# Move files to extension folders
$sourceBasePath = (Resolve-Path $SourcePath).Path
$result = Move-FilesToExtensionFolders -Files $allFiles -DestinationRoot $DestinationRoot -PreserveStructure:$PreserveStructure -SourceBasePath $sourceBasePath

# Report results
Write-Log -Message "File organization completed: $($result.Moved) of $($result.Total) files moved successfully with $($result.Errors) errors" -Level $(if ($result.Errors -eq 0) { "INFO" } else { "WARNING" })

# Delete empty source directories if requested
if ($DeleteEmptySource) {
    Write-Log -Message "Removing empty directories from source..." -Level "INFO"
    $deletedDirs = Remove-EmptyDirectories -Path $SourcePath
    Write-Log -Message "Removed $deletedDirs empty directories" -Level "INFO"
}

Write-Log -Message "File organization process complete" -Level "INFO"
Write-Host "Log file created at: $LogFile" -ForegroundColor Cyan

