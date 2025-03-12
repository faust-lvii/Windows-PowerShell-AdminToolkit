<#
.SYNOPSIS
    Bulk file renaming utility with advanced features.

.DESCRIPTION
    The Rename-BulkFiles script provides comprehensive capabilities for renaming multiple files at once.
    It supports various renaming methods including pattern matching, regular expressions, sequential numbering,
    date-based naming, and case changes. The script includes preview functionality, undo capability,
    file filtering, progress tracking, logging, and error handling.

.PARAMETER Path
    The path containing files to be renamed. Defaults to the current directory.

.PARAMETER Filter
    Specifies a filter to apply to the files. Accepts wildcards (e.g., "*.txt").

.PARAMETER PatternMatch
    Enables pattern matching. Use with ReplacePattern and ReplaceWith parameters.

.PARAMETER ReplacePattern
    The pattern to be replaced in the filenames.

.PARAMETER ReplaceWith
    The replacement string for the pattern match.

.PARAMETER UseRegex
    Use regular expressions for pattern matching.

.PARAMETER AddNumbering
    Adds sequential numbering to filenames.

.PARAMETER StartNumber
    The starting number for sequential numbering. Defaults to 1.

.PARAMETER Padding
    The number of digits to use for padding numbers (e.g., 3 = 001, 002). Defaults to 2.

.PARAMETER NumberPosition
    Position to add the number: "Prefix", "Suffix", or specific position. Defaults to "Suffix".

.PARAMETER AddDate
    Adds a date to the filename.

.PARAMETER DateFormat
    The format of the date to add (e.g., "yyyy-MM-dd"). Defaults to "yyyy-MM-dd".

.PARAMETER DatePosition
    Position to add the date: "Prefix", "Suffix", or specific position. Defaults to "Prefix".

.PARAMETER ChangeCase
    Changes the case of filenames: "lower", "upper", "title".

.PARAMETER Preview
    Shows a preview of the changes without actually renaming files.

.PARAMETER Undo
    Undoes the last rename operation if a log file exists.

.PARAMETER Recursive
    Processes files in subdirectories recursively.

.PARAMETER LogFile
    The path to the log file. Defaults to "RenameLog.csv" in the current directory.

.EXAMPLE
    .\Rename-BulkFiles.ps1 -Path "C:\Photos" -Filter "*.jpg" -PatternMatch -ReplacePattern "IMG_" -ReplaceWith "Photo_"
    Renames all .jpg files in C:\Photos, replacing "IMG_" with "Photo_".

.EXAMPLE
    .\Rename-BulkFiles.ps1 -Path "C:\Documents" -AddNumbering -StartNumber 1 -Padding 3 -NumberPosition "Prefix"
    Adds sequential numbers as prefix to all files in C:\Documents (001_filename.ext, 002_filename.ext).

.EXAMPLE
    .\Rename-BulkFiles.ps1 -Path "C:\Logs" -AddDate -DateFormat "yyyy-MM-dd" -DatePosition "Prefix" -Preview
    Shows a preview of adding today's date as prefix to all files in C:\Logs.

.EXAMPLE
    .\Rename-BulkFiles.ps1 -Path "C:\Data" -ChangeCase "lower" -Recursive
    Converts all filenames to lowercase in C:\Data and its subdirectories.

.EXAMPLE
    .\Rename-BulkFiles.ps1 -Undo
    Undoes the last rename operation based on the log file.

.EXAMPLE
    .\Rename-BulkFiles.ps1 -Path "C:\Files" -UseRegex -ReplacePattern "^\d{3}_" -ReplaceWith "" -Preview
    Shows a preview of removing the first three digits and underscore from filenames.

.NOTES
    Author: PowerShell Administrator
    Version: 1.0
    Date: 2023-11-12
#>

[CmdletBinding(DefaultParameterSetName = 'Common')]
param (
    [Parameter(ParameterSetName = 'Common')]
    [Parameter(ParameterSetName = 'PatternMatch')]
    [Parameter(ParameterSetName = 'Numbering')]
    [Parameter(ParameterSetName = 'DateAdd')]
    [Parameter(ParameterSetName = 'CaseChange')]
    [string]$Path = (Get-Location).Path,

    [Parameter(ParameterSetName = 'Common')]
    [Parameter(ParameterSetName = 'PatternMatch')]
    [Parameter(ParameterSetName = 'Numbering')]
    [Parameter(ParameterSetName = 'DateAdd')]
    [Parameter(ParameterSetName = 'CaseChange')]
    [string]$Filter = "*",

    [Parameter(ParameterSetName = 'PatternMatch', Mandatory = $true)]
    [switch]$PatternMatch,

    [Parameter(ParameterSetName = 'PatternMatch', Mandatory = $true)]
    [string]$ReplacePattern,

    [Parameter(ParameterSetName = 'PatternMatch', Mandatory = $true)]
    [string]$ReplaceWith,

    [Parameter(ParameterSetName = 'PatternMatch')]
    [switch]$UseRegex,

    [Parameter(ParameterSetName = 'Numbering', Mandatory = $true)]
    [switch]$AddNumbering,

    [Parameter(ParameterSetName = 'Numbering')]
    [int]$StartNumber = 1,

    [Parameter(ParameterSetName = 'Numbering')]
    [int]$Padding = 2,

    [Parameter(ParameterSetName = 'Numbering')]
    [ValidateSet('Prefix', 'Suffix', 'Position')]
    [string]$NumberPosition = 'Suffix',

    [Parameter(ParameterSetName = 'Numbering')]
    [int]$InsertPosition = 0,

    [Parameter(ParameterSetName = 'DateAdd', Mandatory = $true)]
    [switch]$AddDate,

    [Parameter(ParameterSetName = 'DateAdd')]
    [string]$DateFormat = "yyyy-MM-dd",

    [Parameter(ParameterSetName = 'DateAdd')]
    [ValidateSet('Prefix', 'Suffix', 'Position')]
    [string]$DatePosition = 'Prefix',

    [Parameter(ParameterSetName = 'DateAdd')]
    [int]$DateInsertPosition = 0,

    [Parameter(ParameterSetName = 'CaseChange', Mandatory = $true)]
    [ValidateSet('lower', 'upper', 'title')]
    [string]$ChangeCase,

    [Parameter(ParameterSetName = 'Common')]
    [Parameter(ParameterSetName = 'PatternMatch')]
    [Parameter(ParameterSetName = 'Numbering')]
    [Parameter(ParameterSetName = 'DateAdd')]
    [Parameter(ParameterSetName = 'CaseChange')]
    [switch]$Preview,

    [Parameter(ParameterSetName = 'Undo', Mandatory = $true)]
    [switch]$Undo,

    [Parameter(ParameterSetName = 'Common')]
    [Parameter(ParameterSetName = 'PatternMatch')]
    [Parameter(ParameterSetName = 'Numbering')]
    [Parameter(ParameterSetName = 'DateAdd')]
    [Parameter(ParameterSetName = 'CaseChange')]
    [switch]$Recursive,

    [Parameter(ParameterSetName = 'Common')]
    [Parameter(ParameterSetName = 'PatternMatch')]
    [Parameter(ParameterSetName = 'Numbering')]
    [Parameter(ParameterSetName = 'DateAdd')]
    [Parameter(ParameterSetName = 'CaseChange')]
    [Parameter(ParameterSetName = 'Undo')]
    [string]$LogFile = "RenameLog.csv"
)

#region Functions

function Write-Log {
    param (
        [string]$Message,
        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$Level = 'Information'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$Level] $Message"
    
    switch ($Level) {
        'Information' { Write-Verbose -Message $logEntry }
        'Warning' { Write-Warning -Message $Message }
        'Error' { Write-Error -Message $Message }
    }
    
    $logEntry | Out-File -FilePath "$env:TEMP\RenameFiles_Log.txt" -Append
}

function Get-NewFileName {
    param (
        [string]$OriginalName,
        [string]$BaseName,
        [string]$Extension,
        [int]$FileNumber
    )

    $newName = $BaseName

    # Apply pattern matching
    if ($PatternMatch) {
        if ($UseRegex) {
            try {
                $newName = [regex]::Replace($newName, $ReplacePattern, $ReplaceWith)
            }
            catch {
                Write-Log -Message "Error in regex pattern: $_" -Level Error
                return $null
            }
        }
        else {
            $newName = $newName.Replace($ReplacePattern, $ReplaceWith)
        }
    }

    # Apply case changes
    if ($ChangeCase) {
        switch ($ChangeCase) {
            'lower' { $newName = $newName.ToLower() }
            'upper' { $newName = $newName.ToUpper() }
            'title' { 
                $textInfo = (Get-Culture).TextInfo
                $newName = $textInfo.ToTitleCase($newName.ToLower())
            }
        }
    }

    # Apply numbering
    if ($AddNumbering) {
        $number = "{0:D$Padding}" -f ($StartNumber + $FileNumber - 1)
        
        switch ($NumberPosition) {
            'Prefix' { $newName = "${number}_$newName" }
            'Suffix' { $newName = "$newName`_$number" }
            'Position' {
                if ($InsertPosition -gt 0 -and $InsertPosition -lt $newName.Length) {
                    $newName = $newName.Insert($InsertPosition, "_$number`_")
                }
                else {
                    $newName = "$newName`_$number"
                }
            }
        }
    }

    # Apply date
    if ($AddDate) {
        $date = Get-Date -Format $DateFormat
        
        switch ($DatePosition) {
            'Prefix' { $newName = "${date}_$newName" }
            'Suffix' { $newName = "$newName`_$date" }
            'Position' {
                if ($DateInsertPosition -gt 0 -and $DateInsertPosition -lt $newName.Length) {
                    $newName = $newName.Insert($DateInsertPosition, "_$date`_")
                }
                else {
                    $newName = "$newName`_$date"
                }
            }
        }
    }

    # Add the extension back
    $newName = "$newName$Extension"
    
    # Validate new name
    if (-not (Test-ValidFileName -FileName $newName)) {
        Write-Log -Message "Invalid file name generated: $newName" -Level Error
        return $null
    }
    
    return $newName
}

function Test-ValidFileName {
    param (
        [string]$FileName
    )
    
    # Check for invalid characters
    $invalidChars = [IO.Path]::GetInvalidFileNameChars()
    $invalidCharFound = $invalidChars | Where-Object { $FileName.Contains($_) }
    
    if ($invalidCharFound) {
        return $false
    }
    
    # Check for reserved Windows filenames like CON, PRN, AUX, etc.
    $reservedNames = @('CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9')
    $nameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($FileName)
    
    if ($reservedNames -contains $nameWithoutExt.ToUpper()) {
        return $false
    }
    
    # Check filename length
    if ($FileName.Length -gt 255) {
        return $false
    }
    
    return $true
}

function Write-RenameProgress {
    param (
        [int]$Current,
        [int]$Total,
        [string]$CurrentFile
    )
    
    $percent = ($Current / $Total) * 100
    $status = "Processing file $Current of $Total : $CurrentFile"
    
    Write-Progress -Activity "Renaming Files" -Status $status -PercentComplete $percent
}

function Get-FileList {
    param (
        [string]$Path,
        [string]$Filter,
        [switch]$Recursive
    )
    
    $params = @{
        Path = $Path
        Filter = $Filter
    }
    
    if ($Recursive) {
        $params.Add('Recurse', $true)
    }
    
    return Get-ChildItem @params -File
}

function Save-RenameOperations {
    param (
        [array]$Operations,
        [string]$LogFile
    )
    
    $operationsToExport = $Operations | ForEach-Object {
        [PSCustomObject]@{
            OriginalName = $_.OriginalName
            NewName = $_.NewName
            FullPath = $_.FullPath
            TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    
    $operationsToExport | Export-Csv -Path $LogFile -NoTypeInformation
    Write-Log -Message "Saved rename operations to $LogFile" -Level Information
}

function Invoke-UndoRenames {
    param (
        [string]$LogFile
    )
    
    if (-not (Test-Path -Path $LogFile)) {
        Write-Log -Message "Log file not found: $LogFile" -Level Error
        Write-Host "Error: Log file not found. Cannot undo operations." -ForegroundColor Red
        return
    }
    
    $operations = Import-Csv -Path $LogFile
    $total = $operations.Count
    $success = 0
    $failed = 0
    
    Write-Host "Starting undo operation for $total files..." -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $total; $i++) {
        $op = $operations[$i]
        $currentPath = Split-Path -Path $op.FullPath
        $newFullPath = Join-Path -Path $currentPath -ChildPath $op.NewName
        $originalFullPath = Join-Path -Path $currentPath -ChildPath $op.OriginalName
        
        Write-RenameProgress -Current ($i + 1) -Total $total -CurrentFile $op.NewName
        
        if (Test-Path -Path $newFullPath) {
            try {
                Rename-Item -Path $

