# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Clear-SdnWorkingDirectory {
    <#
    .SYNOPSIS
        Clears the contents of the directory specified
    .PARAMETER Path
        Specifies a path of the items being removed. Wildcard characters are permitted. If ommitted, defaults to (Get-WorkingDirectory).
    .PARAMETER Recurse
        Indicates that this cmdlet deletes the items in the specified locations and in all child items of the locations.
    .PARAMETER Force
        Forces the cmdlet to remove items that cannot otherwise be changed, such as hidden or read-only files or read-only aliases or variables.
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -Force -Recurse
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -Path 'C:\Temp\SDN1','C:\Temp\SDN2' -Force -Recurse
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Path = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    try {
        foreach ($object in $Path) {
            if ($object -inotlike "$($Global:SdnDiagnostics.Settings.FolderPathsAllowedForCleanup)*") {
                "{0} is not defined as an allowed path for cleanup. Skipping" -f $object | Trace-Output -Level:Warning
                continue
            }

            if (Test-Path -Path $object) {
                "Remove {0}" -f $object | Trace-Output -Level:Verbose
                Remove-Item -Path $object -Exclude $Global:SdnDiagnostics.Settings.FilesExcludedFromCleanup -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction Continue
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
