# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Clear-SdnWorkingDirectory {
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
            if (Test-Path -Path $object) {
                "Remove {0}" -f $object | Trace-Output -Level:Verbose
                Remove-Item -Path $object -Exclude $Global:SdnDiagnostics.Settings.filesExcludedFromCleanup -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction Continue
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
