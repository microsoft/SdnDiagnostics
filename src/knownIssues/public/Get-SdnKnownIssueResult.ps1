# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnKnownIssueResult {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $cacheResults = Get-SdnCache -Name 'KnownIssues'

        if ($PSBoundParameters.ContainsKey('Name')) {
            if ($cacheResults) {
                return $cacheResults | Where-Object {$_.Name -eq $Name}
            }
        }

        return $cacheResults
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
