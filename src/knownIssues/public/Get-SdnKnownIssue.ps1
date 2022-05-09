# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnKnownIssue {
    <#
        .SYNOPSIS
            Returns the results that have been saved to cache as part of running Test-SdnKnownISsue.
        .PARAMETER Name
            The name of the known issue test.
        .EXAMPLE
            PS> Get-SdnKnownIssue
        .EXAMPLE
            PS> Get-SdnKnownIssue -Name 'Test-SdnKiNetworkInterfacePlacement'
    #>

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
