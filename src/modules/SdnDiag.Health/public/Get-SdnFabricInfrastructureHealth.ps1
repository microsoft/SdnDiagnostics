function Get-SdnFabricInfrastructureHealth {
    <#
        .SYNOPSIS
            Returns the results that have been saved to cache as part of running Debug-SdnFabricInfrastructure.
        .PARAMETER Name
            The name of the known issue test.
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureHealth
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureHealth -Name 'Test-NetworkControllerServiceState'
    #>


    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    try {
        $cacheResults = Get-SdnCache -Name 'FabricHealth'

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
