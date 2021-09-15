function Get-TraceProviders {
    <#
    .SYNOPSIS
        Get ETW Trace Providers based on Role
    .PARAMETER Role
        The SDN Roles 
    .PARAMETER Providers
        Allowed values are Default,Optional And All to control what are the providers needed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default",

        [Parameter(Mandatory = $false)]
        [Switch]$AsString
    )

    try {
        $config = Get-SdnRoleConfiguration -Role $Role
        $traceProvidersArray = [System.Collections.ArrayList]::new()
        foreach ($traceProviders in $config.properties.etwTraceProviders) {
            switch ($Providers) {
                "Default" {
                    if ($traceProviders.isOptional -ne $true) {
                        [void]$traceProvidersArray.Add($traceProviders)
                    }
                }
                "Optional" {
                    if ($traceProviders.isOptional -eq $true) {
                        [void]$traceProvidersArray.Add($traceProviders)
                    }
                }
                "All" {
                    [void]$traceProvidersArray.Add($traceProviders)
                }
            }
        }

        # we want to be able to return string value back so it can then be passed to netsh trace command
        # enumerate the properties that have values to build a formatted string that netsh expects
        if ($PSBoundParameters.ContainsKey('AsString') -and $traceProvidersArray) {
            [string]$formattedString = $null
            foreach ($traceProvider in $traceProvidersArray) {
                foreach ($provider in $traceProvider.Providers) {
                    $formattedString += "$(Format-NetshTraceProviderAsString -Provider $provider -Level $traceProvider.level -Keywords $traceProvider.keywords) "
                }
            }

            return $formattedString.Trim()
        }

        return $traceProvidersArray
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
