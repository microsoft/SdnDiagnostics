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

    $traceProvidersArray = @()

    try {
        $config = Get-SdnModuleConfiguration -Role $Role.ToString()
        foreach ($key in $config.properties.EtwTraceProviders.Keys) {
            $traceProvider = $config.properties.EtwTraceProviders[$key]
            switch ($Providers) {
                "Default" {
                    if ($traceProvider.isOptional -ne $true) {
                        $traceProvidersArray += [PSCustomObject]@{
                            Name = $key
                            Properties = $traceProvider
                        }
                    }
                }
                "Optional" {
                    if ($traceProvider.isOptional -eq $true) {
                        $traceProvidersArray += [PSCustomObject]@{
                            Name = $key
                            Properties = $traceProvider
                        }
                    }
                }
                "All" {
                    $traceProvidersArray += [PSCustomObject]@{
                        Name = $key
                        Properties = $traceProvider
                    }
                }
            }
        }

        # we want to be able to return string value back so it can then be passed to netsh trace command
        # enumerate the properties that have values to build a formatted string that netsh expects
        if ($PSBoundParameters.ContainsKey('AsString') -and $traceProvidersArray) {
            [string]$formattedString = $null
            foreach ($traceProvider in $traceProvidersArray) {
                foreach ($provider in $traceProvider.Properties.Providers) {
                    $formattedString += "$(Format-NetshTraceProviderAsString -Provider $provider -Level $traceProvider.level -Keywords $traceProvider.keywords) "
                }
            }

            return $formattedString.Trim()
        }

        return $traceProvidersArray
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
