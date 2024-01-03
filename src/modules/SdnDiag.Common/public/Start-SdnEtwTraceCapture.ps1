function Start-SdnEtwTraceCapture {
    <#
    .SYNOPSIS
        Start ETW Trace capture based on Role
    .PARAMETER Role
        The SDN Roles
    .PARAMETER Providers
        Allowed values are Default,Optional And All to control what are the providers needed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [System.String]$OutputDirectory = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"
    )

    # this is the default trace size that we will limit each etw trace session to
    $maxTraceSize = 1024

    try {
        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers

        # we want to calculate the max size on number of factors to ensure sufficient disk space is available
        $diskSpaceRequired = $maxTraceSize*($traceProvidersArray.Count)*1.5
        if (-NOT (Initialize-DataCollection -Role $Role -FilePath $OutputDirectory -MinimumMB $diskSpaceRequired)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Exception
            return
        }

        foreach ($traceProviders in $traceProvidersArray) {
            "Starting trace session {0}" -f $traceProviders.name | Trace-Output -Level:Verbose
            Start-EtwTraceSession -TraceName $traceProviders.name -TraceProviders $traceProviders.properties.providers -TraceFile "$OutputDirectory\$($traceProviders.name).etl" -MaxTraceSize $maxTraceSize
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
