function Stop-SdnEtwTraceCapture {
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
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"

    )

    try {
        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers

        foreach ($traceProviders in $traceProvidersArray) {
            Stop-EtwTraceSession -TraceName $traceProviders.name
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
