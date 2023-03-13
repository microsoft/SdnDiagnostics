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
        [SdnRoles]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"
    )

    try {
        $config = Get-SdnModuleConfiguration -Role $Role
        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers

        foreach ($traceProviders in $traceProvidersArray) {
            "Starting trace session {0}" -f $traceProviders.name | Trace-Output -Level:Verbose
            Start-EtwTraceSession -TraceName $traceProviders.name -TraceProviders $traceProviders.providers -TraceFile "$OutputDirectory\$($traceProviders.name).etl" -MaxTraceSize 1024
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
