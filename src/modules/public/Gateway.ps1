# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Enable-SdnGatewayTracing {
    <#
    .SYNOPSIS
        Enables netsh tracing for the RAS components. Files will be saved to C:\Windows\Tracing by default
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024
    )

    try {
        # ensure that the appropriate windows feature is installed and ensure module is imported
        $config = Get-SdnRoleConfiguration -Role:Gateway
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        $traceFileName = "{0}\{1}_{2}.etl" -f $OutputDirectory.FullName, $env:COMPUTERNAME, (Get-FormattedDateTimeUTC)

        # remove any previous or stale logs
        $files = Get-Item -Path "$($config.properties.commonPaths.rasGatewayTraces)\*" -Include '*.log','*.etl'
        if($files){
            "Cleaning up files from previous collections" | Trace-Output -Level:Verbose
            $files | Remove-Item -Force
        }

        # enable ras tracing
        netsh ras set tracing * enabled

        # enable netsh tracing with capture
        $traceProviderString = Get-TraceProviders -Role:Gateway -Providers Default -AsString
        Start-NetshTrace -TraceFile $traceFileName -TraceProviderString $traceProviderString -MaxTraceSize $MaxTraceSize -Report 'Disabled' -Capture 'Yes' -Overwrite 'Yes'
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Disable-SdnGatewayTracing {
    <#
    .SYNOPSIS
        Disable netsh tracing for the RAS components
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    try {
        $config = Get-SdnRoleConfiguration -Role:Gateway
        
        # disable ras tracing and copy logs to the output directory
        netsh ras set tracing * disabled

        Start-Sleep -Seconds 5

        $files = Get-Item -Path "$($config.properties.commonPaths.rasGatewayTraces)\*" -Include '*.log','*.etl'
        if($files){
            $files | Move-Item -Destination $OutputDirectory.FullName -Force
        }

        # disable the netsh trace
        Stop-NetshTrace
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
