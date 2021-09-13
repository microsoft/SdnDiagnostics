# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Enable-RasGatewayTracing {
    <#
    .SYNOPSIS
        Enables netsh tracing for the RAS components. Files will be saved to C:\Windows\Tracing by default
    #>

    try {
        # ensure that the appropriate windows feature is installed and ensure module is imported
        $config = Get-SdnRoleConfiguration -Role:Gateway
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        # remove any previous or stale logs
        $files = Get-Item -Path "$($config.properties.commonPaths.rasGatewayTraces)\*" -Include '*.log','*.etl'
        if($files){
            "Cleaning up files from previous collections" | Trace-Output -Level:Verbose
            $files | Remove-Item -Force
        }

        # enable ras tracing
        netsh ras set tracing * enabled
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Disable-RasGatewayTracing {
    <#
    .SYNOPSIS
        Disable netsh tracing for the RAS components
    #>

    try {
        $config = Get-SdnRoleConfiguration -Role:Gateway
        
        # disable ras tracing and copy logs to the output directory
        netsh ras set tracing * disabled

        Start-Sleep -Seconds 5
        $files = Get-Item -Path "$($config.properties.commonPaths.rasGatewayTraces)\*" -Include '*.log','*.etl'
    
        if($files){
            return $files.FullName
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
