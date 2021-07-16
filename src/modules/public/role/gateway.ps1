function Enable-GatewayTracing {
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
        $files = Get-ChildItem -Path $config.properties.commonPaths.rasGatewayTraces -Include '*.log','*.etl'
        if($files){
            "Cleaning up files from previous collections" | Trace-Output
            $files | Remove-Item -Force
        }

        # enable tracing
        netsh ras set tracing * enabled
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

    try {
        # disable tracing
        netsh ras set tracing * disabled
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
