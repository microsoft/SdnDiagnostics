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
        $files = Get-Item -Path "$($config.properties.commonPaths.rasGatewayTraces)\*" -Include '*.log','*.etl' | Where-Object {$_.LastWriteTime -le (Get-Date).AddHours(-1)}
        if($files){
            "Cleaning up files from previous collections" | Trace-Output -Level:Verbose
            $files | Remove-Item -Force
        }

        # enable ras tracing
        $expression = Invoke-Expression -Command "netsh ras set tracing * enabled"
        if($expression -ilike "*Unable to start ETW*"){
            $msg = $expression[1]
            throw New-Object -TypeName System.Exception($msg)
        }
        else {
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Running'
                }
            )
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
