function Disable-RasGatewayTracing {
    <#
    .SYNOPSIS
        Disable netsh tracing for the RAS components
    #>

    try {      
        # since there has not been a time when this as returned an error, just invoking the expression and not doing any error handling
        Invoke-Expression -Command "netsh ras set tracing * disabled"

        Start-Sleep -Seconds 5
        $files = Get-Item -Path "$($config.properties.commonPaths.rasGatewayTraces)\*" -Include '*.log','*.etl'

        $object = New-Object -TypeName PSCustomObject -Property (
            [Ordered]@{
                Status = 'Stopped'
                Files = $files.FullName
            }
        )

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
