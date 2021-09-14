function Invoke-SdnNetworkControllerStateDump {
    <#
    .SYNOPSIS
        Executes a PUT operation against REST API endpoint for Network Controller to trigger a IMOS dump of Network Controller services.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    try {
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()
        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion 'v1' -ServiceName:NetworkControllerState

        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
            $null = Invoke-WebRequest -Headers @{"Accept" = "application/json" } `
                -Content "application/json; charset=UTF-8" `
                -Uri $uri `
                -Body "{}" `
                -Method PUT `
                -Credential $Credential `
                -UseBasicParsing
        }
        else {
            $null = Invoke-WebRequest -Headers @{"Accept" = "application/json" } `
                -Content "application/json; charset=UTF-8" `
                -Uri $uri `
                -Body "{}" `
                -Method PUT `
                -UseDefaultCredentials `
                -UseBasicParsing
        }

        # monitor until the provisionState for the object is not in 'Updating' state
        while ($true) {
            Start-Sleep -Seconds $PollingInterval
            if ($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut) {
                throw New-Object System.TimeoutException("Operation did not complete within the specified time limit")
            }

            $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:NetworkControllerState -Credential $Credential
            if ($result.properties.provisioningState -ine 'Updating') {
                break
            }
        }

        $stopWatch.Stop()
    
        if ($result.properties.provisioningState -ine 'Succeeded') {
            $msg = "Unable to get NetworkControllerState. ProvisioningState: {0}" -f $result.properties.provisioningState
            throw New-Object System.Exception($msg)
        }

        return $true
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
