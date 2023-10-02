function Get-SdnSlbStateInformation {
    <#
    .SYNOPSIS
        Generates an aggregated report of Virtual IPs (VIPs) in the environment and their current status as reported by the MUXes.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the timeout duration to wait before automatically terminated. If omitted, defaults to 600 seconds.
    .PARAMETER PollingInterval
        Interval in which to query the state of the request to determine completion.
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com"
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -Credential (Get-Credential)
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -ExecutionTimeout 1200
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
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 5
    )

    try {
        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'SlbState'
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose

        $stopWatch = [system.diagnostics.stopwatch]::StartNew()

        $putResult = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $Credential -Body "{}" -UseBasicParsing `
        -Content "application/json; charset=UTF-8" -Headers @{"Accept" = "application/json"}

        $resultObject = ConvertFrom-Json $putResult.Content
        "Response received $($putResult.Content)" | Trace-Output -Level:Verbose
        [System.String]$operationURI = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'SlbStateResults' -OperationId $resultObject.properties.operationId

        while ($true) {
            if ($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut) {
                $msg = "Unable to get results for OperationId: {0}. Operation timed out" -f $operationId
                throw New-Object System.TimeoutException($msg)
            }

            Start-Sleep -Seconds $PollingInterval

            $stateResult = Invoke-WebRequestWithRetry -Uri $operationURI -UseBasicParsing -Credential $Credential
            $stateResult = $stateResult.Content | ConvertFrom-Json
            if ($stateResult.properties.provisioningState -ine 'Updating') {
                break
            }
        }

        $stopWatch.Stop()

        if ($stateResult.properties.provisioningState -ine 'Succeeded') {
            $msg = "Unable to get results for OperationId: {0}. {1}" -f $operationId, $stateResult.properties
            throw New-Object System.Exception($msg)
        }
        else {
            return $stateResult.properties.output
        }
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
