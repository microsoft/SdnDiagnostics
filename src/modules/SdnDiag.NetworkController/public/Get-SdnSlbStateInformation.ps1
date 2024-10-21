function Get-SdnSlbStateInformation {
    <#
    .SYNOPSIS
        Generates an aggregated report of Virtual IPs (VIPs) in the environment and their current status as reported by Software Load Balancer and MUXes.
    .PARAMETER NcUri
         Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER VirtualIPAddress
        Specifies the VIP address to return information for. If omitted, returns all VIPs.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER Certificate
        Specifies the client certificate that is used for a secure web request. Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER ExecutionTimeout
        Specify the timeout duration to wait before automatically terminated. If omitted, defaults to 600 seconds.
    .PARAMETER PollingInterval
        Interval in which to query the state of the request to determine completion.
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com"
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -VirtualIPAddress 41.40.40.1
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -Credential (Get-Credential)
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -ExecutionTimeout 1200
    #>

    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Certificate')]
        [X509Certificate]$Certificate,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 5
    )

    $putParams = @{
        Uri             = $null
        Method          = 'Put'
        Headers         = @{"Accept" = "application/json" }
        Content         = "application/json; charset=UTF-8"
        Body            = "{}"
        UseBasicParsing = $true
    }

    $getParams = @{
        $uri            = $null
        UseBasicParsing = $true
    }

    if ($Certificate) {
        $putParams.Add('Certificate', $Certificate)
        $getParams.Add('Certificate', $Certificate)
    }
    else {
        $putParams.Add('Credential', $Credential)
        $getParams.Add('Credential', $Credential)
    }

    try {
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()

        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'SlbState'
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose
        $putParams.Uri = $uri

        $putResult = Invoke-WebRequestWithRetry @putParams

        $resultObject = ConvertFrom-Json $putResult.Content
        "Response received $($putResult.Content)" | Trace-Output -Level:Verbose
        [System.String]$operationURI = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'SlbStateResults' -OperationId $resultObject.properties.operationId
        $getParams.Uri = $operationURI

        while ($true) {
            if ($stopWatch.Elapsed.TotalSeconds -gt $ExecutionTimeOut) {
                $stopWatch.Stop()
                $msg = "Unable to get results for OperationId: {0}. Operation timed out" -f $operationId
                throw New-Object System.TimeoutException($msg)
            }

            Start-Sleep -Seconds $PollingInterval

            $stateResult = Invoke-WebRequestWithRetry @getParams
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

        # if a VIP address is specified, return only the details for that VIP
        # must do some processing to get into the raw data
        if ($VirtualIPAddress) {
            $tenantDetails = $stateResult.properties.output.datagroups | Where-object { $_.name -eq 'Tenant' }
            $vipDetails = $tenantDetails.dataSections.dataunits | Where-object { $_.name -eq $VirtualIPAddress.IPAddressToString }
            return $vipDetails.value
        }

        return $stateResult.properties.output
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
