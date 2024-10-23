function Get-SdnSlbStateInformation {
    <#
    .SYNOPSIS
        Generates an aggregated report of Virtual IPs (VIPs) in the environment and their current status as reported by Software Load Balancer and MUXes.
    .PARAMETER NcUri
         Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER VirtualIPAddress
        Specifies the VIP address to return information for. If omitted, returns all VIPs.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the timeout duration to wait before automatically terminated. If omitted, defaults to 600 seconds.
    .PARAMETER PollingInterval
        Interval in which to query the state of the request to determine completion.
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com"
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -VirtualIPAddress 41.40.40.1
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -NcRestCredential (Get-Credential)
    .EXAMPLE
        Get-SdnSlbStateInformation -NcUri "https://nc.contoso.com" -ExecutionTimeout 1200
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [IPAddress]$VirtualIPAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

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
        Uri             = $null
        UseBasicParsing = $true
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $putParams.Add('Certificate', $NcRestCertificate)
            $getParams.Add('Certificate', $NcRestCertificate)
        }
        'RestCredential' {
            $putParams.Add('Credential', $NcRestCredential)
            $getParams.Add('Credential', $NcRestCredential)
        }
    }

    try {
        $stopWatch = [system.diagnostics.stopwatch]::StartNew()

        [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceName 'SlbState'
        "Gathering SLB state information from {0}" -f $uri | Trace-Output -Level:Verbose
        $putParams.Uri = $uri

        $putResult = Invoke-WebRequestWithRetry @putParams

        $resultObject = ConvertFrom-Json $putResult.Content
        "Response received $($putResult.Content)" | Trace-Output -Level:Verbose
        [System.String]$operationURI = Get-SdnApiEndpoint -NcUri $NcUri -ResourceName 'SlbStateResults' -OperationId $resultObject.properties.operationId
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
