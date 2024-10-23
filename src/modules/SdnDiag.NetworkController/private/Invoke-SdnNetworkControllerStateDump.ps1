function Invoke-SdnNetworkControllerStateDump {
    <#
    .SYNOPSIS
        Executes a PUT operation against REST API endpoint for Network Controller to trigger a IMOS dump of Network Controller services.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ExecutionTimeout
        Specify the execution timeout (seconds) on how long you want to wait for operation to complete before cancelling operation. If omitted, defaults to 300 seconds.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 300,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    $putParams = @{
        Uri             = $null
        Method          = 'Put'
        Headers         = @{"Accept" = "application/json" }
        Content         = "application/json; charset=UTF-8"
        Body            = "{}"
        UseBasicParsing = $true
    }

    $confirmParams = @{
        UseBasicParsing = $true
        TimeoutInSec = $ExecutionTimeOut
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $confirmParams.Add('NcRestCertificate', $NcRestCertificate)
            $putParams.Add('Certificate', $NcRestCertificate)
        }
        'RestCredential' {
            $confirmParams.Add('NcRestCredential', $NcRestCredential)
            $putParams.Add('Credential', $NcRestCredential)
        }
    }

    [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceRef 'diagnostics/networkControllerState'
    $putParams.Uri = $uri

    try {
        # trigger IMOS dump
        "Generate In Memory Object State (IMOS) dump by executing PUT operation against {0}" -f $uri | Trace-Output
        $null = Invoke-WebRequestWithRetry @putParams

        # monitor until the provisionState for the object is not in 'Updating' state
        if (-NOT (Confirm-ProvisioningStateSucceeded -Uri $putParams.Uri @confirmParams)) {
            throw New-Object System.Exception("Unable to generate IMOS dump")
        }
        else {
            return $true
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $false
}
