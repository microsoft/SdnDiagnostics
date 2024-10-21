function Get-SdnResource {
    <#
    .SYNOPSIS
        Invokes a web request to SDN API for the requested resource.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceRef
        The resource ref of the object you want to perform the operation against.
    .PARAMETER Resource
        The resource type you want to perform the operation against.
    .PARAMETER ResourceId
        Specify the unique ID of the resource.
    .PARAMETER InstanceID
        Specify the unique Instance ID of the resource.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -Resource PublicIPAddresses
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -Resource PublicIPAddresses -ResourceId "d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [Parameter(Mandatory = $true, ParameterSetName = 'InstanceID')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [SdnApiResource]$Resource,

        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'InstanceID')]
        [System.String]$InstanceId,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [Parameter(Mandatory = $false, ParameterSetName = 'InstanceID')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.String]$CertificateThumbprint
    )

    $params = @{
        UseBasicParsing = $true
        ErrorAction     = 'Stop'
        Method          = 'Get'
    }

    if (-NOT [string]::IsNullOrEmpty($CertificateThumbprint)) {
        $params.Add('CertificateThumbprint', $CertificateThumbprint)
    }
    else {
        $params.Add('Credential', $Credential)
    }

    switch ($PSCmdlet.ParameterSetName) {
        'InstanceId' {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceName 'internalResourceInstances'
            [System.String]$uri = "{0}/{1}" -f $uri, $InstanceId.Trim()
        }
        'ResourceRef' {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceRef $ResourceRef
        }
        'Resource' {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceName $Resource

            if ($ResourceID) {
                [System.String]$uri = "{0}/{1}" -f $uri, $ResourceId.Trim()
            }
        }
    }

    "{0} {1}" -f $method, $uri | Trace-Output -Level:Verbose
    $params.Add('Uri', $uri)

    # gracefully handle System.Net.WebException responses such as 404 to throw warning
    # anything else we want to throw terminating exception and capture for debugging purposes
    try {
        $result = Invoke-RestMethodWithRetry @params
    }
    catch [System.Net.WebException] {
        if ($_.Exception.Response.StatusCode -eq 'NotFound') {

            # if the resource is iDNSServer configuration, we want to return null instead of throwing a warning
            # as this may be expected behavior if the iDNSServer is not configured
            if ($_.Exception.Response.ResponseUri.AbsoluteUri -ilike '*/idnsserver/configuration') {
                return $null
            }
            else {
                "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Write-Warning
                return $null
            }
        }
        else {
            throw $_
        }
    }

    # if multiple objects are returned, they will be nested under a property called value
    # so we want to do some manual work here to ensure we have a consistent behavior on data returned back
    if ($result.value) {
        return $result.value
    }

    # in some instances if the API returns empty object, we will see it saved as 'nextLink' which is a empty string property
    # we need to return null instead otherwise the empty string will cause calling functions to treat the value as it contains data
    elseif ($result.PSObject.Properties.Name -ieq "nextLink" -and $result.PSObject.Properties.Name.Count -eq 1) {
        return $null
    }

    return $result
}
