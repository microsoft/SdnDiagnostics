# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnApiEndpoint {
    <#
    .SYNOPSIS
        Used to construct the URI endpoint for Network Controller NB API
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint. By default, reads from $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion
        which defaults to 'v1' unless explicity overwritten, or 'Get-SdnInfrastructureInfo' is called.
    .PARAMETER ResourceName
        Network Controller resource exposed via NB API interface of Network Controller, as defined under https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ncnbi/6dbabf43-0fcd-439c-81e2-7eb794f7c140.
    .PARAMETER OperationId
        Operation ID for diagnostics operation. This is optional and only used for certain resources.
    .PARAMETER ResourceRef
        The exact resource reference in format of /resourceName/{resourceId}/childObject/{resourceId}
    .EXAMPLE
        PS> Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName 'VirtualNetworks'
    .EXAMPLE
        PS> Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ResourceName '/virtualnetworks/contoso-vnet01'
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceName')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceName')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceName')]
        [System.String]$ResourceName,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceName')]
        [System.String]$OperationId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef
    )

    switch ($PSCmdlet.ParameterSetName) {
        'ResourceRef' {
            $apiEndpointProperties = $Global:SdnDiagnostics.Config.NetworkController.properties.apiResources | Where-Object {$_.uri -ilike "$ResourceRef*"}
            if ([string]::IsNullOrEmpty($apiEndpointProperties.minVersion)) {
                [System.String]$endpoint = "{0}/networking/{1}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ResourceRef.TrimStart('/')
            }
            else {
                [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $ResourceRef.TrimStart('/')
            }
        }
        'ResourceName' {
            $apiEndpointProperties = $Global:SdnDiagnostics.Config.NetworkController.properties.apiResources | Where-Object {$_.name -ieq $resourceName}

            if ([string]::IsNullOrEmpty($apiEndpointProperties.minVersion)) {
                [System.String]$endpoint = "{0}/networking/{1}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $apiEndpointProperties.uri
            }
            else {
                [System.String]$endpoint = "{0}/networking/{1}/{2}" -f $NcUri.AbsoluteUri.TrimEnd('/'), $ApiVersion, $apiEndpointProperties.uri
            }

            if ($apiEndpointProperties.operationId) {
                $endpoint = "{0}/{1}" -f $endpoint, $OperationId
            }
        }
    }

    "Endpoint: {0}" -f $endpoint | Trace-Output -Level:Verbose

    # query system supported configuration endpoints and throw warning if trying to query resource that does not exist on the system
	[int]$apiVersionInt = $ApiVersion.Replace('v','').Replace('V','')
	[int]$minVersionInt = $apiEndpointProperties.minVersion.Replace('v','').Replace('V','')

    if ($apiVersionInt -lt $minVersionInt) {
        "{0} requires minimum API version {1} while system is currently configured for {2}. Set Rest API version by running 'Get-SdnInfrastructureInfo'" `
        -f $apiEndpointProperties.uri, $apiEndpointProperties.minVersion, $ApiVersion | Trace-Output -Level:Warning
    }

    return $endpoint
}
