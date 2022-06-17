# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnResource {
    <#
    .SYNOPSIS
        Invokes a web request to SDN API for the requested resource.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceRef
        The resource ref of the object you want to perform the operation against.
    .PARAMETER ResourceType
        The resource type you want to perform the operation against.
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnResource -ResourceType PublicIPAddresses
    .EXAMPLE
        PS> Get-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/publicIPAddresses/d9266251-a3ba-4ac5-859e-2c3a7c70352a"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'NoResourceRef')]
        [SdnApiResource]$ResourceType,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NoResourceRef')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NoResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        [System.String]$method = 'GET'

        if($PSBoundParameters.ContainsKey('ResourceRef')){
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceRef $ResourceRef
        }
        else {
            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ServiceName $ResourceType
        }

        "{0} {1}" -f $method, $uri | Trace-Output -Level:Verbose

        # gracefully handle System.Net.WebException responses such as 404 to throw warning
        # anything else we want to throw terminating exception and capture for debugging purposes
        try {
            if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
                $result = Invoke-RestMethod -Uri $uri -Method $method -UseBasicParsing -Credential $Credential -ErrorAction Stop
            }
            else {
                $result = Invoke-RestMethod -Uri $uri -Method $method -UseBasicParsing -UseDefaultCredentials -ErrorAction Stop
            }
        }
        catch [System.Net.WebException] {
            "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Write-Warning
            return $null
        }
        catch {
            throw $_
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
    catch {
        "{0}`nAbsoluteUri:{1}`n{2}" -f $_.Exception, $_.TargetObject.Address.AbsoluteUri, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
