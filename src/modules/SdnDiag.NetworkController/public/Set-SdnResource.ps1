function Set-SdnResource {
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
    .PARAMETER ApiVersion
        The API version to use when invoking against the NC REST API endpoint.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Set-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -ResourceRef "/networkInterfaces/contoso-nic1" -Object $object
    .EXAMPLE
        PS> Set-SdnResource -NcUri "https://nc.$env:USERDNSDOMAIN" -Resource "networkInterfaces" -ResourceId "contoso-nic1" -Object $object
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [System.String]$ResourceRef,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [SdnApiResource]$Resource,

        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Resource')]
        [System.Object]$Object,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.String]$ApiVersion = $Global:SdnDiagnostics.EnvironmentInfo.RestApiVersion,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Resource')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $restParams = @{
        Uri      = $null
        Method  = 'Get'
        Credential = $Credential
        UseBasicParsing = $true
        ErrorAction = 'Stop'
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'ResourceRef' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceRef $ResourceRef
            }
            'Resource' {
                [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri.AbsoluteUri -ApiVersion $ApiVersion -ResourceName $Resource
                [System.String]$uri = "{0}/{1}" -f $uri, $ResourceId.Trim()
            }
        }

        $restParamsGet.Uri = $uri

        # perform a query against the resource to ensure it exists
        # as we only support operations against existing resources within this function
        try {
            if ($PSCmdlet.ShouldProcess($uri, "Invoke-RestMethod will be called to update the properties of resource")) {
                $null = Invoke-RestMethodWithRetry @restParams
            }
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Response.StatusCode -eq "NotFound") {
                throw New-Object System.NotSupportedException("Resource was not found. Ensure the resource exists before attempting to update it.")
            }
            else {
                throw $_
            }
        }
        catch {
            throw $_
        }

        $restParams.Method = 'Put'
        $restParams.Body = ($Object | ConvertTo-Json -Depth 100)

        $null = Invoke-RestMethodWithRetry @restParams -ErrorAction Stop
        $resourceState = Confirm-ProvisioningStateSucceeded -Uri $uri -Credential $Credential -TimeoutInSec 300 -UseBasicParsing -ErrorAction Stop
        return $resourceState
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
