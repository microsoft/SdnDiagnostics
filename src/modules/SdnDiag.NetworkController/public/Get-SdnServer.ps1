function Get-SdnServer {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER ResourceId
        Specifies the unique identifier for the resource.
    .PARAMETER ResourceRef
        Specifies the resource reference for the resource.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef 'Servers/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -NcRestCredential (Get-Credential) -ResourceRef 'Servers/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceId')]
        [String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'ResourceRef')]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [switch]$ManagementAddressOnly
    )

    $ncRestParams = @{
        NcUri = $NcUri
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'ResourceId' {
                $result = Get-SdnResource @ncRestParams -Resource 'Servers' -ResourceId $ResourceId
            }
            'ResourceRef' {
                $result = Get-SdnResource @ncRestParams -ResourceRef $ResourceRef
            }
            default {
                $result = Get-SdnResource @ncRestParams -Resource 'Servers'
            }
        }

        if ($result) {
            foreach($obj in $result){
                if($obj.properties.provisioningState -ne 'Succeeded'){
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if($ManagementAddressOnly){
                $connections = (Get-ManagementAddress -ManagementAddress $result.properties.connections.managementAddresses)
                return $connections
            }
            else {
                return $result
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
