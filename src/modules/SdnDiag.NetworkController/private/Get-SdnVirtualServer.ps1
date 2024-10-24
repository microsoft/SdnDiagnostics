function Get-SdnVirtualServer {
    <#
    .SYNOPSIS
        Returns virtual server of a particular resource Id from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER ResourceRef
        Specifies Resource Ref of virtual server.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    $restParams = @{
        NcUri = $NcUri
        ResourceRef = $ResourceRef
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $restParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $restParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        $result = Get-SdnResource @restParams

        foreach ($obj in $result) {
            if ($obj.properties.provisioningState -ne 'Succeeded') {
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if ($ManagementAddressOnly) {
            $connections = (Get-ManagementAddress -ManagementAddress $result.properties.connections.managementAddresses)
            return $connections
        }
        else {
            return $result
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
