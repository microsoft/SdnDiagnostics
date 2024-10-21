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
    .PARAMETER Certificate
        Specifies the client certificate that is used for a secure web request. Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -Credential (Get-Credential) -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -Credential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -Credential (Get-Credential) -ResourceRef 'Servers/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e'
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -Credential (Get-Credential) -ResourceId 'f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
    .EXAMPLE
        PS> Get-SdnServer -NcUri 'https://NC.FQDN' -Credential (Get-Credential) -ResourceRef 'Servers/f5e3b3e0-1b7a-4b9e-8b9e-5b5e3b3e0f5e' -ManagementAddressOnly
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
        [X509Certificate]$Certificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [switch]$ManagementAddressOnly
    )

    $params = @{
        NcUri = $NcUri
    }

    if ($Certificate) {
        $params.Add('Certificate', $Certificate)
    }
    else {
        $params.Add('Credential', $Credential)
    }

    switch ($PSCmdlet.ParameterSetName) {
        'ResourceId' {
            $params.Add('Resource', 'Servers')
            $params.Add('ResourceId', $ResourceId)
        }
        'ResourceRef' {
            $params.Add('ResourceRef', $ResourceRef)
        }
        default {
            $params.Add('Resource', 'Servers')
        }
    }

    try {
        $result = Get-SdnResource @params
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
