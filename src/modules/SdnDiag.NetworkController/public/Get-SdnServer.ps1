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

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceId')]
        [String]$ResourceId,

        [Parameter(Mandatory = $false, ParameterSetName = 'ResourceRef')]
        [String]$ResourceRef,

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
        Resource = 'Servers'
        Credential = $Credential
    }

    switch ($PSCmdlet.ParameterSetName()) {
        'ResourceId' {
            $params.Add('ResourceId', $ResourceId)
        }
        'ResourceRef' {
            $params.Add('ResourceRef', $ResourceRef)
        }
        default {
            # do nothing
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
                $managementAddress = @()
                foreach ($address in $result.properties.connections.managementAddresses) {
                    $managementAddress += $address
                }

                # there might be multiple connection endpoints to each node so we will want to only return the unique results
                # this does not handle if some duplicate connections are listed as IPAddress with another record saved as NetBIOS or FQDN
                # further processing may be required by the calling function to handle that
                return ($managementAddress | Sort-Object -Unique)
            }
            else{
                return $result
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
