function Get-SdnGateway {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER ManagementAddressOnly
        Optional parameter to only return back the Management Address value.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource:Gateways -Credential $Credential
        if ($result) {
            foreach($obj in $result){
                if($obj.properties.provisioningState -ne 'Succeeded'){
                    "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
                }
            }

            if($ManagementAddressOnly){
                $managementAddresses = [System.Collections.ArrayList]::new()
                foreach ($resource in $result) {
                    $virtualServerMgmtAddress = Get-SdnVirtualServer -NcUri $NcUri.AbsoluteUri -ResourceRef $resource.properties.virtualserver.ResourceRef -ManagementAddressOnly -Credential $Credential
                    [void]$managementAddresses.Add($virtualServerMgmtAddress)
                }
                return $managementAddresses
            }
            else{
                return $result
            }
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
