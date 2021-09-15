function Get-SdnGateway {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddressOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:Gateways -Credential $Credential
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
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
