function Get-SdnVirtualServer {
    <#
    .SYNOPSIS
        Returns virtual server of a particular resource Id from network controller.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.

    .PARAMETER ResourceRef
        Specifies Resource Ref of virtual server.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [String]$ResourceRef,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementAddress,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $ResourceRef -Credential $Credential

        foreach ($obj in $result) {
            if ($obj.properties.provisioningState -ne 'Succeeded') {
                "{0} is reporting provisioningState: {1}" -f $obj.resourceId, $obj.properties.provisioningState | Trace-Output -Level:Warning
            }
        }

        if ($ManagementAddress) {
            $connections = (Get-ManagementAddress -ManagementAddress $result.properties.connections.managementAddresses)
            return $connections
        }
        else {
            return $result
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
