function Get-SdnNetworkControllerNode {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER Name
        Specifies the friendly name of the node for the network controller. If not provided, settings are retrieved for all nodes in the deployment.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ServerNameOnly
    )

    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigurationType) {
        'FailoverCluster' {
            Get-SdnNetworkControllerFCNode @PSBoundParameters -ErrorAction Stop
        }
        'ServiceFabric' {
            Get-SdnNetworkControllerSFNode @PSBoundParameters -ErrorAction Stop
        }
    }
}
