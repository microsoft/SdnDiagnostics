function Get-SdnNetworkController {
    <#
    .SYNOPSIS
        Gets network controller application settings from the network controller.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkController
    .EXAMPLE
        PS> Get-SdnNetworkController -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigurationType) {
        'FailoverCluster' {
            Get-SdnNetworkControllerFC @PSBoundParameters
        }
        'ServiceFabric' {
            Get-SdnNetworkControllerSF @PSBoundParameters
        }
    }
}
