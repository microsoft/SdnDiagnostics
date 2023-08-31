function Get-SdnVipConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VirtualIPAddress,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $slbManagerPrimary = Get-SdnServiceFabricReplica -ServiceTypeName 'SlbManagerService' -Primary -NetworkController $NetworkController -Credential $Credential -ErrorAction Stop
    if ($slbManagerPrimary) {
        $slbManagerPrimaryNodeName = $slbManagerPrimary.ReplicaAddress.Split(':')[0]
        $slbManager = Connect-SlbManager -SlbManagerPrimary $slbManagerPrimaryNodeName

        $vipConfig = $slbManager.GetVipConfiguration($VirtualIPAddress)
        return $vipConfig
    }
}
