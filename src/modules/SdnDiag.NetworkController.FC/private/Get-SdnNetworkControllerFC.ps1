function Get-SdnNetworkControllerFC {
    <#
    .SYNOPSIS
        Gets network controller application settings from the network controller node leveraging Failover Cluster.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerFC
    .EXAMPLE
        PS> Get-SdnNetworkControllerFC -NetworkController 'NC01' -Credential (Get-Credential)
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

    $networkControllerSB = {
        Get-NetworkControllerOnFailoverCluster
    }

    try {
        if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
            Confirm-IsNetworkController
            $result = Invoke-Command -ScriptBlock $networkControllerSB
        }
        else {
            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $networkControllerSB -Credential $Credential
        }

        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
