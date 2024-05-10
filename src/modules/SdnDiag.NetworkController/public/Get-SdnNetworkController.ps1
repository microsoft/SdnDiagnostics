function Get-SdnNetworkController {
    <#
    .SYNOPSIS
        Gets network controller application settings.
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

    $networkControllerSB = {
        Get-NetworkController
    }

    try {
        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                Confirm-IsNetworkController
                $result = Invoke-Command -ScriptBlock $networkControllerSB
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $networkControllerSB -Credential $Credential
            }
        }
        catch {
            "Get-NetworkController failed with following exception: `n`t{0}`n" -f $_ | Trace-Output -Level:Error
            $result = Get-SdnNetworkControllerInfoFromClusterManifest -NetworkController $NetworkController -Credential $Credential
        }

        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
