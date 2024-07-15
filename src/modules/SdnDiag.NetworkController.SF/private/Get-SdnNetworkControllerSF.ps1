function Get-SdnNetworkControllerSF {
    <#
    .SYNOPSIS
        Gets network controller application settings from the network controller node leveraging Service Fabric.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerSF
    .EXAMPLE
        PS> Get-SdnNetworkControllerSF -NetworkController 'NC01' -Credential (Get-Credential)
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
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        Get-NetworkController
    }

    try {
        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                Confirm-IsNetworkController
                $result = Invoke-Command -ScriptBlock $networkControllerSB -ErrorAction Stop
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $networkControllerSB -Credential $Credential -ErrorAction Stop
            }
        }
        catch {
            $_ | Trace-Exception
            "Get-NetworkController failed: {0}" -f $_.Exception.Message | Trace-Output -Level:Warning
            $result = Get-SdnNetworkControllerInfoFromClusterManifest -NetworkController $NetworkController -Credential $Credential
        }

        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
