function Get-SdnServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Gets health information for a Service Fabric cluster from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricClusterHealth -NetworkController 'NC01' -Credential (Get-Credential)
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

    $sb = {
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Get-ServiceFabricClusterHealth
    }

    try {
        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
