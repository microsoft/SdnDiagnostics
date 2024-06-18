function Get-SdnServiceFabricApplicationHealth {
    <#
    .SYNOPSIS
        Gets the health of a Service Fabric application from Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricApplicationHealth -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sb = {
        param([string]$param1)
        # check if service fabric service is running
        $serviceState = Get-Service -Name 'FabricHostSvc' -ErrorAction Stop
        if ($serviceState.Status -ne 'Running') {
            throw New-Object System.Exception("Service Fabric Service is currently not running.")
        }

        # The 3>$null 4>$null sends unwanted verbose and debug streams into the bit bucket
        $null = Connect-ServiceFabricCluster -TimeoutSec 15 3>$null 4>$null
        Get-ServiceFabricApplicationHealth -ApplicationName $param1
    }

    try {
        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock $sb -ArgumentList @($ApplicationName)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
