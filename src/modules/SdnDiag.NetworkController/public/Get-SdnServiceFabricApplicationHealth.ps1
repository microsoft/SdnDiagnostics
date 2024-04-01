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
