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

    try {
        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential -ScriptBlock { Get-ServiceFabricClusterHealth }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
