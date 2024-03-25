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
        [System.String[]]$NetworkController = $global:SdnDiagnostics.EnvironmentInfo.NetworkController,

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NetworkController) {
            Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock { Get-ServiceFabricApplicationHealth -ApplicationName $using:ApplicationName } -Credential $Credential
        }
        else {
            Invoke-SdnServiceFabricCommand -ScriptBlock { Get-ServiceFabricApplicationHealth -ApplicationName $using:ApplicationName } -Credential $Credential
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
