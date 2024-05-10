function Get-SdnServiceFabricNode {
    <#
    .SYNOPSIS
        Gets information for all nodes in a Service Fabric cluster for Network Controller.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NodeName
        Specifies the name of the Service Fabric node whose information is being returned. If not specified, the cmdlet will return information for all the nodes in the cluster.
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -NodeName 'Prefix-NC02'
    .EXAMPLE
        PS> Get-SdnServiceFabricNode -NodeName 'Prefix-NC01'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.String]$NodeName

    )

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }
    if ($NodeName) {
        $sfParams.Add('ArgumentList', @($NodeName))
    }

    $sb = {
        param([string]$param1)
        if ($param1) {
            Get-ServiceFabricNode -NodeName $param1
        }
        else {
            Get-ServiceFabricNode
        }
    }

    try {
        Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
