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
        [System.String[]]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.String]$NodeName

    )

    try {

        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnModuleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        if ($NodeName) {
            $sb = {
                Get-ServiceFabricNode -NodeName $using:NodeName
            }
        }
        else {
            $sb = {
                Get-ServiceFabricNode
            }
        }

        Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -ScriptBlock $sb -Credential $Credential
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
