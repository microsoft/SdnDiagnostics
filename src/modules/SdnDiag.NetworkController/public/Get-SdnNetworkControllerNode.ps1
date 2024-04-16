function Get-SdnNetworkControllerNode {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller.
    .PARAMETER Name
        Specifies the friendly name of the node for the network controller. If not provided, settings are retrieved for all nodes in the deployment.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode
    .EXAMPLE
        PS> Get-SdnNetworkControllerNode -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$ServerNameOnly
    )

    if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
        $config = Get-SdnModuleConfiguration -Role 'NetworkController'
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
            return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
        }
    }

    $params = @{
        NetworkController = $NetworkController
        Credential        = $Credential
        ErrorAction       = 'Stop'
    }
    if ($Name) {
        $params.Add('Name', $Name)
    }

    $sb = {
        param([String]$arg0)

        # check if service fabric service is running otherwise this command will hang
        if ((Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
            throw "Service Fabric Service is not running on $NetworkController"
        }

        if ([string]::IsNullOrEmpty($arg0)) {
            Get-NetworkControllerNode -ErrorAction Stop
        }
        else {
            Get-NetworkControllerNode -Name $arg0 -ErrorAction Stop
        }
    }

    try {
        try {
            # Run the script block locally or remotely
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                $result = Invoke-Command -ScriptBlock $sb -ArgumentList @($Name) -ErrorAction Stop
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock $sb -ArgumentList @($Name) -ErrorAction Stop
            }

            # in this scenario if the results returned we will parse the objects returned and generate warning to user if node is not up
            # this property is only going to exist though if service fabric is healthy and underlying NC cmdlet can query node status
            $result | ForEach-Object {
                if ($_.Status -ine 'Up') {
                    "{0} is reporting status {1}" -f $_.Name, $_.Status | Trace-Output -Level:Warning
                }

                if (!($_.PSOBject.Properties.name -contains "NodeCertificateThumbprint")) {
                    $_ | Add-Member -MemberType NoteProperty -Name 'NodeCertificateThumbprint' -Value $_.NodeCertificate.Thumbprint
                }
            }
        }
        catch {
            "Get-NetworkControllerNode failed: {0}" -f $_.Exception.Message | Trace-Output -Level:Error
            $result = Get-NetworkControllerNodeInfoFromClusterManifest @params
        }

        if($ServerNameOnly){
            return [System.Array]$result.Server
        }
        else {
            return $result
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
