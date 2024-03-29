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
        [System.String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
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

        try {
            if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
                # check if service fabric service is running otherwise this command will hang
                if ((Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
                    throw "Service Fabric Service is not running on $NetworkController"
                }

                $result = Get-NetworkController
            }
            else {
                $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
                    # check if service fabric service is running otherwise this command will hang
                    if ((Get-Service -Name 'FabricHostSvc').Status -ine 'Running' ) {
                        throw "Service Fabric Service is not running on $NetworkController"
                    }

                    Get-NetworkController
                } -ErrorAction Stop
            }
        }
        catch {
            "Get-NetworkController failed: {0}" -f $_.Exception.Message | Trace-Output -Level:Error
            $result = Get-SdnNetworkControllerInfoFromClusterManifest -NetworkController $NetworkController -Credential $Credential
        }

        return $result
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
