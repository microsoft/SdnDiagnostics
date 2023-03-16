function Debug-SdnFabricInfrastructure {
    <#
    .SYNOPSIS
        Executes a series of fabric validation tests to validate the state and health of the underlying components within the SDN fabric.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [SdnDiag.Common.Helper.SdnRoles[]]$Role = ('Gateway','LoadBalancerMux','NetworkController','Server')
    )

    $objectArray = @()
    $restApiParams = @{
        NcRestCredential = $NcRestCredential
    }

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnModuleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        $environmentInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        if($null -eq $environmentInfo){
            throw New-Object System.NullReferenceException("Unable to retrieve environment details")
        }

        $restApiParams.Add('NcUri', $environmentInfo.NcUrl)

        foreach ($object in $Role) {
            switch ($object) {
                'Gateway' {
                    $gwyParams = @{
                        Credential = $Credential
                        ComputerName = $environmentInfo.Gateway
                    }

                    $objectArray += @(
                        Test-GatewayConfigState @restApiParams
                        Test-GatewayServiceState @gwyParams
                    )
                }
                'LoadBalancerMux' {
                    $lbmParams = @{
                        Credential = $Credential
                        ComputerName = $environmentInfo.LoadBalancerMux
                    }

                    $objectArray += @(
                        Test-LoadBalancerMuxConfigState @restApiParams
                        Test-LoadBalancerMuxServiceState @lbmParams
                    )
                }
                'NetworkController' {
                    $ncParams = @{
                        Credential = $Credential
                        ComputerName = $environmentInfo.NetworkController
                    }

                    $objectArray += @(
                        Test-NetworkControllerServiceState @ncParams
                    )
                }
                'Server' {
                    $serverParams = @{
                        Credential = $Credential
                        ComputerName = $environmentInfo.Server
                    }

                    $objectArray += @(
                        Test-EncapOverhead @serverParams
                        Test-ProviderNetwork @serverParams
                        Test-ServerConfigState @restApiParams
                        Test-ServerServiceState @serverParams
                    )
                }
            }
        }

        $Global:SdnDiagnostics.Cache.FabricHealth = $objectArray

        "Results for fabric health have been saved to cache for further analysis. Use 'Get-SdnFabricInfrastructureHealth' to examine the results." | Trace-Output
        return $Global:SdnDiagnostics.Cache.FabricHealth
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
