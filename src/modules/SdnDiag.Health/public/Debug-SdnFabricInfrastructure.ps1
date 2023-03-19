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

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $true, ParameterSetName = 'ComputerName')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Role')]
        [SdnDiag.Common.Helper.SdnRoles[]]$Role = ('Gateway','LoadBalancerMux','NetworkController','Server'),

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $script:SdnDiagnostics_Health.Cache = $null
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

        # if we opted to specify the ComputerName rather than Role, we need to determine which role
        # the computer names are associated with
        if ($PSCmdlet.ParameterSetName -ieq 'ComputerName') {
            $Role = @()
            $ComputerName | ForEach-Object {
                $computerRole = $_ | Get-SdnRole -EnvironmentInfo $environmentInfo
                if ($computerRole) {
                    $Role += $computerRole
                }
            }
        }

        $restApiParams.Add('NcUri', $environmentInfo.NcUrl)
        $resourceParams = $restApiParams
        $resourceParams.Add('Resource', $null)

        $Role = $Role | Sort-Object -Unique
        foreach ($object in $Role) {
            $config = Get-SdnModuleConfiguration -Role $object.ToString()
            [string[]]$services = $config.Properties.Services.Keys
            $svcStateParams = @{
                Credential = $Credential
                ComputerName = $null
                Name = $services
            }

            if ($ComputerName) {
                $svcStateParams.ComputerName = $ComputerName
            }
            else {
                $svcStateParams.ComputerName = $environmentInfo[$object.ToString()]
            }

            $resourceParams.Resource = $config.ResourceName

            switch ($object) {
                'Gateway' {
                    $objectArray += @{
                        Gateway = @(
                            Test-ResourceConfigurationState @resourceParams
                            Test-ServiceState @svcStateParams
                        )
                    }
                }
                'LoadBalancerMux' {
                    $objectArray += @{
                        LoadBalancerMux = @(
                            Test-ResourceConfigurationState @resourceParams
                            Test-ServiceState @svcStateParams
                        )
                    }
                }
                'NetworkController' {
                    $objectArray += @{
                        NetworkController = @(
                            Test-ServiceState @svcStateParams
                        )
                    }
                }
                'Server' {
                    $serverParams = @{
                        Credential = $Credential
                        ComputerName = $environmentInfo[$object.ToString()]
                    }

                    $objectArray += @{
                        Server = @(
                            Test-EncapOverhead @serverParams
                            Test-ProviderNetwork @serverParams
                            Test-ResourceConfigurationState @resourceParams
                            Test-ServiceState @svcStateParams
                        )
                    }
                }
            }
        }

        $script:SdnDiagnostics_Health.Cache = $objectArray

        "Results for fabric health have been saved to cache for further analysis. Use 'Get-SdnFabricInfrastructureResult' to examine the results." | Trace-Output
        return $script:SdnDiagnostics_Health.Cache
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
