function Debug-SdnFabricInfrastructure {
    <#
    .SYNOPSIS
        Executes a series of fabric validation tests to validate the state and health of the underlying components within the SDN fabric.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Role
        The specific SDN role(s) to perform tests and validations for. If ommitted, defaults to all roles.
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

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [SdnDiag.Common.Helper.SdnRoles[]]$Role = ('Gateway','LoadBalancerMux','NetworkController','Server'),

        [Parameter(Mandatory = $true, ParameterSetName = 'ComputerName')]
        [System.String[]]$ComputerName,

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
    $aggregateHealthReport = @()

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

        $Role = $Role | Sort-Object -Unique
        foreach ($object in $Role) {
            "Processing tests for {0} role" -f $object.ToString() | Trace-Output
            $config = Get-SdnModuleConfiguration -Role $object.ToString()

            $roleHealthReport = [SdnFabricHealthReport]@{
                Role = $object.ToString()
            }

            $sdnFabricDetails = [SdnFabricEnvObject]@{
                NcUrl = $environmentInfo.NcUrl
                Role  = $config
                EnvironmentInfo = $environmentInfo
            }

            if ($ComputerName) {
                $sdnFabricDetails.ComputerName = $ComputerName
            }
            else {
                $sdnFabricDetails.ComputerName = $environmentInfo[$object.ToString()]
            }

            $restApiParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                NcRestCredential        = $NcRestCredential
            }

            $computerCredParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                Credential              = $Credential
            }

            $computerCredAndRestApiParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                NcRestCredential        = $NcRestCredential
                Credential              = $Credential
            }

            # before proceeding with tests, ensure that the computer objects we are testing against are running the latest version of SdnDiagnostics
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.ComputerName -Credential $Credential

            # perform the health validations for the appropriate roles that were specified directly
            # or determined via which ComputerNames were defined
            switch ($object) {
                'Gateway' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                    )
                }

                'LoadBalancerMux' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-MuxBgpConnectionState @computerCredAndRestApiParams
                        Test-SlbManagerConnectionToMux @computerCredAndRestApiParams
                    )
                }

                'NetworkController' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ServiceState @computerCredParams
                        Test-ServiceFabricPartitionDatabaseSize @computerCredParams
                        Test-ServiceFabricClusterHealth @computerCredParams
                        Test-ServiceFabricApplicationHealth @computerCredParams
                        Test-ServiceFabricNodeStatus @computerCredParams
                        Test-NetworkInterfaceAPIDuplicateMacAddress @restApiParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-NetworkControllerCertCredential @computerCredAndRestApiParams
                    )
                }

                'Server' {
                    $roleHealthReport.HealthValidation += @(
                        Test-EncapOverhead @computerCredParams
                        Test-ProviderNetwork @computerCredParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ServerHostId @computerCredAndRestApiParams
                        Test-VfpDuplicatePort @computerCredParams
                        Test-VMNetAdapterDuplicateMacAddress @computerCredParams
                        Test-HostRootStoreNonRootCert @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-NcHostAgentConnectionToApiService @computerCredAndRestApiParams
                    )
                }
            }

            # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
            # if any of the tests completed with Warning, we will set the aggregate result to Warning
            # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
            # we will skip tests with PASS, as that is the default value
            foreach ($healthStatus in $roleHealthReport.HealthValidation) {
                if ($healthStatus.Result -eq 'Warning') {
                    $roleHealthReport.Result = $healthStatus.Result
                }
                elseif ($healthStatus.Result -eq 'FAIL') {
                    $roleHealthReport.Result = $healthStatus.Result
                    break
                }
            }

            # add the individual role health report to the aggregate report
            $aggregateHealthReport += $roleHealthReport
        }

        if ($aggregateHealthReport) {

            # enumerate all the roles that were tested so we can determine if any completed with Warning or FAIL
            $aggregateHealthReport | ForEach-Object {
                if ($_.Result -ine 'PASS') {
                    $role = $_.Role

                    # enumerate all the individual role tests performed so we can determine if any completed that are not PASS
                    $_.HealthValidation | ForEach-Object {
                        if ($_.Result -ine 'PASS') {
                            # add the remediation steps to an array list so we can pass it to the Write-HealthValidationInfo function
                            # otherwise if we pass it directly, it will be treated as a single string
                            $remediationList = [System.Collections.ArrayList]::new()
                            $_.Remediation | ForEach-Object { [void]$remediationList.Add($_)}

                            Write-HealthValidationInfo -Role $([string]$role) -Name $_.Name -Remediation $remediationList
                        }
                    }
                }
            }

            # save the aggregate health report to cache so we can use it for further analysis
            $script:SdnDiagnostics_Health.Cache = $aggregateHealthReport

            "Results for fabric health have been saved to cache for further analysis. Use 'Get-SdnFabricInfrastructureResult' to examine the results." | Trace-Output
            return $script:SdnDiagnostics_Health.Cache
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
