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
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure
    .EXAMPLE
        PS> Debug-SdnFabricInfrastructure -NetworkController 'NC01' -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Role')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [ValidateSet('Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role = ('Gateway','LoadBalancerMux','NetworkController','Server'),

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
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Role')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ComputerName')]
        [X509Certificate]$NcRestCertificate
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $script:SdnDiagnostics_Health.Cache = $null
    $aggregateHealthReport = @()
    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        Confirm-IsNetworkController
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
    }

    $environmentInfo = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @restCredParam
    if($null -eq $environmentInfo){
        throw New-Object System.NullReferenceException("Unable to retrieve environment details")
    }

    try {
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
            "Processing tests for {0} role" -f $object.ToString() | Trace-Output -Level:Verbose
            $config = Get-SdnModuleConfiguration -Role $object.ToString()

            $roleHealthReport = [SdnFabricHealthReport]@{
                Role = $object.ToString()
            }

            $sdnFabricDetails = [SdnFabricEnvObject]@{
                NcUrl = $environmentInfo.NcUrl
                Role  = $config
                EnvironmentInfo = $environmentInfo
            }

            # check to see if we were provided a specific computer(s) to test against
            # otherwise we will want to pick up the node name(s) from the environment info
            if ($ComputerName) {
                $sdnFabricDetails.ComputerName = $ComputerName
            }
            else {
                # in scenarios where there are not mux(es) or gateway(s) then we need to gracefully handle this
                # and move to the next role for processing
                if ($null -ieq $environmentInfo[$object.ToString()]) {
                    "Unable to locate fabric nodes for {0}. Skipping health tests." -f $object.ToString() | Trace-Output -Level:Warning
                    continue
                }

                $sdnFabricDetails.ComputerName = $environmentInfo[$object.ToString()]
            }

            $restApiParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
            }
            $restApiParams += $restCredParam

            $computerCredParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                Credential              = $Credential
            }

            $computerCredAndRestApiParams = @{
                SdnEnvironmentObject    = $sdnFabricDetails
                Credential              = $Credential
            }
            $computerCredAndRestApiParams += $restCredParam

            # before proceeding with tests, ensure that the computer objects we are testing against are running the latest version of SdnDiagnostics
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.ComputerName -Credential $Credential

            # perform the health validations for the appropriate roles that were specified directly
            # or determined via which ComputerNames were defined
            switch ($object) {
                'Gateway' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceProvisioningState @restApiParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                    )
                }

                'LoadBalancerMux' {
                    $roleHealthReport.HealthValidation += @(
                        Test-ResourceProvisioningState @restApiParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-ServiceState @computerCredParams
                        Test-ScheduledTaskEnabled @computerCredParams
                        Test-MuxBgpConnectionState @computerCredAndRestApiParams
                        Test-SlbManagerConnectionToMux @computerCredAndRestApiParams
                    )
                }

                'NetworkController' {
                    $roleHealthReport.HealthValidation += @(
                        Test-NcUrlNameResolution @computerCredAndRestApiParams
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
                        Test-ResourceProvisioningState @restApiParams
                        Test-ResourceConfigurationState @restApiParams
                        Test-EncapOverhead @computerCredParams
                        Test-ProviderNetwork @computerCredParams
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
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
    finally {
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
        }
    }

    if ($script:SdnDiagnostics_Health.Cache) {
        "Results for fabric health have been saved to cache for further analysis. Use 'Get-SdnFabricInfrastructureResult' to examine the results." | Trace-Output
        return $script:SdnDiagnostics_Health.Cache
    }
}
