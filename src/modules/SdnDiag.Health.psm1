# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.FC.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.SF.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Health.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Health' -Scope 'Script' -Force -Value @{
    Cache = @{}
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################


##########################
#### ARG COMPLETERS ######
##########################

$argScriptBlock = @{
    Role = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult)
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Role | Sort-Object -Unique)
        }

        return $result.Role | Where-Object {$_.Role -like "*$wordToComplete*"} | Sort-Object
    }
    Name = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult).HealthValidation
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Name | Sort-Object -Unique)
        }

        return $result.Name | Where-Object {$_.Name -like "*$wordToComplete*"} | Sort-Object
    }
}

Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Role' -ScriptBlock $argScriptBlock.Role
Register-ArgumentCompleter -CommandName 'Get-SdnFabricInfrastructureResult' -ParameterName 'Name' -ScriptBlock $argScriptBlock.Name

##########################
####### FUNCTIONS ########
##########################

function New-SdnHealthTest {
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Name = (Get-PSCallStack)[0].Command
    )

    $object = [PSCustomObject]@{
        Name = $Name
        Result = 'PASS' # default to PASS. Allowed values are PASS, WARN, FAIL
        OccurrenceTime = [System.DateTime]::UtcNow
        Properties = @()
        Remediation = @()
    }

    return $object
}

function New-SdnRoleHealthReport {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Role
    )

    $object = [PSCustomObject]@{
        Role = $Role
        Result = 'PASS' # default to PASS. Allowed values are PASS, WARN, FAIL
        OccurrenceTime = [System.DateTime]::UtcNow
        HealthTest = @() # array of New-SdnHealthTest objects
    }

    return $object
}

function New-SdnFabricHealthReport {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Role
    )

    $object = [PSCustomObject]@{
        OccurrenceTime = [System.DateTime]::UtcNow
        Role = $Role
        Result = 'PASS' # default to PASS. Allowed values are PASS, WARN, FAIL
        RoleTest = @() # array of New-SdnRoleHealthReport objects
    }

    return $object
}


function Get-HealthData {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Property,

        [Parameter(Mandatory = $true)]
        [System.String]$Id
    )

    $results = $script:SdnDiagnostics_Health.Config[$Property]
    return ($results[$Id])
}

function Write-HealthValidationInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Role,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [String[]]$Remediation
    )

    $details = Get-HealthData -Property 'HealthValidations' -Id $Name

    $outputString = "[$Role] $Name"
    $outputString += "`r`n`r`n"
    $outputString += "--------------------------`r`n"
    $outputString += "Description:`t$($details.Description)`r`n"
    $outputString += "Impact:`t`t$($details.Impact)`r`n"

    if (-NOT [string]::IsNullOrEmpty($Remediation)) {
        $outputString += "Remediation:`r`n`t -`t$($Remediation -join "`r`n`t -`t")`r`n"
    }

    if (-NOT [string]::IsNullOrEmpty($details.PublicDocUrl)) {
        $outputString += "`r`n"
        $outputString += "Additional information can be found at $($details.PublicDocUrl).`r`n"
    }

    $outputString += "`r`n--------------------------`r`n"
    $outputString += "`r`n"

    $outputString | Write-Host -ForegroundColor Yellow
}

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

            $roleHealthReport = New-SdnFabricHealthReport -Role $object.ToString()
            $sdnFabricDetails = [PSCustomObject]@{
                ComputerName = $null
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
                NcUri = $sdnFabricDetails.NcUrl
            }
            $restApiParams += $restCredParam

            # before proceeding with tests, ensure that the computer objects we are testing against are running the latest version of SdnDiagnostics
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.ComputerName -Credential $Credential

            $params = @{
                ComputerName = $sdnFabricDetails.ComputerName
                Credential = $Credential
                ScriptBlock = $null
                ArgumentList = @($restApiParams)
            }

            switch ($object) {
                'Gateway' { $params.ScriptBlock = { param($boundParams) Debug-SdnGateway @boundParams } }
                'LoadBalancerMux' { $params.ScriptBlock = { param($boundParams) Debug-SdnLoadBalancerMux @boundParams } }
                'NetworkController' { $params.ScriptBlock = { param($boundParams) Debug-SdnNetworkController @boundParams } }
                'Server' { $params.ScriptBlock = { param($boundParams) Debug-SdnServer @boundParams } }
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

function Get-SdnFabricInfrastructureResult {
    <#
        .SYNOPSIS
            Returns the results that have been saved to cache as part of running Debug-SdnFabricInfrastructure.
        .PARAMETER Role
            The name of the SDN role that you want to return test results from within the cache.
        .PARAMETER Name
            The name of the test results you want to examine.
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureResult
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureResult -Role Server
        .EXAMPLE
            PS> Get-SdnFabricInfrastructureResult -Role Server -Name 'Test-ServiceState'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    $cacheResults = $script:SdnDiagnostics_Health.Cache

    if ($PSBoundParameters.ContainsKey('Role')) {
        if ($cacheResults) {
            $cacheResults = $cacheResults | Where-Object {$_.Role -eq $Role}
        }
    }

    if ($PSBoundParameters.ContainsKey('Name')) {
        if ($cacheResults) {
            $cacheResults = $cacheResults.HealthValidation | Where-Object {$_.Name -eq $Name}
        }
    }

    return $cacheResults
}

function Debug-SdnNetworkController {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    Confirm-IsNetworkController
    $healthReport = New-SdnRoleHealthReport -Role 'NetworkController'

    try {
        # execute tests for network controller, regardless of the cluster type
        $healthReport.HealthTest += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
        )

        # execute tests based on the cluster type
        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'FailoverCluster' {
                $healthReport.HealthTest += @(
                    Test-DiagnosticsCleanupTaskEnabled -TaskName 'FcDiagnostics'
                )
            }
            'ServiceFabric' {
                $config_sf = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
                [string[]]$services_sf = $config_sf.properties.services.Keys
                $healthReport.HealthTest += @(
                    Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
                    Test-ServiceState -ServiceName $services_sf
                    Test-ServiceFabricApplicationHealth
                    Test-ServiceFabricClusterHealth
                    Test-ServiceFabricNodeStatus
                )
            }
        }

        # enumerate all the tests performed so we can determine if any completed with WARN or FAIL
        # if any of the tests completed with WARN, we will set the aggregate result to WARN
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($test in $healthReport.HealthTest) {
            if ($test.Result -eq 'WARN') {
                $healthReport.Result = $test.Result
            }
            elseif ($test.Result -eq 'FAIL') {
                $healthReport.Result = $test.Result
                break
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $healthReport.Result = 'FAIL'
    }

    return $healthReport
}

function Debug-SdnServer {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    Confirm-IsServer
    $config = Get-SdnModuleConfiguration -Role 'Server'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = New-SdnRoleHealthReport -Role 'Server'

    $ncRestParams = $PSBoundParameters
    $serverResource = Get-SdnResource @ncRestParams -Resource:Servers -ErrorAction Ignore

    try {
        # these tests are executed locally and have no dependencies on network controller rest API being available
        $healthReport.HealthTest += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-EncapOverhead
            Test-VfpDuplicateMacAddress
            Test-VMNetAdapterDuplicateMacAddress
            Test-ServiceState -ServiceName $services
            Test-ProviderNetwork
            Test-HostAgentConnectionStateToApiService
            Test-NetworkControllerApiNameResolution -NcUri $NcUri
        )

        # these tests have dependencies on network controller rest API being available
        # and will only be executed if we have been able to get the data from the network controller
        if ($serverResource) {
            $healthReport.HealthTest += @(
                Test-ServerHostId -InstanceId $serverResource.InstanceId
            )
        }

        # enumerate all the tests performed so we can determine if any completed with WARN or FAIL
        # if any of the tests completed with WARN, we will set the aggregate result to WARN
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($test in $healthReport.HealthTest) {
            if ($test.Result -eq 'WARN') {
                $healthReport.Result = $test.Result
            }
            elseif ($test.Result -eq 'FAIL') {
                $healthReport.Result = $test.Result
                break
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $healthReport.Result = 'FAIL'
    }

    return $healthReport
}

function Debug-SdnLoadBalancerMux {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    Confirm-IsLoadBalancerMux
    $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = New-SdnRoleHealthReport -Role 'LoadBalancerMux'

    $ncRestParams = $PSBoundParameters

    try {
        $muxCertRegKey = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux" -Name MuxCert
        $virtualServers = Get-SdnResource -Resource VirtualServers @ncRestParams
        $muxVirtualServer = $virtualServers | Where-Object {$_.properties.connections.managementaddresses -contains $muxCertRegKey.MuxCert}
        $loadBalancerMux = Get-SdnLoadBalancerMux @ncRestParams | Where-Object {$_.properties.virtualserver.resourceRef -ieq $muxVirtualServer.resourceRef}
        $peerRouters = $loadBalancerMux.properties.routerConfiguration.peerRouterConfigurations.routerIPAddress

        $testResults = @()
        $testResults += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-ServiceState -ServiceName $services
            Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
            Test-MuxConnectionStateToRouter -RouterIPAddress $peerRouters
            Test-MuxConnectionStateToSlbManager
            Test-NetworkControllerApiNameResolution -NcUri $NcUri
        )

        # we need to deserialize the test results from JSON back into SdnHealthTest so we can
        # add to SdnRoleHealthReport.HealthTest
        foreach ($test in $testResults) {
            $healthObject = [SdnHealthTest]::Deserialize($test)
            $healthReport.HealthTest += $healthObject
        }

        # enumerate all the tests performed so we can determine if any completed with WARN or FAIL
        # if any of the tests completed with WARN, we will set the aggregate result to WARN
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($test in $healthReport.HealthTest) {
            if ($test.Result -eq 'WARN') {
                $healthReport.Result = $test.Result
            }
            elseif ($test.Result -eq 'FAIL') {
                $healthReport.Result = $test.Result
                break
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $healthReport.Result = 'FAIL'
    }

    return $healthReport
}

function Debug-SdnGateway {
    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'RestCredential')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    Confirm-IsRasGateway
    $config = Get-SdnModuleConfiguration -Role 'Gateway'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = New-SdnRoleHealthReport -Role 'Gateway'

    $ncRestParams = @{
        NcUri = $NcUri
    }
    switch ($PSCmdlet.ParameterSetName) {
        'RestCredential' { $ncRestParams += @{ NcRestCredential = $NcRestCredential } }
        'RestCertificate' { $ncRestParams += @{ NcRestCertificate = $NcRestCertificate } }
    }

    try {
        $healthReport.HealthTest += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
            Test-ServiceState -ServiceName $services
        )

        # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
        # if any of the tests completed with Warning, we will set the aggregate result to Warning
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($test in $healthReport.HealthTest) {
            if ($test.Result -eq 'Warning') {
                $healthReport.Result = $test.Result
            }
            elseif ($test.Result -eq 'FAIL') {
                $healthReport.Result = $test.Result
                break
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $healthReport.Result = 'FAIL'
    }

    return ( $healthReport )
}

###################################
#### COMMON HEALTH VALIDATIONS ####
###################################

function Test-NonSelfSignedCertificateInTrustedRootStore {
    <#
    .SYNOPSIS
        Validate the Cert in Host's Root CA Store to detect if any Non Root Cert exist
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest
    $array = @()

    try {
        $rootCerts = Get-ChildItem -Path 'Cert:LocalMachine\Root' | Where-Object { $_.Issuer -ne $_.Subject }
        if ($rootCerts -or $rootCerts.Count -gt 0) {
            $sdnHealthTest.Result = 'FAIL'

            $rootCerts | ForEach-Object {
                $sdnHealthTest.Remediation += "Remove Certificate Thumbprint: $($_.Thumbprint) Subject: $($_.Subject)"
                $array += [PSCustomObject]@{
                    Thumbprint = $rootCert.Thumbprint
                    Subject    = $rootCert.Subject
                    Issuer     = $rootCert.Issuer
                }
            }
        }

        $sdnHealthTest.Properties = $array
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ServiceState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$ServiceName
    )

    $sdnHealthTest = New-SdnHealthTest
    $failureDetected = $false
    $array = @()

    try {
        foreach ($service in $ServiceName) {
            $result = Get-Service -Name $service -ErrorAction Ignore
            if ($result) {
                $array += [PSCustomObject]@{
                    ServiceName = $result.Name
                    Status      = $result.Status
                }

                if ($result.Status -ine 'Running') {
                    $failureDetected = $true
                    $sdnHealthTest.Remediation += "[$service] Start the service"
                }
            }
            else {
                $failureDetected = $true
            }
        }

        if ($failureDetected) {
            $sdnHealthTest.Result = 'FAIL'
        }

        if ($array) {
            $sdnHealthTest.Properties = $array
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-DiagnosticsCleanupTaskEnabled {
    <#
    .SYNOPSIS
        Ensures the scheduled task responsible for etl compression is enabled and running
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('FcDiagnostics', 'SDN Diagnostics Task')]
        [String]$TaskName
    )

    $sdnHealthTest = New-SdnHealthTest

    try {
        # check to see if logging is enabled on the registry key
        $isLoggingEnabled = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\NetworkController\Sdn\Diagnostics\Parameters" -Name 'IsLoggingEnabled' -ErrorAction Ignore

        # in this scenario, logging is currently disabled so scheduled task will not be available
        if ($isLoggingEnabled ) {
            try {
                $result = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                if ($result.State -ieq 'Disabled') {
                    $sdnHealthTest.Result = 'FAIL'
                    $sdnHealthTest.Remediation += "Use 'Repair-SdnDiagnosticsScheduledTask -TaskName $TaskName'."
                }
            }
            catch {
                $sdnHealthTest.Result = 'FAIL'
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-NetworkControllerApiNameResolution {
    <#
    .SYNOPSIS
        Validates that the Network Controller API is resolvable via DNS
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri
    )

    $sdnHealthTest = New-SdnHealthTest

    try {
        # check to see if the Uri is an IP address or a DNS name
        # if it is a DNS name, we need to ensure that it is resolvable
        # if it is an IP address, we can skip the DNS resolution check
        $isIpAddress = [System.Net.IPAddress]::TryParse($NcUri.Host, [ref]$null)
        if (-NOT $isIpAddress) {
            $dnsResult = Resolve-DnsName -Name $NcUri.Host -ErrorAction Ignore
            if ($null -eq $dnsResult) {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation += "Ensure that the DNS server(s) are reachable and DNS record exists."
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

###################################
#### SERVER HEALTH VALIDATIONS ####
###################################

function Test-EncapOverhead {
    <#
    .SYNOPSIS

    #>

    [CmdletBinding()]
    param ()

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthTest = New-SdnHealthTest

    try {
        $encapOverheadResults = Get-SdnNetAdapterEncapOverheadConfig
        if ($null -eq $encapOverheadResults) {
            $sdnHealthTest.Result = 'FAIL'
        }
        else {
            $encapOverheadResults | ForEach-Object {
                # if encapoverhead is not enabled, this is most commonly due to network adapter firmware or driver
                # recommendations are to update the firmware and driver to the latest version and make sure not using default inbox drivers
                if ($_.EncapOverheadEnabled -eq $false) {

                    # in this scenario, encapoverhead is disabled and we have the expected jumbo packet value
                    # packets will be allowed to traverse the network without being dropped after adding VXLAN/GRE headers
                    if ($_.JumboPacketValue -ge $jumboPacketExpectedValue) {
                        # will not do anything as configuring the jumbo packet is viable workaround if encapoverhead is not supported on the network adapter
                        # this is a PASS scenario
                    }

                    # in this scenario, encapoverhead is disabled and we do not have the expected jumbo packet value
                    # this will result in a failure on the test as it will result in packets being dropped if we exceed default MTU
                    if ($_.JumboPacketValue -lt $jumboPacketExpectedValue) {
                        $sdnHealthTest.Result = 'FAIL'
                        $sdnHealthTest.Remediation += "[$($_.NetAdapterInterfaceDescription)] Ensure the latest firmware and drivers are installed to support EncapOverhead. Configure JumboPacket to $jumboPacketExpectedValue if EncapOverhead is not supported."
                    }

                }

                # in this case, the encapoverhead is enabled but the value is less than the expected value
                if ($_.EncapOverheadEnabled -and $_.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                    # do nothing here at this time as may be expected if no workloads deployed to host
                }
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ServerHostId {
    <#
    .SYNOPSIS
        Queries the NCHostAgent HostID registry key value across the hypervisor hosts to ensure the HostID matches known InstanceID results from NC Servers API.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$InstanceId
    )

    $sdnHealthTest = New-SdnHealthTest
    $regkeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters'

    try {
        $regHostId = Get-ItemProperty -Path $regkeyPath -Name 'HostId' -ErrorAction Ignore
        if ($null -ieq $regHostId) {
            $sdnHealthTest.Result = 'FAIL'
        }
        else {
            if ($regHostId.HostId -inotin $InstanceId) {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation += "Update the HostId registry under $regkeyPath to match the correct InstanceId from the NC Servers API."
                $sdnHealthTest.Properties = [PSCustomObject]@{
                    HostID = $regHostId
                }
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-VfpDuplicateMacAddress {
    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $vfpPorts = Get-SdnVfpVmSwitchPort
        $duplicateObjects = $vfpPorts | Where-Object {$_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress} | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if ($duplicateObjects) {
            $sdnHealthTest.Result = 'FAIL'

            $duplicateObjects | ForEach-Object {
                $sdnHealthTest.Remediation += "[$($_.Name)] Resolve the duplicate MAC address issue with VFP."
            }
        }

        $sdnHealthTest.Properties = [PSCustomObject]@{
            DuplicateVfpPorts = $duplicateObjects.Group
            VfpPorts          = $vfpPorts
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-VMNetAdapterDuplicateMacAddress {
    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $vmNetAdapters = Get-SdnVMNetworkAdapter
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if ($duplicateObjects) {
            $sdnHealthTest.Result = 'FAIL'

            $duplicateObjects | ForEach-Object {
                $sdnHealthTest.Remediation += "[$($_.Name)] Resolve the duplicate MAC address issue with VMNetworkAdapters."
            }
        }

        $sdnHealthTest.Properties = [PSCustomObject]@{
            DuplicateVMNetworkAdapters = $duplicateObjects.Group
            VMNetworkAdapters          = $vmNetAdapters
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ProviderNetwork {
    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest
    $failureDetected = $false

    try {
        $addressMapping = Get-SdnOvsdbAddressMapping
        if (-NOT ($null -eq $addressMapping -or $addressMapping.Count -eq 0)) {
            $providerAddreses = $addressMapping.ProviderAddress | Sort-Object -Unique
            $connectivityResults = Test-SdnProviderAddressConnectivity -ProviderAddress $providerAddreses

            foreach ($destination in $connectivityResults) {
                $sourceIPAddress = $destination.SourceAddress[0]
                $destinationIPAddress = $destination.DestinationAddress[0]
                $jumboPacketResult = $destination | Where-Object {$_.BufferSize -gt 1472}
                $standardPacketResult = $destination | Where-Object {$_.BufferSize -le 1472}

                if ($destination.Status -ine 'Success') {
                    $remediationMsg = $null
                    $failureDetected = $true

                    # if both jumbo and standard icmp tests fails, indicates a failure in the physical network
                    if ($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Failure') {
                        $remediationMsg = "Unable to ping Provider Addresses. Ensure ICMP enabled on $sourceIPAddress and $destinationIPAddress. If issue persists, investigate physical network."
                        $sdnHealthTest.Remediation += $remediationMsg
                    }

                    # if standard MTU was success but jumbo MTU was failure, indication that jumbo packets or encap overhead has not been setup and configured
                    # either on the physical nic or within the physical switches between the provider addresses
                    if ($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Success') {
                        $remediationMsg = "Ensure the physical network between $sourceIPAddress and $destinationIPAddress are configured to support VXLAN or NVGRE encapsulated packets with minimum MTU of 1660."
                        $sdnHealthTest.Remediation += $remediationMsg
                    }
                }
            }
        }

        if ($failureDetected) {
            $sdnHealthTest.Result = 'FAIL'
        }
        if ($connectivityResults) {
            $sdnHealthTest.Properties = [PSCustomObject]@{
                PingResult = $connectivityResults
            }
            $sdnHealthTest.PropertyDepth = 5
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-HostAgentConnectionStateToApiService {
    [CmdletBinding()]
    param()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $tcpConnection = Get-NetTCPConnection -RemotePort 6640 -ErrorAction Ignore
        if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
            $sdnHealthTest.Result = 'FAIL'
        }

        if ($tcpConnection) {
            if ($tcpConnection.ConnectionState -ine 'Connected') {
                $serviceState = Get-Service -Name NCHostAgent -ErrorAction Stop
                if ($serviceState.Status -ine 'Running') {
                    $sdnHealthTest.Result = 'WARN'
                    $sdnHealthTest.Remediation += "Ensure the NCHostAgent service is running."
                }
                else {
                    $sdnHealthTest.Result = 'FAIL'
                    $sdnHealthTest.Remediation += "Ensure that Network Controller ApiService is healthy and operational. Investigate and fix TCP / TLS connectivity issues."
                }
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

###################################
###### NC HEALTH VALIDATIONS ######
###################################

function Test-ServiceFabricApplicationHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller application within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $applicationHealth = Get-SdnServiceFabricApplicationHealth -ErrorAction Stop
        if ($applicationHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthTest.Result = 'FAIL'
            $sdnHealthTest.Remediation += "Examine the Service Fabric Application Health for Network Controller to determine why the health is not OK."
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ServiceFabricClusterHealth {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller cluster within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $clusterHealth = Get-SdnServiceFabricClusterHealth -ErrorAction Stop
        if ($clusterHealth.AggregatedHealthState -ine 'Ok') {
            $sdnHealthTest.Result = 'FAIL'
            $sdnHealthTest.Remediation += "Examine the Service Fabric Cluster Health for Network Controller to determine why the health is not OK."
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ServiceFabricNodeStatus {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller nodes within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $ncNodes = Get-SdnServiceFabricNode -NodeName $env:COMPUTERNAME -ErrorAction Stop
        if ($null -eq $ncNodes) {
            $sdnHealthTest.Result = 'FAIL'
        }
        else {
            if ($ncNodes.NodeStatus -ine 'Up') {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation = 'Examine the Service Fabric Nodes for Network Controller to determine why the node is not Up.'
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

###################################
##### MUX HEALTH VALIDATIONS ######
###################################

function Test-MuxConnectionStateToRouter {
    <#
    SYNOPSIS
        Validates the TCP connectivity for BGP endpoint to the routers.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RouterIPAddress
    )

    $sdnHealthTest = New-SdnHealthTest

    try {
        foreach ($router in $RouterIPAddress) {
            $tcpConnection = Get-NetTCPConnection -RemotePort 179 -RemoteAddress $router -ErrorAction Ignore
            if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation += "Examine the TCP connectivity for router $router to determine why TCP connection is not established."
            }
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-MuxConnectionStateToSlbManager {
    <#
        SYNOPSIS
        Validates the TCP / TLS connectivity to the SlbManager service.
    #>

    [CmdletBinding()]
    param()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $tcpConnection = Get-NetTCPConnection -LocalPort 8560 -ErrorAction Ignore
        if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
            $sdnHealthTest.Result = 'FAIL'
            $sdnHealthTest.Remediation += "Move SlbManager service primary role to another node. Examine the TCP / TLS connectivity for the SlbManager service."
        }
    }
    catch {
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}
