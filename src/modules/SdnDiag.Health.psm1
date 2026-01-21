# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Server.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.FC.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.SF.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Health.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Health' -Scope 'Script' -Force -Value @{
    Cache  = @{}
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

##########################
#### FAULT HELPERS   #####
##########################

# pInvoke definition for fault APIs
$signature = @'
[DllImport("hcihealthutils.dll", CharSet = CharSet.Unicode, SetLastError = false)]
public static extern int HciModifyFault(
    string entityType,
    string entityKey,
    string entityDescription,
    string entityLocation,
    string entityUniqueKey,
    uint action,
    string faultType,
    uint urgency,
    string title,
    string description,
    string actions,
    uint flag);

[DllImport("hcihealthutils.dll", CharSet = CharSet.Unicode, SetLastError = false)]
public static extern int HciModifyRelationship(
    string entityType,
    string entityKey,
    string entityDescription,
    string entityLocation,
    string entityUniqueKey,
    uint action,
    string parentEntityType,
    string parenetEntityKey,
    string parentEntityDescription,
    string parentEntityLocation,
    string parentEntityUniqueKey,
    string groupKey,
    uint urgency,
    uint relationshipType,
    uint flag);
'@

function LogWmiHealthFault {

    <#
        .SYNOPSIS
        Logs the WMI version of the health fault

        .PARAMETER fault
        The fault to log
    #>

    param(
        [object] $fault
    )
    Write-Verbose "    WmiFault:"
    Write-Verbose "    (FaultId) $($fault.FaultId)"
    Write-Verbose "    (FaultingObjectDescription) $($fault.FaultingObjectDescription)"
    Write-Verbose "    (FaultingObjectLocation) $($fault.FaultingObjectLocation)"
    Write-Verbose "    (FaultingObjectType) $($fault.FaultingObjectType)"
    Write-Verbose "    (FaultingObjectUniqueId) $($fault.FaultingObjectUniqueId)"
    Write-Verbose "    (FaultTime) $($fault.FaultTime)"
    Write-Verbose "    (FaultType) $($fault.FaultType)"
    Write-Verbose "    (Reason) $($fault.Reason)"
}

function DeleteFaultById {
    <#
        .SYNOPSIS
        Deletes a fault by its unique ID

        .PARAMETER faultUniqueID
        The unique ID of the fault to delete
    #>
    param(
        [string] $faultUniqueID
    )

    if ([string]::IsNullOrEmpty($faultUniqueID)) {
        throw "Empty faultID"
    }

    InitFaults
    Write-Verbose "DeleteFaultById $faultId"
    $fault = Get-HealthFault | Where-Object { $_.FaultId -eq $faultUniqueID }

    if ($null -eq $fault) {
        throw "Fault with ID $faultUniqueID not found"
    }
    else {
        LogWmiHealthFault -fault $fault
    }

    [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyFault( `
            $fault.FaultingObjectType, `
            $fault.FaultingObjectUniqueId, `
            "", `
            $fault.FaultingObjectUniqueId, `
            $fault.FaultingObjectUniqueId, `
            $HCI_MODIFY_FAULT_ACTION_REMOVE, `
            $fault.FaultType, `
            $HEALTH_URGENCY_UNHEALTHY, `
            "", `
            "", `
            "", `
            $HCI_MODIFY_FAULT_FLAG_NONE) | Out-Null
}

function InitFaults {
    <#
        .SYNOPSIS
        Initializes defaults and constants for fault handling
    #>

    [CmdletBinding()]
    param()

    Write-Verbose "InitFaults"
    if (-not ("Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils" -as [type])) {
        Add-Type -MemberDefinition $signature -Name "HciHealthUtils" -Namespace "Microsoft.NetworkHud.FunctionalTests.Module" | Out-Null
        Write-Verbose "Registered HCI fault utilities"
    }

    New-Variable -Name 'HCI_MODIFY_FAULT_ACTION_MODIFY' -Scope 'Script' -Force -Value 0
    New-Variable -Name 'HCI_MODIFY_FAULT_ACTION_REMOVE' -Scope 'Script' -Force -Value 1

    New-Variable -Name 'HCI_MODIFY_RELATIONSHIP_ACTION_MODIFY' -Scope 'Script' -Force -Value 0
    New-Variable -Name 'HCI_MODIFY_RELATIONSHIP_ACTION_REMOVE' -Scope 'Script' -Force -Value 1

    New-Variable -Name 'HEALTH_RELATIONSHIP_UNKNOWN' -Scope 'Script' -Force -Value 0
    New-Variable -Name 'HEALTH_RELATIONSHIP_COMPOSITION' -Scope 'Script' -Force -Value 1
    New-Variable -Name 'HEALTH_RELATIONSHIP_CONTAINMENT' -Scope 'Script' -Force -Value 2
    New-Variable -Name 'HEALTH_RELATIONSHIP_COLLECTION' -Scope 'Script' -Force -Value 3

    New-Variable -Name 'HEALTH_URGENCY_UNKNOWN' -Scope 'Script' -Force -Value 255
    New-Variable -Name 'HEALTH_URGENCY_HEALTHY' -Scope 'Script' -Force -Value 0
    New-Variable -Name 'HEALTH_URGENCY_WARNING' -Scope 'Script' -Force -Value 1
    New-Variable -Name 'HEALTH_URGENCY_UNHEALTHY' -Scope 'Script' -Force -Value 2

    New-Variable -Name 'HCI_MODIFY_FAULT_FLAG_NONE' -Scope 'Script' -Force -Value 0
    New-Variable -Name 'HCI_MODIFY_RELATIONSHIP_FLAG_NONE' -Scope 'Script' -Force -Value 0

    New-Variable -Name 'LOG_NAME' -Scope 'Script' -Force -Value 'SdnHealthService'
    New-Variable -Name 'LOG_CHANNEL' -Scope 'Script' -Force -Value 'Admin'
    New-Variable -Name 'LOG_SOURCE' -Scope 'Script' -Force -Value 'HealthService'

    [bool] $eventLogFound = $false
    try {
        $evtLog = Get-EventLog -LogName $script:LOG_NAME -Source $script:LOG_SOURCE -ErrorAction SilentlyContinue
        if ($null -ne $evtLog) {
            $eventLogFound = $true
        }
    }
    catch {
        #get-eventlog throws even on erroraction silentlycontinue
    }

    try {
        if ($eventLogFound -eq $false) {
            New-EventLog -LogName $script:LOG_NAME -Source $script:LOG_SOURCE -ErrorAction SilentlyContinue
        }
    }
    catch {
        #failure to create event log is non-fatal
    }
}

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

        return $result.Role | Where-Object { $_ -like "*$wordToComplete*" } | Sort-Object
    }
    Name = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult).RoleTest.HealthTest
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Name | Sort-Object -Unique)
        }

        return $result | Where-Object { $_.Name -like "*$wordToComplete*" } | Sort-Object
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
        Name           = $Name
        Result         = 'PASS' # default to PASS. Allowed values are PASS, WARN, FAIL
        OccurrenceTime = [System.DateTime]::UtcNow
        Properties     = @()
        Remediation    = @()
    }

    return $object
}

function New-SdnRoleHealthReport {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Role
    )

    $object = [PSCustomObject]@{
        Role           = $Role
        ComputerName   = $env:COMPUTERNAME
        Result         = 'PASS' # default to PASS. Allowed values are PASS, WARN, FAIL
        OccurrenceTime = [System.DateTime]::UtcNow
        HealthTest     = @() # array of New-SdnHealthTest objects
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
        Role           = $Role
        Result         = 'PASS' # default to PASS. Allowed values are PASS, WARN, FAIL
        RoleTest       = @() # array of New-SdnRoleHealthReport objects
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
        [String]$ComputerName,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [String[]]$Remediation
    )

    $details = Get-HealthData -Property 'HealthValidations' -Id $Name

    $outputString += "`r`n`r`n"
    $outputString += "--------------------------`r`n"
    $outputString += "[$ComputerName] $Name"
    $outputString += "`r`n`r`n"
    $outputString += "Description:`t$($details.Description)`r`n"
    $outputString += "Impact:`t`t$($details.Impact)`r`n"

    if (-NOT [string]::IsNullOrEmpty($Remediation)) {
        if ($Remediation -ieq [array]) {
            $outputString += "Remediation:`r`n`t- $($Remediation -join "`r`n`t - ")`r`n"
        }
        else {
            $outputString += "Remediation:`t$Remediation`r`n"
        }

    }

    if (-NOT [string]::IsNullOrEmpty($details.PublicDocUrl)) {
        $outputString += "`r`n"
        $outputString += "Additional information can be found at $($details.PublicDocUrl).`r`n"
    }

    $outputString += "`r`n--------------------------`r`n"

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
        [String[]]$Role = ('Gateway', 'LoadBalancerMux', 'NetworkController', 'Server'),

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
    if ($null -eq $environmentInfo) {
        throw New-Object System.NullReferenceException("Unable to retrieve environment details")
    }

    $ncRestParams = $restCredParam.Clone()
    $ncRestParams.Add('NcUri', $environmentInfo.NcUrl)
    $ncRestParamsResource = $ncRestParams.Clone()
    $ncRestParamsResource.Add('ResourceId', [string]::Empty)
    $ncRestParamsResource.Add('Resource', [string]::Empty)

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
                ComputerName    = $null
                NcUrl           = $environmentInfo.NcUrl
                Role            = $config
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

            # before proceeding with tests, ensure that the computer objects we are testing against are running the latest version of SdnDiagnostics
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.ComputerName -Credential $Credential

            $params = @{
                ComputerName = $sdnFabricDetails.ComputerName
                Credential   = $Credential
                ScriptBlock  = $null
            }

            switch ($object) {
                'Gateway' { $params.ScriptBlock = { Debug-SdnGateway } }
                'LoadBalancerMux' { $params.ScriptBlock = { Debug-SdnLoadBalancerMux } }
                'NetworkController' { $params.ScriptBlock = { Debug-SdnNetworkController } }
                'Server' { $params.ScriptBlock = { Debug-SdnServer } }
            }

            $healthReport = Invoke-SdnCommand @params

            # update the health report results with the configuration/provisioning state of the resources
            switch ($object) {
                'Gateway' {
                    $ncRestParamsResource.Resource = 'Gateways'
                    $sdnGateways = Get-SdnGateway @ncRestParams
                    foreach ($gateway in $sdnGateways){
                        $ncRestParamsResource.ResourceId = $gateway.ResourceId
                        $mgmtFqdnIpAddress = Get-SdnGateway @ncRestParams -ResourceId $gateway.ResourceId -ManagementAddressOnly
                        $netBiosFQDN = Get-ComputerNameFQDNandNetBIOS -ComputerName $mgmtFqdnIpAddress
                        foreach ($report in $healthReport) {
                            if ($report.ComputerName -ieq $netBiosFQDN.ComputerNameNetBIOS -or $report.ComputerName -ieq $netBiosFQDN.ComputerNameFQDN) {
                                $report.HealthTest += @(
                                    Test-SdnResourceProvisioningState @ncRestParamsResource
                                    Test-SdnResourceConfigurationState @ncRestParamsResource
                                )
                            }
                        }
                    }
                }
                'LoadBalancerMux' {
                    $ncRestParamsResource.Resource = 'LoadBalancerMuxes'
                    $sdnMuxes = Get-SdnLoadBalancerMux @ncRestParams
                    foreach ($mux in $sdnMuxes){
                        $ncRestParamsResource.ResourceId = $mux.ResourceId
                        $mgmtFqdnIpAddress = Get-SdnLoadBalancerMux @ncRestParams -ResourceId $mux.ResourceId -ManagementAddressOnly
                        $netBiosFQDN = Get-ComputerNameFQDNandNetBIOS -ComputerName $mgmtFqdnIpAddress
                        foreach ($report in $healthReport) {
                            if ($report.ComputerName -ieq $netBiosFQDN.ComputerNameNetBIOS -or $report.ComputerName -ieq $netBiosFQDN.ComputerNameFQDN) {
                                $report.HealthTest += @(
                                    Test-SdnResourceProvisioningState @ncRestParamsResource
                                    Test-SdnResourceConfigurationState @ncRestParamsResource
                                )
                            }
                        }
                    }
                }
                'NetworkController' {
                    # we do not need to do anything here for provisioning or configuration state.
                }
                'Server' {
                    $ncRestParamsResource.Resource = 'Servers'
                    $sdnServers = Get-SdnServer @ncRestParams
                    foreach ($server in $sdnServers){
                        $ncRestParamsResource.ResourceId = $server.ResourceId
                        $mgmtFqdnIpAddress = Get-SdnServer @ncRestParams -ResourceId $server.ResourceId -ManagementAddressOnly
                        $netBiosFQDN = Get-ComputerNameFQDNandNetBIOS -ComputerName $mgmtFqdnIpAddress
                        foreach ($report in $healthReport) {
                            if ($report.ComputerName -ieq $netBiosFQDN.ComputerNameNetBIOS -or $report.ComputerName -ieq $netBiosFQDN.ComputerNameFQDN) {
                                $report.HealthTest += @(
                                    Test-SdnResourceProvisioningState @ncRestParamsResource
                                    Test-SdnResourceConfigurationState @ncRestParamsResource
                                )
                            }
                        }
                    }
                }
            }

            # evaluate the results of the tests and determine if any completed with Warning or FAIL
            # if so, we will want to set the Result of the report to reflect this
            foreach ($test in $healthReport) {
                if ($test.Result -ieq 'WARN') {
                    $roleHealthReport.Result = 'WARN'
                }
                if ($test.Result -ieq 'FAIL') {
                    $roleHealthReport.Result = 'FAIL'
                    break
                }
            }

            $roleHealthReport.RoleTest += $healthReport
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
                    # enumerate all the individual role tests performed so we can determine if any completed that are not PASS
                    $_.RoleTest | ForEach-Object {
                        $c = $_.ComputerName
                        $_.HealthTest | ForEach-Object {

                            # enum only the health tests that failed
                            if ($_.Result -ine 'PASS') {
                                # add the remediation steps to an array list so we can pass it to the Write-HealthValidationInfo function
                                # otherwise if we pass it directly, it will be treated as a single string
                                $remediationList = [System.Collections.ArrayList]::new()
                                $_.Remediation | ForEach-Object { [void]$remediationList.Add($_) }

                                Write-HealthValidationInfo -ComputerName $c -Name $_.Name -Remediation $remediationList
                            }
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
            PS> Get-SdnFabricInfrastructureResult -Role Server -Name 'Test-SdnServiceState'
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
            $cacheResults = $cacheResults | Where-Object { $_.Role -eq $Role }
        }
    }

    if ($PSBoundParameters.ContainsKey('Name')) {
        if ($cacheResults) {
            $cacheResults = $cacheResults.HealthValidation | Where-Object { $_.Name -eq $Name }
        }
    }

    return $cacheResults
}

function Debug-SdnNetworkController {
    [CmdletBinding()]
    param ()

    Confirm-IsNetworkController
    $healthReport = New-SdnRoleHealthReport -Role 'NetworkController'

    try {
        # execute tests for network controller, regardless of the cluster type
        $healthReport.HealthTest += @(
            Test-SdnNonSelfSignedCertificateInTrustedRootStore
        )

        # execute tests based on the cluster type
        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'FailoverCluster' {
                $healthReport.HealthTest += @(
                    Test-SdnDiagnosticsCleanupTaskEnabled -TaskName 'FcDiagnostics'
                )
            }
            'ServiceFabric' {
                $config_sf = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
                [string[]]$services_sf = $config_sf.properties.services.Keys
                $healthReport.HealthTest += @(
                    Test-SdnDiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
                    Test-SdnNetworkControllerNodeRestInterface
                    Test-SdnServiceFabricApplicationHealth
                    Test-SdnServiceFabricClusterHealth
                    Test-SdnServiceFabricNodeStatus
                )

                foreach ($service in $services_sf) {
                    $healthReport.HealthTest += @(
                        Test-SdnServiceState -ServiceName $service
                    )
                }
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
    [CmdletBinding()]
    param ()

    Confirm-IsServer
    $config = Get-SdnModuleConfiguration -Role 'Server'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = New-SdnRoleHealthReport -Role 'Server'
    $peerCertName = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'PeerCertificateCName' -ErrorAction Stop

    try {
        # execute tests based on the cluster type
        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'ServiceFabric' {
                $healthReport.HealthTest += @(
                    Test-SdnDiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
                )
            }
            'FailoverCluster' {
                $healthReport.HealthTest += @(
                    Test-SdnDiagnosticsCleanupTaskEnabled -TaskName 'FcDiagnostics'
                )
            }
        }

        # these tests are executed locally and have no dependencies on network controller rest API being available
        $healthReport.HealthTest += @(
            Test-SdnNonSelfSignedCertificateInTrustedRootStore
            Test-SdnEncapOverhead
            Test-VfpDuplicateMacAddress
            Test-VMNetAdapterDuplicateMacAddress
            Test-SdnProviderNetwork
            Test-SdnHostAgentConnectionStateToApiService
            Test-SdnVfpEnabledVMSwitch
            Test-SdnVfpEnabledVMSwitchMultiple
            Test-SdnCertificateExpired
            Test-SdnCertificateMultiple
            Test-SdnNetworkControllerApiNameResolution -Endpoint $peerCertName.PeerCertificateCName
        )

        foreach ($service in $services) {
            $healthReport.HealthTest += @(
                Test-SdnServiceState -ServiceName $service
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
    [CmdletBinding()]
    param ()

    Confirm-IsLoadBalancerMux
    $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = New-SdnRoleHealthReport -Role 'LoadBalancerMux'

    try {
        $healthReport.HealthTest += @(
            Test-SdnNonSelfSignedCertificateInTrustedRootStore
            Test-SdnDiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
            Test-SdnMuxConnectionStateToSlbManager
            Test-SdnCertificateExpired
            Test-SdnCertificateMultiple
        )

        foreach ($service in $services) {
            $healthReport.HealthTest += @(
                Test-SdnServiceState -ServiceName $service
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

function Debug-SdnGateway {
    [CmdletBinding()]
    param ()

    Confirm-IsRasGateway
    $config = Get-SdnModuleConfiguration -Role 'Gateway'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = New-SdnRoleHealthReport -Role 'Gateway'

    try {
        $healthReport.HealthTest += @(
            Test-SdnNonSelfSignedCertificateInTrustedRootStore @PSBoundParameters
            Test-SdnDiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task' @PSBoundParameters
            Test-SdnAdapterPerformanceSetting @PSBoundParameters
        )

        foreach ($service in $services) {
            $healthReport.HealthTest += @(
                Test-SdnServiceState -ServiceName $service @PSBoundParameters
            )
        }

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

function Test-SdnNonSelfSignedCertificateInTrustedRootStore {
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
                "`t- Thumbprint: {0} Subject: {1} Issuer: {2} NotAfter: {3}" -f $_.Thumbprint, $_.Subject, $_.Issuer, $_.NotAfter
                $array += [PSCustomObject]@{
                    Thumbprint = $_.Thumbprint
                    Subject    = $_.Subject
                    Issuer     = $_.Issuer
                    NotAfter   = $_.NotAfter
                    NotBefore  = $_.NotBefore
                }
            }

            $sdnHealthTest.Remediation = "Move any non-self-signed certificated out of the Trusted Root Certification Authorities Certificate store and into the Intermediate Certification Authorities Certificate store:`r`n{0}." -f ($certDetails -join "`r`n")
        }

        $sdnHealthTest.Properties = $array
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnServiceState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$ServiceName
    )

    $sdnHealthTest = New-SdnHealthTest

    try {
        $result = Get-Service -Name $ServiceName -ErrorAction Ignore
        if ($result) {
            $sdnHealthTest.Properties += [PSCustomObject]@{
                ServiceName = $result.Name
                Status      = $result.Status
            }

            if ($result.Status -ine 'Running') {
                $sdnHealthTest.Remediation += "[$ServiceName] Start the service"
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnDiagnosticsCleanupTaskEnabled {
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
                $_ | Trace-Exception
                $sdnHealthTest.Result = 'FAIL'
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnNetworkControllerApiNameResolution {
    <#
    .SYNOPSIS
        Validates that the Network Controller API is resolvable via DNS
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Endpoint
    )

    $sdnHealthTest = New-SdnHealthTest
    $array = @()

    try {
        # check to see if the Uri is an IP address or a DNS name
        # if it is a DNS name, we need to ensure that it is resolvable
        # if it is an IP address, we can skip the DNS resolution check
        $isIpAddress = [System.Net.IPAddress]::TryParse($Endpoint, [ref]$null)
        if (-NOT $isIpAddress) {
            $dnsServers = (Get-DnsClientServerAddress).ServerAddresses | Sort-Object -Unique
            $dnsServers = $dnsServers | Where-Object {
                $_ -ne '::1' -and                     # Exclude loopback
                $_ -ne '::' -and                      # Exclude unspecified
                $_ -notmatch '^fe80:' -and            # Exclude link-local
                $_ -notmatch '^fec0:' -and            # Exclude deprecated site-local
                $_ -notmatch '^ff'
            }

            if ($dnsServers.Count -eq 0) {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation = "No DNS servers are configured on $env:COMPUTERNAME. Ensure that DNS server(s) are configured and reachable."
            }
            else {
                $dnsFailures = $dnsServers | ForEach-Object {
                    $dnsServer = $_
                    try {
                        $result = Resolve-DnsName -Name $Endpoint -Server $dnsServer -ErrorAction Stop
                        $array += $result
                    }
                    catch {
                        $_ | Trace-Exception
                        "`t- Investigate DNS resolution failure against DNS server {0} for name {1}" -f $dnsServer, $Endpoint
                    }
                }

                if ($dnsFailures) {
                    $sdnHealthTest.Result = 'FAIL'
                    $sdnHealthTest.Remediation += $dnsFailures
                }

                $sdnHealthTest.Properties = $array
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnCertificateExpired {

    $role = $Global:SdnDiagnostics.Config.Role
    $sdnHealthTest = New-SdnHealthTest

    try {
        foreach ($r in $role) {
            switch ($r) {
                'LoadBalancerMux' {
                    $certificate = Get-SdnMuxCertificate
                }
                'Server' {
                    $certificate = Get-SdnServerCertificate
                }
            }
        }

        if ($certificate) {
            $certificate = $certificate | Where-Object { $_.NotAfter -lt (Get-Date).ToUniversalTime() }
            if ($certificate -or $certificate.Count -gt 0) {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation = "Renew the certificate(s) used for SDN components."
                $certificate | ForEach-Object {
                    $sdnHealthTest.Properties += [PSCustomObject]@{
                        Thumbprint = $_.Thumbprint
                        Subject    = $_.Subject
                        NotAfter   = $_.NotAfter
                        NotBefore  = $_.NotBefore
                        Issuer     = $_.Issuer
                    }
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnCertificateMultiple {

    $role = $Global:SdnDiagnostics.Config.Role
    $sdnHealthTest = New-SdnHealthTest

    try {
        foreach ($r in $role) {
            switch ($r) {
                'LoadBalancerMux' {
                    $certificate = Get-SdnMuxCertificate -NetworkControllerOid
                }
                'Server' {
                    $certificate = Get-SdnServerCertificate -NetworkControllerOid
                }
            }
        }

        if ($null -ne $certificate -and $certificate.Count -gt 1) {
            # eliminate the most current certificate from the array as we do not want to flag that one
            $latestCert = $certificate | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
            $certificate = $certificate | Where-Object { $_.Thumbprint -ne $latestCert.Thumbprint }
            $certDetails = $certificate | ForEach-Object {
                "`t- Thumbprint: {0} Subject: {1} Issuer: {2} NotAfter: {3}" -f $_.Thumbprint, $_.Subject, $_.Issuer, $_.NotAfter
            }

            $sdnHealthTest.Result = 'WARN'
            $sdnHealthTest.Remediation = "Examine and cleanup the certificates if no longer needed:`r`n{0}" -f ($certDetails -join "`r`n")
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

###################################
#### SERVER HEALTH VALIDATIONS ####
###################################

function Test-SdnEncapOverhead {
    <#
    .SYNOPSIS
        Validate EncapOverhead configuration on the network adapter
    #>

    [CmdletBinding()]
    param ()

    Confirm-IsServer

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthTest = New-SdnHealthTest
    [string[]] $misconfiguredNics = @()

    try {
        # check to see if provider addresses are configured
        # if not, we know that workloads have not been deployed and we can skip this test
        # as none of the settings will be configured
        $providerAddreses = Get-SdnProviderAddress
        if ($null -ieq $providerAddreses -or $providerAddreses.Count -eq 0) {
            return $sdnHealthTest
        }

        $encapOverheadResults = Get-SdnNetAdapterEncapOverheadConfig
        if ($null -eq $encapOverheadResults) {
            # skip generation of fault if we cannot determine status confidently
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
                        $misconfiguredNics += $_.NetAdapterInterfaceDescription
                    }
                }

                # in this case, the encapoverhead is enabled but the value is less than the expected value
                if ($_.EncapOverheadEnabled -and $_.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                    $sdnHealthTest.Result = 'FAIL'
                    $sdnHealthTest.Remediation += "[$($_.NetAdapterInterfaceDescription)] Ensure the latest firmware and drivers are installed to support EncapOverhead. Configure JumboPacket to $jumboPacketExpectedValue if EncapOverhead is not supported."
                    $misconfiguredNics += $_.NetAdapterInterfaceDescription
                }
            }
        }

        if ($misconfiguredNics) {
            $sdnHealthTest.Properties = $misconfiguredNics
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ServerHostId {
    <#
    .SYNOPSIS
        Queries the NCHostAgent HostID registry key value ensure the HostID matches known InstanceID
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$InstanceId
    )

    Confirm-IsServer

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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-VfpDuplicateMacAddress {
    [CmdletBinding()]
    param ()

    Confirm-IsServer
    $sdnHealthTest = New-SdnHealthTest

    try {
        $vfpPorts = Get-SdnVfpVmSwitchPort
        $duplicateObjects = $vfpPorts | Where-Object { $_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress } | Group-Object -Property MacAddress | Where-Object { $_.Count -ge 2 }
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-VMNetAdapterDuplicateMacAddress {
    [CmdletBinding()]
    param ()

    Confirm-IsServer
    $sdnHealthTest = New-SdnHealthTest

    try {
        $vmNetAdapters = Get-SdnVMNetworkAdapter -All
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object { $_.Count -ge 2 }
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnProviderNetwork {

    <#
        .SYNOPSIS
            Validate the health of the provider network by pinging the provider addresses.
    #>

    [CmdletBinding()]
    param ()

    Confirm-IsServer
    $sdnHealthTest = New-SdnHealthTest
    $filteredAddressMappings = @()

    try {
        # get the provider addresses on the system
        # if there are no provider addresses, we can skip this test
        $localProviderAddress = Get-SdnProviderAddress
        if ($null -ieq $localProviderAddress -or $localProviderAddress.Count -eq 0) {
            return $sdnHealthTest
        }

        # since we are testing the provider network, we need to determine the subnet of the provider addresses
        # as the addressMappings may contain addresses that are not in the same subnet as the provider addresses
        # as we also get a similar type of PACA mapping for internal load balancer mappings
        $subnetMask = Get-SubnetMaskFromCidr -Cidr $localProviderAddress[0].PrefixLength
        $subnet = Get-NetworkSubnetFromIP -IPv4Address $localProviderAddress[0].Address -SubnetMask $subnetMask
        $cidr = "$subnet/$($localProviderAddress[0].PrefixLength)"

        $addressMapping = Get-SdnOvsdbAddressMapping
        if (-NOT ($null -eq $addressMapping -or $addressMapping.Count -eq 0)) {
            $providerAddreses = $addressMapping.ProviderAddress | Sort-Object -Unique
            foreach ($pAddress in $providerAddreses) {
                if (Confirm-IpAddressInCidrRange -IpAddress $pAddress -Cidr $cidr) {
                    $filteredAddressMappings += $pAddress
                }
            }

            $connectivityResults = Test-SdnProviderAddressConnectivity -ProviderAddress $filteredAddressMappings

            foreach ($destination in $connectivityResults) {
                $failureDetected = $false
                $sourceIPAddress = $destination.SourceAddress[0]
                $destinationIPAddress = $destination.DestinationAddress[0]
                $jumboPacketResult = $destination | Where-Object { $_.BufferSize -gt 1472 }
                $standardPacketResult = $destination | Where-Object { $_.BufferSize -le 1472 }

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
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnHostAgentConnectionStateToApiService {
    <#
        SYNOPSIS
            Validate the health of the Network Controller Host Agent connection to the Network Controller API Service.
    #>

    [CmdletBinding()]
    param()

    Confirm-IsServer
    $sdnHealthTest = New-SdnHealthTest

    try {
        $tcpConnection = Get-NetTCPConnection -RemotePort 6640 -ErrorAction Ignore
        if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
            $sdnHealthTest.Result = 'FAIL'
        }

        if ($tcpConnection) {
            if ($tcpConnection.State -ine 'Established') {
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnVfpEnabledVMSwitchMultiple {
    <#
        .SYNOPSIS
            Enumerates the VMSwitches on the system and validates that only one VMSwitch is configured with VFP.
    #>

    [CmdletBinding()]
    param()

    Confirm-IsServer
    $sdnHealthTest = New-SdnHealthTest

    try {
        # return back a list of VMSwitches that are configured with VFP
        # if there are no VMSwitches configured with VFP, this is a failure and it will be handled in the VfpEnabledVMSwitch test
        # if there is more than one VMSwitch configured with VFP, this is a failure as SDN does not support this configuration
        $vmSwitches = Get-SdnVMSwitch -VfpEnabled
        if ($vmSwitches.Count -gt 1) {
            $sdnHealthTest.Result = 'FAIL'
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnVfpEnabledVMSwitch {
    <#
        .SYNOPSIS
            Enumerates the VMSwitches on the system and validates that only one VMSwitch is configured with VFP.
    #>

    [CmdletBinding()]
    param()

    Confirm-IsServer
    $sdnHealthTest = New-SdnHealthTest

    try {
        # return back a list of VMSwitches that are configured with VFP
        # if there are no VMSwitches configured with VFP, this is a failure
        # if there is more than one VMSwitch configured with VFP, while this is a failure it will be handled in the VfpEnabledVMSwitchMultiple test
        $vmSwitches = Get-SdnVMSwitch -VfpEnabled
        if ($vmSwitches.Count -eq 0 -or $null -eq $vmSwitches) {
            $sdnHealthTest.Result = 'FAIL'
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

###################################
###### NC HEALTH VALIDATIONS ######
###################################

function Test-SdnServiceFabricApplicationHealth {
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnServiceFabricClusterHealth {
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnServiceFabricNodeStatus {
    <#
    .SYNOPSIS
        Validate the health of the Network Controller nodes within Service Fabric.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $ncNode = Get-SdnServiceFabricNode -NodeName $env:COMPUTERNAME -ErrorAction Stop
        if ($null -eq $ncNode) {
            $sdnHealthTest.Result = 'FAIL'
        }
        else {
            if ($ncNode.NodeStatus -ine 'Up' -or $ncNode.HealthState -ine 'Ok') {
                $sdnHealthTest.Result = 'FAIL'
                $sdnHealthTest.Remediation = 'Examine the Service Fabric Nodes for Network Controller to determine why the node is not Up or Healthy.'
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnResourceConfigurationState {
    <#
    .SYNOPSIS
        Validate that the configurationState of the resources.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Resource,

        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

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

    $sdnHealthTest = New-SdnHealthTest

    try {
        "Validating configuration state of {0} within {1}" -f $ResourceID, $Resource | Trace-Output -Level:Verbose
        $sdnResource = Get-SdnResource @PSBoundParameters -WarningAction SilentlyContinue

        # if we have a resource that is not in a success state, we will skip validation
        # as we do not expect configurationState to be accurate if provisioningState is not Success
        if ($sdnResource.properties.provisioningState -ine 'Succeeded') {
            return $sdnHealthTest
        }

        # examine the configuration state of the resource and display errors to the screen
        $errorMessages = @()
        switch ($sdnResource.properties.configurationState.Status) {
            'Warning' {
                # if we already have a failure, we will not change the result to warning
                if ($sdnHealthTest.Result -ne 'FAIL') {
                    $sdnHealthTest.Result = 'WARNING'
                }
            }

            'Failure' {
                $sdnHealthTest.Result = 'FAIL'
            }

            'InProgress' {
                # if we already have a failure, we will not change the result to warning
                if ($sdnHealthTest.Result -ne 'FAIL') {
                    $sdnHealthTest.Result = 'WARNING'
                }
            }

            'Uninitialized' {
                # in scenarios where state is redundant, we will not fail the test
                if ($sdnResource.properties.state -ieq 'Redundant') {
                    # do nothing
                }
                else {
                    # if we already have a failure, we will not change the result to warning
                    if ($sdnHealthTest.Result -ne 'FAIL') {
                        $sdnHealthTest.Result = 'WARNING'
                    }
                }
            }

            default {
                # do nothing
            }
        }

        if ($sdnResource.properties.configurationState.detailedInfo) {
            foreach ($detail in $sdnResource.properties.configurationState.detailedInfo) {
                switch ($detail.code) {
                    'Success' {
                        # do nothing
                    }

                    default {
                        $errorMessages += $detail.message
                        try {
                            $errorDetails = Get-HealthData -Property 'ConfigurationStateErrorCodes' -Id $detail.code
                            $sdnHealthTest.Remediation += "[{0}] {1}" -f $sdnResource.resourceRef, $errorDetails.Action
                        }
                        catch {
                            "Unable to locate remediation actions for {0}" -f $detail.code | Trace-Output -Level:Warning
                            $remediationString = "[{0}] Examine the configurationState property to determine why configuration failed." -f $sdnResource.resourceRef
                            $sdnHealthTest.Remediation += $remediationString
                        }
                    }
                }
            }
        }

        $details = [PSCustomObject]@{
            resourceRef        = $sdnResource.resourceRef
            configurationState = $sdnResource.properties.configurationState
        }

        $sdnHealthTest.Properties = $details
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnResourceProvisioningState {
    <#
    .SYNOPSIS
        Validate that the provisioningState of the resources.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Resource,

        [Parameter(Mandatory = $true)]
        [string]$ResourceId,

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

    $sdnHealthTest = New-SdnHealthTest

    try {
        "Validating provisioning state of {0} in {1}" -f $ResourceId, $Resource | Trace-Output -Level:Verbose

        $sdnResource = Get-SdnResource @PSBoundParameters -WarningAction SilentlyContinue
        switch ($sdnResource.properties.provisioningState) {
            'Failed' {
                $sdnHealthTest.Result = 'FAIL'
                $msg | Trace-Output -Level:Error

                $sdnHealthTest.Remediation += "[$($sdnResource.resourceRef)] Examine the Network Controller logs to determine why provisioning is $($sdnResource.properties.provisioningState)."
            }

            'Updating' {
                # if we already have a failure, we will not change the result to warning
                if ($sdnHealthTest.Result -ne 'FAIL') {
                    $sdnHealthTest.Result = 'WARNING'
                }

                # since we do not know what operations happened prior to this, we will log a warning
                # and ask the user to monitor the provisioningState
                $sdnHealthTest.Remediation += "[$($sdnResource.resourceRef)] is reporting $($sdnResource.properties.provisioningState). Monitor to ensure that provisioningState moves to Succeeded."
            }

            default {
                # DO NOTHING
            }
        }

        $details = [PSCustomObject]@{
            resourceRef       = $sdnResource.resourceRef
            provisioningState = $sdnResource.properties.provisioningState
        }

        $sdnHealthTest.Properties = $details
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnNetworkControllerNodeRestInterface {
    <#
        .SYNOPSIS
            Validates that a Network Adapter on the Network Controller node exists that matches the RestInterface name.
    #>

    [CmdletBinding()]
    param()

    Confirm-IsNetworkController
    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ieq 'FailoverCluster') {
        throw New-Object System.NotSupportedException("This function is not applicable to Failover Cluster Network Controller.")
    }

    $sdnHealthTest = New-SdnHealthTest
    try {
        $node = Get-SdnNetworkControllerNode -Name $env:COMPUTERNAME -ErrorAction Stop
        $netAdapter = Get-NetAdapter -Name $node.RestInterface -ErrorAction Ignore
        if ($null -eq $netAdapter) {
            $sdnHealthTest.Result = 'FAIL'
            $sdnHealthTest.Remediation += "Ensure that the Network Adapter $($node.RestInterface) exists. Leverage 'Set-NetworkControllerNode to update the -RestInterface if original adapter is not available."
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

###################################
##### MUX HEALTH VALIDATIONS ######
###################################


function Test-SdnMuxConnectionStateToRouter {
    <#
    SYNOPSIS
        Validates the TCP connectivity for BGP endpoint to the routers.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RouterIPAddress
    )

    Confirm-IsLoadBalancerMux
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-SdnMuxConnectionStateToSlbManager {
    <#
        SYNOPSIS
        Validates the TCP / TLS connectivity to the SlbManager service.
    #>

    [CmdletBinding()]
    param()

    Confirm-IsLoadBalancerMux
    $sdnHealthTest = New-SdnHealthTest

    try {
        $tcpConnection = Get-NetTCPConnection -LocalPort 8560 -ErrorAction Ignore | Where-Object {$_.LocalAddress -ine "0.0.0.0"}
        if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
            $sdnHealthTest.Result = 'FAIL'
            $sdnHealthTest.Remediation += "Move SlbManager service primary role to another node. Examine the TCP / TLS connectivity for the SlbManager service."
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Clear-SdnHealthFault {
    <#
        .SYNOPSIS
            Clears a specific health fault by its unique ID.
        .PARAMETER Id
            The unique ID of the health fault to clear.
        .EXAMPLE
            PS> Get-HealthFault | Format-Table -Property FaultId, FaultType, FaultingObjectUniqueId, FaultingObjectType
            PS> Clear-SdnHealthFault -Id "{79eba061-f88f-4205-bcfa-dc9196ae5338}"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )

    $currentHealthFaults = Get-HealthFault -ErrorAction Stop
    $fault = $currentHealthFaults | Where-Object { $_.FaultId -eq $Id }
    if ($null -ieq $fault) {
        throw New-Object System.ArgumentException("No health fault found with the specified ID: $Id")
    }

    DeleteFaultById -faultUniqueID $Id
    "Please allow 5 minutes for the fault to be cleared" | Trace-Output -Level:Information
}

###################################
### GATEWAY HEALTH VALIDATIONS ####
###################################

function Test-SdnAdapterPerformanceSetting {
    <#
        .SYNOPSIS
            Validates that the network adapters used for gateway traffic have optimal performance settings configured.
    #>

    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    $adaptersToRepair = @()
    try {
        $netAdapters = Get-NetAdapter | Where-Object {$_.Name -ieq 'Internal' -or $_.Name -ieq 'External'}
        foreach ($adapter in $netAdapters) {
            $forwardingOptimization = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName 'Forwarding Optimization' -ErrorAction Ignore
            if ($forwardingOptimization.DisplayValue -ine 'Enabled') {
                $adaptersToRepair += $adapter.Name
            }
        }

        if ($adaptersToRepair.Count -gt 0) {
            $sdnHealthTest.Result = 'WARNING'
            foreach ($adapter in $adaptersToRepair) {
                $sdnHealthTest.Remediation += "Use Invoke-SdnRemediationScript -ScriptName 'ConfigureForwardOptimization.ps1' -ArgumentList @{AdapterName='$adapter'; NoRestart=`$false}"
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
} 