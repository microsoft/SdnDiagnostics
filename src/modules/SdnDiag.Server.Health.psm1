# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module .\SdnDiag.Health.psm1
using module .\SdnDiag.HealthFault.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.psm1
Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1
Import-Module $PSScriptRoot\SdnDiag.HealthFault.psm1

##########################
#### CLASSES & ENUMS #####
##########################

##########################
####### FUNCTIONS ########
##########################

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

    $config = Get-SdnModuleConfiguration -Role 'Server'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = [SdnRoleHealthReport]@{
        Role = 'Server'
    }

    $ncRestParams = $PSBoundParameters
    $serverResource = Get-SdnResource @ncRestParams -Resource:Servers -ErrorAction Ignore

    try {
        # these tests are executed locally and have no dependencies on network controller rest API being available
        $healthReport.HealthValidation += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-EncapOverhead
            Test-VfpDuplicateMacAddress
            Test-VMNetAdapterDuplicateMacAddress
            Test-ServiceState -ServiceName $services
            Test-ProviderNetwork
        )

        # these tests have dependencies on network controller rest API being available
        # and will only be executed if we have been able to get the data from the network controller
        if ($serverResource) {
            $healthReport.HealthValidation += @(
                Test-ServerHostId -InstanceId $serverResource.InstanceId
            )
        }

        # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
        # if any of the tests completed with Warning, we will set the aggregate result to Warning
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($healthStatus in $healthReport.HealthValidation) {
            if ($healthStatus.Result -eq 'Warning') {
                $healthReport.Result = $healthStatus.Result
            }
            elseif ($healthStatus.Result -eq 'FAIL') {
                $healthReport.Result = $healthStatus.Result
                break
            }
        }

        return $healthReport
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-EncapOverhead {
    <#
    .SYNOPSIS

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool] $GenerateFault = $false
    )

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthObject = [SdnHealthTest]::new()
    [bool] $misconfigurationFound = $false
    [string[]] $misconfiguredNics = @()

    try {
        $encapOverheadResults = Get-SdnNetAdapterEncapOverheadConfig
        if ($null -eq $encapOverheadResults) {
            $sdnHealthObject.Result = 'FAIL'

            # skip generation of fault if we cannot determine status confidently
            return $sdnHealthObject
        }

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
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "[$($_.NetAdapterInterfaceDescription)] Ensure the latest firmware and drivers are installed to support EncapOverhead. Configure JumboPacket to $jumboPacketExpectedValue if EncapOverhead is not supported."

                    $misconfigurationFound = $true
                    $misconfiguredNics += $_.NetAdapterInterfaceDescription
                }
            }
            # in this case, the encapoverhead is enabled but the value is less than the expected value
            if ($_.EncapOverheadEnabled -and $_.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                # do nothing here at this time as may be expected if no workloads deployed to host
            }
        }
        
        if($GenerateFault) {
            $FAULTNAME = "InvalidEncapOverheadConfiguration"
            ##########################################################################################
            ## EncapOverhead Fault Template
            ##########################################################################################
            # $KeyFaultingObjectDescription    (SDN ID)    : [HostName]
            # $KeyFaultingObjectID             (ARC ID)    : [NetworkAdapterIfDescsCsv]
            # $KeyFaultingObjectType           (CODE)      : InvalidEncapOverheadConfiguration
            # $FaultingObjectLocation          (SOURCE)    : [HostName]
            # $FaultDescription                (MESSAGE)   : EncapOverhead is not enabled or configured correctly for <AdapterNames> on host <HostName>. 
            # $FaultActionRemediation          (ACTION)    : JumboPacket should be enabled & EncapOverhead must be configured to support SDN. Please check NetworkATC configuration for configuring optimal networking configuration.
            # *EncapOverhead Faults will be reported from each node 
            ##########################################################################################
            $sdnHealthFault = [SdnFaultInfo]::new()
            $sdnHealthFault.KeyFaultingObjectDescription = $env:COMPUTERNAME
            $sdnHealthFault.KeyFaultingObjectID = $misconfiguredNics -join ','
            $sdnHealthFault.KeyFaultingObjectType = $FAULTNAME
            $sdnHealthFault.FaultingObjectLocation = $env:COMPUTERNAME
            $sdnHealthFault.FaultDescription = "EncapOverhead is not enabled or configured correctly for $misconfiguredNics on host $env:COMPUTERNAME."
            $sdnHealthFault.FaultActionRemediation = "JumboPacket should be enabled & EncapOverhead must be configured to support SDN. Please check NetworkATC configuration for configuring optimal networking configuration."

            if($misconfigurationFound -eq $true) {
                CreateorUpdateFault -Fault $sdnHealthFault -Verbose
            } else {
                # clear all existing faults for host($FAULTNAME)
                # todo: validate multiple hosts reporting the same fault
                DeleteFaultBy -KeyFaultingObjectDescription $env:COMPUTERNAME -KeyFaultingObjectType $FAULTNAME -Verbose
            }
        }
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
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

    $sdnHealthObject = [SdnHealthTest]::new()
    $regkeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters'

    try {
        $regHostId = Get-ItemProperty -Path $regkeyPath -Name 'HostId' -ErrorAction Ignore
        if ($null -ieq $regHostId) {
            $sdnHealthObject.Result = 'FAIL'
            return $sdnHealthObject
        }

        if ($regHostId.HostId -inotin $InstanceId) {
            $sdnHealthObject.Result = 'FAIL'
            $sdnHealthObject.Remediation += "Update the HostId registry under $regkeyPath to match the correct InstanceId from the NC Servers API."
            $sdnHealthObject.Properties = [PSCustomObject]@{
                HostID = $regHostId
            }
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-VfpDuplicateMacAddress {
    [CmdletBinding()]
    param ()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $vfpPorts = Get-SdnVfpVmSwitchPort
        $duplicateObjects = $vfpPorts | Where-Object {$_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress} | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if ($duplicateObjects) {
            $sdnHealthObject.Result = 'FAIL'

            $duplicateObjects | ForEach-Object {
                $sdnHealthObject.Remediation += "[$($_.Name)] Resolve the duplicate MAC address issue with VFP."
            }
        }

        $sdnHealthObject.Properties = [PSCustomObject]@{
            DuplicateVfpPorts = $duplicateObjects.Group
            VfpPorts          = $vfpPorts
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-VMNetAdapterDuplicateMacAddress {
    [CmdletBinding()]
    param ()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $vmNetAdapters = Get-SdnVMNetworkAdapter
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if ($duplicateObjects) {
            $sdnHealthObject.Result = 'FAIL'

            $duplicateObjects | ForEach-Object {
                $sdnHealthObject.Remediation += "[$($_.Name)] Resolve the duplicate MAC address issue with VMNetworkAdapters."
            }
        }

        $sdnHealthObject.Properties = [PSCustomObject]@{
            DuplicateVMNetworkAdapters = $duplicateObjects.Group
            VMNetworkAdapters          = $vmNetAdapters
        }

        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ProviderNetwork {
    [CmdletBinding()]
    param ()

    $sdnHealthObject = [SdnHealthTest]::new()
    $failureDetected = $false

    try {
        $addressMapping = Get-SdnOvsdbAddressMapping
        if ($null -eq $addressMapping -or $addressMapping.Count -eq 0) {
            return $sdnHealthObject
        }

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
                    $sdnHealthObject.Remediation += $remediationMsg
                }

                # if standard MTU was success but jumbo MTU was failure, indication that jumbo packets or encap overhead has not been setup and configured
                # either on the physical nic or within the physical switches between the provider addresses
                if ($jumboPacketResult.Status -ieq 'Failure' -and $standardPacketResult.Status -ieq 'Success') {
                    $remediationMsg = "Ensure the physical network between $sourceIPAddress and $destinationIPAddress are configured to support VXLAN or NVGRE encapsulated packets with minimum MTU of 1660."
                    $sdnHealthObject.Remediation += $remediationMsg
                }
            }
        }

        if ($failureDetected) {
            $sdnHealthObject.Result = 'FAIL'
        }

        $sdnHealthObject.Properties = [PSCustomObject]@{
            PingResults = $connectivityResults
        }
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-ConfigurationState {
    [CmdletBinding()]
    param (
        [bool] $GenerateFault = $false,
        [string] $NcUri
    )

    if(-not $GenerateFault) {
        Write-Output "Skipping fault generation"
    }

    # servers
    $NcUri = "https://v-NC.v.masd.stbtest.microsoft.com"
    
    Import-Module NetworkController

    # generate faults for servers
    $servers = Get-NetworkControllerServer -ConnectionUri $NcUri 
    $faultSet = GetFaultFromConfigurationState -resources $servers
    ShowFaultSet -faults $faultSet
    UpdateFaultSet -successFaults $faultSet[0] -FailureFaults $faultSet[1]

    # generate faults for vnics
    $vnics = Get-NetworkControllerNetworkInterface -ConnectionUri $NcUri
    $faultSet = GetFaultFromConfigurationState -resources $vnics
    ShowFaultSet -faults $faultSet
    UpdateFaultSet -successFaults $faultSet[0] -FailureFaults $faultSet[1]
}


function GetFaultFromConfigurationState {
    param(
        [object[]] $resources
    )

    $resHash = @{}
    $healthFaults = @()
    # successful faults are just a stub holder for the resource 
    # these are not created, but used for clearing out any older unhealthy states
    # these have KeyFaultingObjectType set to string.empty
    $successFaults = @()
    
    foreach ($resource in $resources) {

        ##########################################################################################
        ## ServiceState Fault Template (ServerResource)
        ##########################################################################################
        # $KeyFaultingObjectDescription    (SDN ID)    : [ResourceIRef]
        # $KeyFaultingObjectID             (ARC ID)    : [ResourceMetadataID (if available) else ResourceRef]
        # $KeyFaultingObjectType           (CODE)      : "ConfgiStateCode" (if 2 more errors are found with same other properties will be concatanated)
        # $FaultingObjectLocation          (SOURCE)    : "Source (if keys of 2 errors collide they will be concatanated)"
        # $FaultDescription                (MESSAGE)   : "ConfigStateMessage (2 or more if errors collide)."
        # $FaultActionRemediation          (ACTION)    : "See <href> for more information on how to resolve this issue."
        # * Config state faults issued only from the primary Node
        ##########################################################################################

        
        if($null -ne $resource.Properties.ConfigurationState -and $null -ne $resource.Properties.ConfigurationState.DetailedInfo -and `
            $resource.Properties.ConfigurationState.DetailedInfo.Count -gt 0) {

            foreach($detailedInfo in $resource.Properties.ConfigurationState.DetailedInfo) {

                # supression check for some of the known configuration states
                if(IsConfigurationStateSkipped -Source $detailedInfo.Source -Message $detailedInfo.Message -Code $detailedInfo.Code) {
                    continue
                }
                
                # handle success cases
                if($detailedInfo.Code -eq "Success") {
                    $successFault = [SdnFaultInfo]::new()
                    $successFault.KeyFaultingObjectDescription = $resource.ResourceRef
                    $successFault.KeyFaultingObjectID = $resource.ResourceRef
                    $successFault.KeyFaultingObjectType = [string]::Empty
                    $successFault.FaultingObjectLocation = [string]::Empty
                    $successFault.FaultDescription = [string]::Empty
                    $successFaults += $successFault
                    continue
                }

                # find any existing overlapping fault
                $existingFault = $healthFaults | Where-Object {$_.KeyFaultingObjectDescription -eq $resource.ResourceRef -and `
                    $_.KeyFaultingObjectType -eq $detailedInfo.Code}
                    
                    if($null -ne $existingFault) {
                        
                        $existingFault.FaultDescription += ("; " + $detailedInfo.Message)
                        $existingFault.FaultingObjectLocation += ("; " + $detailedInfo.Source)
                        
                    } else {
                        
                        $healthFault = [SdnFaultInfo]::new()
                        $healthFault.KeyFaultingObjectDescription = $resource.ResourceRef
                        $healthFault.KeyFaultingObjectType = $detailedInfo.Code
                        $healthFault.FaultingObjectLocation = $detailedInfo.Source
                        $healthFault.FaultDescription += $detailedInfo.Message

                        # add resource metadata if available
                        if($null -ne $resource.Properties.ResourceMetadata) {
                            $healthFault.KeyFaultingObjectID = $resource.Properties.ResourceMetadata
                        } else {
                            $healthFault.KeyFaultingObjectID = $resource.ResourceRef
                        }

                    }
                    $healthFaults += $healthFault
            }
        } 
        
        # if configuration state is not available, we will clear out any existing faults
        if($healthFaults.Count -eq 0) {
            $successFault = [SdnFaultInfo]::new()
            $successFault.KeyFaultingObjectDescription = $resource.ResourceRef
            $successFault.KeyFaultingObjectType = [string]::Empty
            $successFault.FaultingObjectLocation = [string]::Empty
            $successFault.FaultDescription = [string]::Empty
            $successFault.KeyFaultingObjectID = $resource.ResourceRef
            $successFaults += $successFault
        }
    }
    @($successFaults, $healthFaults)
}

function IsConfigurationStateSkipped {
    param(
        [string] $Source,
        [string] $Message,
        [string] $Code
    )

    if($Source -eq "SoftwareLoadbalancerManager") {
        if($Code -eq "HostNotConnectedToController") {
            return $true
        }
    }

    $false
}