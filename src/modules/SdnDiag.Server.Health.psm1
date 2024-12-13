# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module .\SdnDiag.Health.psm1

Import-Module $PSScriptRoot\SdnDiag.Health.psm1
Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

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

    Confirm-IsServer
    $config = Get-SdnModuleConfiguration -Role 'Server'
    [string[]]$services = $config.properties.services.Keys
    $healthReport = [SdnRoleHealthReport]@{
        Role = 'Server'
    }

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

        # enumerate all the tests performed so we can determine if any completed with Warning or FAIL
        # if any of the tests completed with Warning, we will set the aggregate result to Warning
        # if any of the tests completed with FAIL, we will set the aggregate result to FAIL and then break out of the foreach loop
        # we will skip tests with PASS, as that is the default value
        foreach ($healthStatus in $healthReport.HealthTest) {
            if ($healthStatus.Result -eq 'Warning') {
                $healthReport.Result = $healthStatus.Result
            }
            elseif ($healthStatus.Result -eq 'FAIL') {
                $healthReport.Result = $healthStatus.Result
                break
            }
        }
    }
    catch {
        $healthReport.Result = 'FAIL'
    }

    return $healthReport
}

function Test-EncapOverhead {
    <#
    .SYNOPSIS

    #>

    [CmdletBinding()]
    param ()

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $encapOverheadResults = Get-SdnNetAdapterEncapOverheadConfig
        if ($null -eq $encapOverheadResults) {
            $sdnHealthObject.Result = 'FAIL'
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
                }

            }

            # in this case, the encapoverhead is enabled but the value is less than the expected value
            if ($_.EncapOverheadEnabled -and $_.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                # do nothing here at this time as may be expected if no workloads deployed to host
            }
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
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

    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
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
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
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
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
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
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}

function Test-HostAgentConnectionStateToApiService {
    [CmdletBinding()]
    param()

    $sdnHealthObject = [SdnHealthTest]::new()

    try {
        $tcpConnection = Get-NetTCPConnection -RemotePort 6640 -ErrorAction Ignore
        if ($null -eq $tcpConnection -or $tcpConnection.State -ine 'Established') {
            $sdnHealthObject.Result = 'FAIL'
        }

        if ($tcpConnection) {
            $sdnHealthObject.Properties = $tcpConnection

            if ($tcpConnection.ConnectionState -ine 'Connected') {
                $serviceState = Get-Service -Name NCHostAgent -ErrorAction Stop
                if ($serviceState.Status -ine 'Running') {
                    $sdnHealthObject.Result = 'WARNING'
                    $sdnHealthObject.Remediation += "Ensure the NCHostAgent service is running."
                }
                else {
                    $sdnHealthObject.Result = 'FAIL'
                    $sdnHealthObject.Remediation += "Ensure that Network Controller ApiService is healthy and operational. Investigate and fix TCP / TLS connectivity issues."
                }
            }
        }
    }
    catch {
        $sdnHealthObject.Result = 'FAIL'
    }

    return $sdnHealthObject
}
