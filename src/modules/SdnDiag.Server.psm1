# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Server.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Server' -Scope 'Local' -Force -Value @{
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

enum OvsdbTable {
    ms_vtep
    ms_firewall
    ServiceInsertion
}

enum VMState {
    Other
    Running
    Off
    Stopping
    Saved
    Paused
    Starting
    Reset
    Saving
    Pausing
    Resuming
    FastSaved
    FastSaving
    RunningCritical
    OffCritical
    StoppingCritical
    SavedCritical
    PausedCritical
    StartingCritical
    ResetCritical
    SavingCritical
    PausingCritical
    ResumingCritical
    FastSavedCritical
    FastSavingCritical
}

class OvsdbCore {
    hidden [guid]$UUID
}

class OvsdbGlobalTable : OvsdbCore {
    [int]$CurrentConfig # maps to the cur_cfg property of the Global table of ms_vtep database
    [int]$NextConfig # maps to the next_cfg property of the Global table of ms_vtep database
    [int]$Version # maps to the db_version property of the Global table of ms_vtep database
    [string]$Managers # maps to the managers property of the Global table of ms_vtep database
    [string]$OtherConfig # maps to the other_config property of the Global table of ms_vtep database
    [guid]$Switches # maps to the switches property of the Global table of ms_vtep database
}

class OvsdbFirewallRule : OvsdbCore {
    [string]$Action
    [string]$Direction
    [string]$Logging # maps to logging_state in ms_firewall database
    [int]$Priority
    [string]$Protocols
    [string]$SourceAddress # maps to src_ip_addresses in ms_firewall database
    [string]$SourcePort # maps to src_port in ms_firewall database
    [string]$DestinationAddress # maps to dst_ip_addresses in ms_firewall database
    [string]$DestinationPort # maps to dst_port in ms_firewall database
    [guid]$RuleId # maps to rule_id in ms_firewall database
    [string]$State # maps to rule_state in ms_firewall database
    hidden [String]$Type # maps to rule_type in ms_firewall database
    [guid]$VirtualNicId # maps to vnic_id in ms_firewall database
}

class OvsdbAddressMapping : OvsdbCore {
    [string]$CustomerAddress # maps to the ipaddr property of the Ucast_Macs_Remote table of ms_vtep database
    [string]$ProviderAddress # maps to the dst_ip property of the Physical_Locator table of ms_vtep database
    [string]$MacAddress # maps to the MAC property of the Ucast_Macs_Remote table of ms_vtep database
    [guid]$RoutingDomainId # maps to the description property of the Logical_Switch table of ms_vtep database
    [string]$VSwitchID # maps to the name property of the Logical_Switch table of ms_vtep database
    [string]$MappingType # maps to the mapping_type property of the Ucast_Macs_Remote table of ms_vtep database
    [string]$EncapType # maps to the encapsulation_type property of the Physical_Locator table of ms_vtep database
}

class OvsdbRouter : OvsdbCore {
    [string]$Description #maps to the description property of the Logical_Router table of ms_vtep database
    [string]$EnableLogicalRouter # maps to the enable_logical_router property of the Logical_Router table of ms_vtep database
    [guid]$VirtualNetworkId # maps to the name property of the Logical_Switch table of ms_vtep database
    [string[]]$StaticRoutes # maps to the static_routes property of the Logical_Router table of ms_vtep database
    [string[]]$SwitchBinding # maps to the switch_binding property of the Logical_Router table of ms_vtep database
}

class OvsdbUcastMacRemote : OvsdbCore {
    [string]$MacAddress # maps to the MAC property of the Ucast_Macs_Remote table of ms_vtep database
    [string]$CustomerAddress # maps to the ipaddr property of the Ucast_Macs_Remote table of ms_vtep database
    [string]$LogicalSwitch # maps to the logical_switch property of the Logical_Switch table of ms_vtep database
    [string]$Locator # maps to the locator property of the Ucast_Macs_Remote table of ms_vtep database
    [string]$MappingType # maps to the mapping_type property of the Ucast_Macs_Remote table of ms_vtep database
}

class OvsdbPhysicalPort : OvsdbCore {
    [string]$Description
    [string]$Name
}

class CommonVfp {
    hidden [string]$FriendlyName
    [int]$Priority
}

class VfpLayer : CommonVfp {
    [string]$Layer
    [string]$Flags
}

class VfpGroup : CommonVfp {
    [string]$Group
    [string]$Direction
    [string]$Type
    [string[]]$Conditions
    [string]$MatchType
}

class VfpRule : CommonVfp {
    [string]$Rule
    [string]$Type
    [string[]]$Conditions
    [int]$FlowTTL
    [string]$MatchType
    [string]$Flags
    [string]$FlagsEx
    hidden [string[]]$Properties
}

class VfpMeterRule : VfpRule {
    [boolean]$CounterOffloaded
    [string]$MeterInfo
}

class VfpEncapRule : VfpRule {
    [string]$EncapType
    [string[]]$EncapDestination
    [string]$EncapSourceIP
    [string]$Transposition
    [string[]]$Modify
    [string[]]$RuleData
    [int]$GREKey
}

class VfpFirewallRule : VfpRule {}

class VfpPortState {
    [boolean]$Enabled
    [boolean]$Blocked
    [boolean]$BlockOnRestore
    [boolean]$BlockLayerCreation
    [boolean]$PreserveVlan
    [boolean]$IsVmContextSet
    [boolean]$VmqEnabled
    $OffloadState = [OffLoadStateDetails]::new()
    [boolean]$QosHardwareReservationsEnabled
    [boolean]$QosHardwareCapsEnabled
    [boolean]$GftOffloadEnabled
    [boolean]$DtlsOffloadEnabled
}

class OffLoadStateDetails {
    [boolean]$LsoV2Supported
    [boolean]$LsoV2SupportedVxlan
    [boolean]$RssSupported
    [boolean]$RssSupportedVxlan
    [boolean]$TransmitChecksumOffloadSupported
    [boolean]$TransmitChecksumOffloadSupportedVxlan
    [boolean]$ReceiveChecksumOffloadSupported
    [boolean]$ReceiveChecksumOffloadSupportedVxlan
    [boolean]$VmqSupported
    [boolean]$VmqSupportedVxlan
    [boolean]$InnerMacVmqEnabled
}

class VfpVmSwitchPort {
    [guid]$PortName
    [string]$PortFriendlyName
    [guid]$SwitchName
    [string]$SwitchFriendlyName
    [int]$PortId
    [int]$VMQWeight
    [int]$VMQUsage
    [int]$SRIOVWeight
    [int]$SRIOVUsage
    [string]$PortType
    [string]$PortState
    [string]$MacLearning
    [string]$NicName
    [string]$NicFriendlyName
    [int]$MTU
    [string]$MacAddress
    [string]$VmName
    [string]$VmId
    [string]$NicState
    [string]$VSCState
    $NicStatistics = [NicStatistics]::new()
    $VmNicStatistics = [VmNicStatistics]::new()
}

class NicStatistics {
    [int64]$BytesSent
    [int64]$BytesReceived
    [int64]$IngressPacketDrops
    [int64]$EgressPacketDrops
    [int64]$IngressVfpDrops
    $IngressDropReason = [DropStatistics]::new()
    [int64]$EgressVfpDrops
    $EgressDropReason = [DropStatistics]::new()
}

class VmNicStatistics {
    [int64]$PacketsSent
    [int64]$PacketsReceived
    [int64]$InterruptsReceived
    [int64]$SendBufferAllocationCount
    [int64]$SendBufferAllocationSize
    [int64]$ReceiveBufferAllocationCount
    [int64]$ReceiveBufferAllocationSize
    [int64]$PendingLinkChange
    [int64]$RingBufferFullErrors
    [int64]$PendingRoutedPackets
    [int64]$InsufficientReceiveBuffers
    [int64]$InsufficientSendBuffers
    [int64]$InsufficientRndisOperations
    [int64]$QuotaExceeded
    [int64]$VspPaused
}

class DropStatistics {
    [int64]$Unknown
    [int64]$InvalidData
    [int64]$InvalidPacket
    [int64]$Resources
    [int64]$NotReady
    [int64]$Disconnected
    [int64]$NotAccepted
    [int64]$Busy
    [int64]$Filtered
    [int64]$FilteredVLAN
    [int64]$UnauthorizedVLAN
    [int64]$UnauthorizedMac
    [int64]$FailedSecurityPolicy
    [int64]$FailedPVLANSetting
    [int64]$QoS
    [int64]$IPsec
    [int64]$MacSpoofing
    [int64]$DhcpGuard
    [int64]$RouterGuard
    [int64]$BridgeReserved
    [int64]$VirtualSubnetID
    [int64]$VFPNotPresent
    [int64]$InvalidConfig
    [int64]$MTUMismatch
    [int64]$NativeForwardingReq
    [int64]$InvalidVLANFormat
    [int64]$InvalidDestMAC
    [int64]$InvalidSourceMAC
    [int64]$FirstNBTooSmall
    [int64]$WNV
    [int64]$StormLimit
    [int64]$InjectedICMP
    [int64]$FailedDestListUpdate
    [int64]$NICDisabled
    [int64]$FailedPacketFilter
    [int64]$SwitchDataDisabled
    [int64]$FilteredIsoUntagged
    [int64]$NA
}

class VMNetAdapterPortProfile {
    [string]$VMName
    [string]$Name
    [string]$MacAddress
    [string]$ProfileId
    [string]$ProfileData
    [string]$PortName
}

##########################
#### ARG COMPLETERS ######
##########################

##########################
####### FUNCTIONS ########
##########################

function Get-OvsdbAddressMapping {
    <#
    .SYNOPSIS
        Returns a list of address mappings from within the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbAddressMapping
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $paMappingTable = $ovsdbResults | Where-Object { $_.caption -eq 'Physical_Locator table' }
    $caMappingTable = $ovsdbResults | Where-Object { $_.caption -eq 'Ucast_Macs_Remote table' }
    $logicalSwitchTable = $ovsdbResults | Where-Object { $_.caption -eq 'Logical_Switch table' }

    if ($null -eq $caMappingTable) {
        return $null
    }

    # enumerate the json rules for each of the tables and create psobject for the mappings
    # unfortunately these values do not return in key/value pair and need to manually map each property
    foreach ($caMapping in $caMappingTable.Data) {

        # create the object
        $addressMapping = [OvsdbAddressMapping]@{
            UUID            = $caMapping[1][1]
            CustomerAddress = $caMapping[2]
            MacAddress      = $caMapping[0]
            MappingType     = $caMapping[5]
        }

        $locator = $caMapping[3][1]
        $logicalSwitch = $caMapping[4][1]

        # Get PA from locator table
        foreach ($paMapping in $paMappingTable.Data) {
            $curLocator = $paMapping[0][1]
            if ($curLocator -eq $locator) {
                $addressMapping.ProviderAddress = $paMapping[3]
                $addressMapping.EncapType = $paMapping[4]
                break
            }
        }

        # Get Rdid and VSID from logical switch table
        foreach ($switch in $logicalSwitchTable.Data) {
            $curSwitch = $switch[0][1]
            if ($curSwitch -eq $logicalSwitch) {
                $addressMapping.RoutingDomainId = $switch[1]
                $addressMapping.VSwitchID = $switch[3]
                break
            }
        }

        # add the object to the array
        [void]$arrayList.Add($addressMapping)
    }

    return $arrayList
}

function Get-OvsdbDatabase {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [OvsdbTable]$Table
    )

    $localPort = Get-NetTCPConnection -LocalPort:6641 -ErrorAction:SilentlyContinue
    if ($null -eq $localPort){
        throw New-Object System.NullReferenceException("No endpoint listening on port 6641. Ensure NCHostAgent service is running.")
    }

    $cmdline = "ovsdb-client.exe dump tcp:127.0.0.1:6641 -f json {0}" -f $Table
    $databaseResults = Invoke-Expression $cmdline | ConvertFrom-Json

    if($null -eq $databaseResults){
        $msg = "Unable to retrieve OVSDB results`n`t{0}" -f $_
        throw New-Object System.NullReferenceException($msg)
    }
    else {
        return $databaseResults
    }
}

function Get-OvsdbFirewallRuleTable {
    <#
    .SYNOPSIS
        Returns a list of firewall rules defined within the firewall table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbFirewallRuleTable
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_firewall
    $firewallTable = $ovsdbResults | Where-Object { $_.caption -eq 'FW_Rules table' }

    if ($null -eq $firewallTable) {
        return $null
    }
    # enumerate the json rules and create object for each firewall rule returned
    # there is no nice way to generate this and requires manually mapping as only the values are return
    foreach ($obj in $firewallTable.data) {
        $result = [OvsdbFirewallRule]@{
            UUID               = $obj[0][1]
            Action             = $obj[1]
            Direction          = $obj[2]
            DestinationAddress = $obj[3]
            DestinationPort    = $obj[4]
            Logging            = $obj[5]
            Priority           = $obj[6]
            Protocols          = $obj[7]
            RuleId             = $obj[8]
            State              = $obj[9]
            Type               = $obj[10]
            SourceAddress      = $obj[11]
            SourcePort         = $obj[12]
            VirtualNicId       = $obj[13]
        }

        # add the psobject to array list
        [void]$arrayList.Add($result)
    }

    return $arrayList
}

function Get-OvsdbGlobalTable {
    <#
    .SYNOPSIS
        Returns the global table configuration from OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbGlobalTable
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $globalTable = $ovsdbResults | Where-Object { $_.caption -eq 'Global table' }

    if ($null -eq $globalTable) {
        return $null
    }

    # enumerate the json results and add to psobject
    foreach ($obj in $globalTable.data) {
        $result = [OvsdbGlobalTable]@{
            uuid     = $obj[0][1]
            CurrentConfig  = $obj[1]
            NextConfig = $obj[4]
            Switches = $obj[6][1]
        }

        # add the psobject to array
        [void]$arrayList.Add($result)
    }

    return $arrayList
}

function Get-OvsdbPhysicalPortTable {
    <#
    .SYNOPSIS
        Returns a list of ports defined within the Physical_Port table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbPhysicalPortTable
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()

    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $portTable = $ovsdbResults | Where-Object { $_.caption -eq 'Physical_Port table' }

    if ($null -eq $portTable) {
        return $null
    }

    # enumerate the json objects and create psobject for each port
    foreach ($obj in $portTable.data) {
        $physicalPort = [OvsdbPhysicalPort]@{
            UUID        = $obj[0][1]
            Description = $obj[1]
            Name        = $obj[2].Trim('{', '}')  # remove the curly braces from the name
        }

        # there are numerous key/value pairs within this object with some having different properties
        # enumerate through the properties and add property and value for each
        foreach ($property in $obj[4][1]) {
            $physicalPort | Add-Member -MemberType NoteProperty -Name $property[0] -Value $property[1]
        }

        # add the psobject to array
        [void]$arrayList.Add($physicalPort)
    }

    return $arrayList
}

function Get-OvsdbRouterTable {
    <#
    .SYNOPSIS
        Returns the logical router table configuration from OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbRouterTable
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()
    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $routerTable = $ovsdbResults | Where-Object { $_.caption -eq 'Logical_Router table' }

    if ($null -eq $routerTable) {
        return $null
    }

    # enumerate the json results and add to psobject
    foreach ($obj in $routerTable.data) {
        $staticroute = @()
        if($obj[5][1].count -gt 0){
            foreach($route in $obj[5][1]){
                if(![string]::IsNullOrEmpty(($staticroute))){
                    $staticroute += ', '
                }
                $staticRoute += "$($route[0])=$($route[1])"
            }
        }

        $switchbinding = @()
        if($obj[6][1].count -gt 0){
            foreach($switch in $obj[6][1]){
                if(![string]::IsNullOrEmpty(($switchbinding))){
                    $switchbinding += ', '
                }

                $switchbinding += "$($switch[0])=$($switch[1][1])"
            }
        }

        $result = [OvsdbRouter]@{
            uuid     = $obj[0][1]
            Description  = $obj[1]
            EnableLogicalRouter = $obj[2]
            VirtualNetworkId = $obj[3]
            StaticRoutes = $staticroute
            SwitchBinding = $switchbinding
        }

        # add the psobject to array
        [void]$arrayList.Add($result)
    }

    return $arrayList
}

function Get-OvsdbUcastMacRemoteTable {
    <#
    .SYNOPSIS
        Returns a list of mac addresses defined within the Ucast_Macs_Remote table of the OVSDB database.
    .EXAMPLE
        PS> Get-OvsdbUcastMacRemoteTable
    #>

    [CmdletBinding()]
    param()

    $arrayList = [System.Collections.ArrayList]::new()
    $ovsdbResults = Get-OvsdbDatabase -Table ms_vtep
    $ucastMacsRemoteTable = $ovsdbResults | Where-Object { $_.caption -eq 'Ucast_Macs_Remote table' }

    if ($null -eq $ucastMacsRemoteTable) {
        return $null
    }

    # enumerate the json objects and create psobject for each port
    foreach ($obj in $ucastMacsRemoteTable.data) {
        $result = [OvsdbUcastMacRemote]@{
            UUID            = $obj[1][1]
            MacAddress      = $obj[0]
            CustomerAddress = $obj[2]
            Locator         = $obj[3][1]
            LogicalSwitch   = $obj[4][1]
            MappingType     = $obj[5]
        }

        [void]$arrayList.Add($result)
    }

    return $arrayList
}

function Get-ServerConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the server role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-ServerConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'

    [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState/Server"

    try {
        $config = Get-SdnModuleConfiguration -Role:Server
        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output
        if (-NOT (Initialize-DataCollection -Role:Server -FilePath $outDir -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        [string]$regDir = Join-Path -Path $outDir -ChildPath "Registry"
        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir

        # Gather VFP port configuration details
        "Gathering VFP port details" | Trace-Output -Level:Verbose
        foreach ($vm in (Get-WmiObject -Namespace 'root\virtualization\v2' -Class 'msvm_computersystem')) {
            foreach ($vma in $vm.GetRelated("Msvm_SyntheticEthernetPort")) {
                foreach ($port in $vma.GetRelated("Msvm_SyntheticEthernetPortSettingData").GetRelated("Msvm_EthernetPortAllocationSettingData").GetRelated("Msvm_EthernetSwitchPort")) {
                    $outputDir = New-Item -Path (Join-Path -Path $outDir -ChildPath "VFP\$($vm.ElementName)") -ItemType Directory -Force
                    vfpctrl /list-nat-range /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_list_nat_range' -FileType txt -Force
                    vfpctrl /list-rule /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_list_rule' -FileType txt -Force
                    vfpctrl /list-mapping /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_list_mapping' -FileType txt -Force
                    vfpctrl /list-unified-flow /port $port.Name | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_list_unifiied_flow'  -FileType txt -Force
                    vfpctrl /get-port-flow-settings /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_get_port_flow_settings' -FileType txt -Force
                    vfpctrl /get-port-flow-stats /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_get_port_flow_stats'  -FileType txt -Force
                    vfpctrl /get-flow-stats /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_get_flow_stats' -FileType txt -Force
                    vfpctrl /get-port-state /port $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'vfpctrl_get_port_state' -FileType txt -Force

                    Get-SdnVfpPortState -PortName $($port.Name) | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $port.Name -Name 'Get-SdnVfpPortState' -FileType txt -Format Table
                }
            }
        }

        vfpctrl /list-vmswitch-port | Export-ObjectToFile -FilePath $outDir -Name 'vfpctrl_list-vmswitch-port' -FileType txt -Force
        Get-SdnVfpVmSwitchPort | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        # Gather OVSDB databases
        "Gathering ovsdb database output" | Trace-Output -Level:Verbose
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_vtep | Export-ObjectToFile -FilePath $outDir -Name 'ovsdb_vtep' -FileType txt -Force
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_firewall | Export-ObjectToFile -FilePath $outDir -Name 'ovsdb_firewall' -FileType txt -Force
        ovsdb-client.exe dump tcp:127.0.0.1:6641 ms_service_insertion | Export-ObjectToFile -FilePath $outDir -Name 'ovsdb_serviceinsertion' -FileType txt -Force

        Get-SdnOvsdbAddressMapping | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-SdnOvsdbFirewallRule | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-SdnOvsdbGlobalTable | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-SdnOvsdbPhysicalPort | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-SdnOvsdbUcastMacRemoteTable | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        # check if networkatc service is running and if so, gather the configuration
        if ((Get-Service -Name 'NetworkAtc' -ErrorAction Ignore).Status -eq 'Running') {
            Get-NetIntent | Export-ObjectToFile -FilePath $outDir -Name 'Get-NetIntent' -FileType txt -Format List

            $netIntentStatus = Get-NetIntentStatus -ComputerName $env:COMPUTERNAME
            # due to the way the Get-NetIntentStatus cmdlet works, we need to eliminate the empty objects
            # and the objects that are type string
            $netIntentStatusObject = @()
            foreach ($obj in $netIntentStatus) {
                if ([string]::IsNullOrEmpty($obj) -or $obj.GetType().Name -ieq 'String'){
                    continue
                }
                $netIntentStatusObject += $obj
            }

            $netIntentStatusObject | Export-ObjectToFile -FilePath $outDir -Name 'Get-NetIntentStatus' -FileType txt -Format List
        }

        # enumerate the vm switches and gather details
        "Gathering VMSwitch details" | Trace-Output -Level:Verbose
        Get-SdnNetAdapterEncapOverheadConfig | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-VMSwitchTeam | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-VMSystemSwitchExtensionPortFeature -FeatureId "9940cd46-8b06-43bb-b9d5-93d50381fd56" | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        $vmSwitch = Get-VMSwitch
        if ($vmSwitch) {
            $vmSwitchRootDir = New-Item -Path (Join-Path -Path $outDir -ChildPath "VMSwitch") -ItemType Directory -Force
            $vmSwitch | Export-ObjectToFile -FilePath $outDir -Name 'Get-VMSwitch' -FileType txt -Format List
            foreach ($vSwitch in $vmSwitch) {
                $prefix = $vSwitch.Name.ToString().Replace(" ", "_").Trim()
                $vSwitch | Get-VMSwitchExtension | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchExtension' -FileType txt -Format List
                $vSwitch | Get-VMSwitchExtensionSwitchData | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchExtensionSwitchData' -FileType txt -Format List
                $vSwitch | Get-VMSwitchExtensionSwitchFeature | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchExtensionSwitchFeature' -FileType txt -Format List
                $vSwitch | Get-VMSwitchTeam | Export-ObjectToFile -FilePath $vmSwitchRootDir.FullName -Prefix $prefix -Name 'Get-VMSwitchTeam' -FileType txt -Format List
            }
        }

        # add fault tolerance for hnvdiagnostics commands that do not have [CmdletBinding()]
        # and will ignore the ErrorActionPreference resulting in a terminating exception
        $hnvDiag = @(
            "Get-PACAMapping",
            "Get-CustomerRoute",
            "Get-ProviderAddress"
        )
        $hnvDiag | ForEach-Object {
            try {
                $cmd = $_
                Invoke-Expression -Command $cmd | Export-ObjectToFile -FilePath $outDir -Name $cmd -FileType txt -Format List
            }
            catch {
                "Failed to execute {0}" -f $cmd | Trace-Output -Level:Error
            }
        }

        # Gather Hyper-V network details
        "Gathering Hyper-V VM and VMNetworkAdapter configuration details" | Trace-Output -Level:Verbose
        $virtualMachines = Get-VM
        if ($virtualMachines) {
            $virtualMachines | Export-ObjectToFile -FilePath $outDir -Name 'Get-VM' -FileType txt -Format List -Force
            $virtualMachines | Export-ObjectToFile -FilePath $outDir -Name 'Get-VM' -FileType json

            $vmRootDir = New-Item -Path (Join-Path -Path $outDir -ChildPath "VM") -ItemType Directory -Force
            foreach ($vm in $virtualMachines) {
                $vmAdapters = $vm.NetworkAdapters
                if ($null -eq $vmAdapters) {
                    continue
                }

                $vmNameFormatted = $vm.Name.ToString().Replace(" ", "_").Trim()
                $vmDir = New-Item -Path (Join-Path -Path $vmRootDir.FullName -ChildPath $vmNameFormatted) -ItemType Directory -Force

                # enumerate the VMNetworkAdapters and gather details within the VM properties itself to speed up data processing
                # calling each function such as Get-VMNetworkAdapter or Get-VMNetworkAdapterVlan will enumerate the VMNetworkAdapters again and slow down the process
                foreach ($adapter in $vmAdapters) {
                    try {
                        $prefix = (Format-SdnMacAddress -MacAddress $adapter.MacAddress)

                        $adapterModified = $adapter | Remove-PropertiesFromObject -PropertiesToRemove 'AclList','ExtendedAclList','IsolationSetting','RoutingDomainList','VlanSetting','CimSession'
                        $adapterModified | Export-ObjectToFile -FilePath $vmDir.FullName -Prefix $prefix -Name 'Get-VM_NetworkAdapter' -FileType txt -Format List
                        $adapter.AclList | Remove-PropertiesFromObject -PropertiesToRemove 'ParentAdapter' | Export-ObjectToFile -FilePath $vmDir.FullName -Prefix $prefix -Name 'Get-VM_AclList' -FileType txt -Format List
                        $adapter.ExtendedAclList | Remove-PropertiesFromObject -PropertiesToRemove 'ParentAdapter','CimSession' | Export-ObjectToFile -FilePath $vmDir.FullName -Prefix $prefix -Name 'Get-VM_ExtendedAclList' -FileType txt -Format List
                        $adapter.IsolationSetting | Remove-PropertiesFromObject -PropertiesToRemove 'ParentAdapter','CimSession' | Export-ObjectToFile -FilePath $vmDir.FullName -Prefix $prefix -Name 'Get-VM_IsolationSetting' -FileType txt -Format List
                        $adapter.RoutingDomainList | Remove-PropertiesFromObject -PropertiesToRemove 'ParentAdapter','CimSession' | Export-ObjectToFile -FilePath $vmDir.FullName -Prefix $prefix -Name 'Get-VM_RoutingDomainList' -FileType txt -Format List
                        $adapter.VlanSetting | Remove-PropertiesFromObject -PropertiesToRemove 'ParentAdapter','CimSession' | Export-ObjectToFile -FilePath $vmDir.FullName -Prefix $prefix -Name 'Get-VM_VlanSetting' -FileType txt -Format List
                    }
                    catch {
                        "Failed to enumerate VMNetworkAdapter for {0}" -f $adapter.Name | Trace-Output -Level:Warning
                    }
                }
            }
        }

        # enumerate the data for all adapters
        Get-VMNetworkAdapter -All | Export-ObjectToFile -FilePath $outDir -Name 'Get-VMNetworkAdapter_All' -FileType txt -Format List
        Get-SdnVMNetworkAdapterPortProfile -All | Export-ObjectToFile -FilePath $outDir -Name 'Get-SdnVMNetworkAdapterPortProfile_All' -FileType txt -Format List

        # collect the management OS network adapter details
        # we do not need this information for general vmnetworkadapters as they are already collected above
        Get-VMNetworkAdapterIsolation -ManagementOS | Export-ObjectToFile -FilePath $outDir -Name 'Get-VMNetworkAdapterIsolation_ManagementOS' -FileType txt -Format List
        Get-VMNetworkAdapterTeamMapping -ManagementOS | Export-ObjectToFile -FilePath $outDir -Name 'Get-VMNetworkAdapterTeamMapping_ManagementOS' -FileType txt -Format List
        Get-VMNetworkAdapterVLAN -ManagementOS | Export-ObjectToFile -FilePath $outDir -Name 'Get-VMNetworkAdapterVLAN _ManagementOS' -FileType txt -Format List
        Get-VMNetworkAdapterRoutingDomainMapping -ManagementOS | Export-ObjectToFile -FilePath $outDir -Name 'Get-VMNetworkAdapterRoutingDomainMapping_ManagementOS' -FileType txt -Format List
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

function Get-VfpPortGroup {
    <#
    .SYNOPSIS
        Enumerates the groups contained within the specific Virtual Filtering Platform (VFP) layer specified for the port.

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer
    )

    $arrayList = [System.Collections.ArrayList]::new()
    $vfpGroups = vfpctrl /list-group /port $PortName /layer $Layer

    if([string]::IsNullOrEmpty($vfpGroups)) {
        $msg = "Unable to list groups within $Layer for $PortName from vfpctrl"
        throw New-Object System.NullReferenceException($msg)
    }

    # if the line contains a failure, then throw an error and exit the function
    # this is typically the first line in the output
    if ($vfpGroups[0] -ilike "ERROR:*") {
        $msg = $vfpGroups[0].Split(':')[1].Trim()
        throw New-Object System.Exception($msg)
    }

    foreach ($line in $vfpGroups) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        # in situations where the value might be nested in another line we need to do some additional data processing
        # subkey is declared below if the value is null after the split
        if ($subKey) {
            if($null -eq $subObject){
                $subObject = New-Object -TypeName PSObject
            }
            if ($null -eq $subArrayList) {
                $subArrayList = [System.Collections.ArrayList]::new()
            }

            switch ($subKey) {
                'Conditions' {
                    # this will have a pattern of multiple lines nested under Conditions: in which we see a pattern of property:value format
                    # we also see common pattern that Match type is the next property after Conditions, so we can use that to determine when
                    # no further processing is needed for this sub value
                    if ($line.Contains('Match type')) {
                        $object.Conditions = $subObject

                        $subObject = $null
                        $subKey = $null
                    }

                    # if <none> is defined for conditions, we can also assume there is nothing to define
                    elseif ($line.Contains('<none>')) {
                        $object.Conditions = $null

                        $subObject = $null
                        $subKey = $null
                    }

                    elseif ($line.Contains(':')) {
                        [System.String[]]$subResults = $line.Split(':').Trim()
                        $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                    }
                }
            }
        }

        # lines in the VFP output that contain : contain properties and values
        # need to split these based on count of ":" to build key and values
        if ($line.Contains(':')) {
            [System.String[]]$results = $line.Split(':').Trim()
            if ($results.Count -eq 2) {
                [System.String]$key = $results[0].Trim()
                [System.String]$value = $results[1].Trim()

                switch ($key) {
                    # group is typically the first property in the output
                    # so we will key off this property to know when to add the object to the array
                    # as well as create a new object
                    'Group' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = [VfpGroup]@{
                            Group = $value
                        }
                    }
                    'Friendly Name' { $object.FriendlyName = $value }
                    'Match type' { $object.MatchType = $value }
                    'Conditions' { $subKey = $key }
                    'Priority' { $object.Priority = $value}

                    default {
                        try {
                            $object.$key = $value
                        }
                        catch {
                            $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                            continue
                        }
                    }
                }
            }
        }
        elseif ($line.Contains('Command list-group succeeded!')) {
            if ($object) {
                [void]$arrayList.Add($object)
            }
        }
    }

    return ($arrayList | Sort-Object -Property Priority)
}

function Get-VfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortName
        The Port Name for the network interface
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName
    )

    $arrayList = [System.Collections.ArrayList]::new()
    $vfpLayers = vfpctrl /list-layer /port $PortName

    if([string]::IsNullOrEmpty($vfpLayers)) {
        $msg = "Unable to list layers for $PortName from vfpctrl"
        throw New-Object System.NullReferenceException($msg)
    }

    # if the line contains a failure, then throw an error and exit the function
    # this is typically the first line in the output
    if ($vfpLayers[0] -ilike "ERROR:*") {
        $msg = $vfpLayers[0].Split(':')[1].Trim()
        throw New-Object System.Exception($msg)
    }

    foreach ($line in $vfpLayers) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        # lines in the VFP output that contain : contain properties and values
        # need to split these based on count of ":" to build key and values
        if ($line.Contains(':')) {
            [System.String[]]$results = $line.Split(':').Trim()
            if ($results.Count -eq 2) {
                [System.String]$key = $results[0].Trim()
                [System.String]$value = $results[1].Trim()

                switch ($key) {
                    # layer is typically the first property in the output
                    # so we will key off this property to know when to add the object to the array
                    # as well as create a new object
                    'Layer' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = [VfpLayer]@{
                            Layer = $value
                        }
                    }

                    # process the rest of the values as normal
                    'Priority' { $object.Priority = $value}
                    'Friendly name' { $object.FriendlyName = $value}
                    'Flags' { $object.Flags = $value}

                    default {
                        try {
                            $object.$key = $value
                        }
                        catch {
                            $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                            continue
                        }
                    }
                }
            }
        }
        else {
            switch -Wildcard ($line) {
                # this should indicate the end of the results from vpctrl
                # if we have an object, add it to the array list
                "*Command list-layer succeeded*" {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }
                }
            }
        }
    }

    return ($arrayList | Sort-Object -Property Priority)
}

function Get-VfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the rules contained within the specific group within Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortName
        The Port name for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Group
        Specify the group layer.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer,

        [Parameter(Mandatory = $true)]
        [System.String]$Group
    )

    $arrayList = [System.Collections.ArrayList]::new()
    $vfpRules = vfpctrl /list-rule /port $PortName /layer $Layer /group $Group
    if([string]::IsNullOrEmpty($vfpRules)) {
        $msg = "Unable to list rules for $Layer and $Group for $PortName from vfpctrl"
        throw New-Object System.NullReferenceException($msg)
    }

    # if the line contains a failure, then throw an error and exit the function
    # this is typically the first line in the output
    if ($vfpRules[0] -ilike "ERROR:*") {
        $msg = $vfpRules[0].Split(':')[1].Trim()
        throw New-Object System.Exception($msg)
    }

    foreach ($line in $vfpRules) {
        $line = $line.Trim()
        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        # in situations where the value might be nested in another line we need to do some additional data processing
        # subkey is declared below if the value is null after the split
        if ($subKey) {
            $doneProcessingSubKey = $false
            if($null -eq $subObject){
                $subObject = [PSCustomObject]::new()
            }
            if ($null -eq $subArrayList) {
                $subArrayList = [System.Collections.ArrayList]::new()
            }

            switch ($subKey) {
                'Conditions' {
                    # this will have a pattern of multiple lines nested under Conditions: in which we see a pattern of property:value format
                    # we also see common pattern that Flow TTL is the next property after Conditions, so we can use that to determine when
                    # no further processing is needed for this sub value
                    if ($line.Contains('Flow TTL')) {
                        $object.Conditions = $subObject

                        $doneProcessingSubKey = $true
                        $subObject = $null
                        $subKey = $null
                    }

                    # if <none> is defined for conditions, we can also assume there is nothing to define
                    elseif ($line.Contains('<none>')) {
                        $object.Conditions = $null

                        $doneProcessingSubKey = $true
                        $subObject = $null
                        $subKey = $null
                    }

                    else {
                        # split the values and add to sub object, that we will then insert into the main object
                        # once we are done processing all the sub values
                        [System.String[]]$subResults = $line.Split(':').Trim()
                        $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                    }
                }
                'Encap Destination(s)' {
                    # once we reach the next line where we have a ':' we can assume we are done processing the sub value
                    if ($line.Contains(':')) {
                        $object.EncapDestination = $subObject

                        $subObject = $null
                        $subKey = $null
                    }
                    else {
                        [System.String[]]$subResults = $line.Replace('{','').Replace('}','').Split(',').Trim()
                        foreach ($subResult in $subResults) {
                            [System.String]$subKeyName = $subResult.Split('=')[0].Trim()
                            [System.String]$subKeyValue = $subResult.Split('=')[1].Trim()

                            $subObject | Add-Member -MemberType NoteProperty -Name $subKeyName -Value $subKeyValue
                        }
                    }
                }
                'Rule Data' {
                    # once we reach the next line where we have a ':' we can assume we are done processing the sub value
                    if ($line.Contains(':')) {
                        $object.RuleData = $subObject

                        $subObject = @()
                        $subKey = $null
                    }
                    else {
                        $subObject += $line.Trim()
                    }
                }
                'Modify' {
                    # this will have a pattern of multiple lines nested under Modify: in which we see a pattern of property:value format
                    # we also see common pattern that Transposition or FlagsEx or Set VLAN is the next property after Conditions, so we can use that to determine when
                    # no further processing is needed for this sub value
                    if ($line.Contains('Transposition') -or $line.Contains('FlagsEx') -or $line.Contains('Set VLAN')) {
                        $object.Modify = $subObject

                        $subObject = [PSCustomObject]::new()
                        $subKey = $null
                    }
                    else {
                        # split the values and add to sub object, that we will then insert into the main object
                        # once we are done processing all the sub values
                        [System.String[]]$subResults = $line.Split(':').Trim()
                        $subObject | Add-Member -MemberType NoteProperty -Name $subResults[0] -Value $subResults[1]
                    }
                }
            }

            if ($doneProcessingSubKey) {
                # we are done processing the subkey, so we can proceed to the rest of the script
            }
            else {
                # we are not done processing the subkey values, so we need to continue to the next line
                continue
            }
        }

        # lines in the VFP output that contain : contain properties and values
        # need to split these based on count of ":" to build key and values
        if ($line.Contains(':')) {
            [System.String[]]$results = $line.Split(':')
            if ($results.Count -eq 2) {
                [System.String]$key = $results[0].Trim()
                [System.String]$value = $results[1].Trim()

                switch ($key) {
                    # rule is typically the first property in the output
                    # so we will key off this property to know when to add the object to the array
                    # as well as create a new object
                    'Rule' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        # create the custom object based on the layer
                        # so that we can add appropriate properties
                        switch ($Layer) {
                            "GW_PA_ROUTE_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "FW_ADMIN_LAYER_ID" {
                                $object = [VfpFirewallRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_DR_REDIRECTION_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "FW_CONTROLLER_LAYER_ID" {
                                $object = [VfpFirewallRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_METER_LAYER_OUT" {
                                $object = [VfpMeterRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_MAC_REWRITE_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_ENCAP_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "VNET_PA_ROUTE_LAYER" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            "SLB_NAT_LAYER" {
                                $object = [VfpRule]@{
                                    Rule = $value
                                }
                            }

                            "SLB_DECAP_LAYER_STATEFUL" {
                                $object = [VfpEncapRule]@{
                                    Rule = $value
                                }
                            }

                            default {
                                $object = [VfpRule]@{
                                    Rule = $value
                                }
                            }
                        }
                    }

                    # because some rules defined within groups do not have a rule name defined such as NAT layers,
                    # grab the friendly name and update the ps object
                    'Friendly name' {
                        if([String]::IsNullOrEmpty($object.Rule)) {
                            $object.Rule = $value
                        }

                        $object.FriendlyName = $value
                    }

                    'Conditions' { $subkey = $key ; continue }
                    'Encap Destination(s)' { $subkey = $key ; continue }
                    'Rule Data' { $subkey = $key ; continue }
                    'Modify' { $subkey = $key ; continue }

                    default {
                        $key = $key.Replace(' ','').Trim()

                        try {
                            $object.$key = $value
                        }
                        catch {
                            # this is the fallback method to just add a property to the object
                            # outside of the defined class properties
                            $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                            continue
                        }
                    }
                }
            }
        }
        else {
            switch -Wildcard ($line) {
                # this should indicate the end of the results from vpctrl
                # if we have an object, add it to the array list
                "*Command list-rule succeeded*" {
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }
                }
                "*ITEM LIST*" { continue }
                "*====*" { continue }
                default {
                    $object.Properties += $line.Trim()
                }
            }
        }
    }

    return ($arrayList | Sort-Object -Property Priority)
}

function Get-VfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $port' to return back the current state of the port specified.
    .PARAMETER PortName
        The port name to return the state for.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName
    )

    $object = [VfpPortState]::new()

    $vfpPortState = vfpctrl.exe /get-port-state /port $PortName
    if([string]::IsNullOrEmpty($vfpPortState)) {
        $msg = "Unable to get port state for $PortName from vfpctrl"
        throw New-Object System.NullReferenceException($msg)
    }

    # if the line contains a failure, then throw an error and exit the function
    # this is typically the first line in the output
    if ($vfpPortState[0] -ilike "ERROR:*") {
        $msg = $vfpPortState[0].Split(':')[1].Trim()
        throw New-Object System.Exception($msg)
    }

    foreach ($line in $vfpPortState) {
        # skip if the line is empty or null
        if([string]::IsNullOrEmpty($line)) {
            continue
        }

        # split the line by the colon and trim the spaces
        $subValue = $line.Split(':').Trim()
        if ($subValue.Count -eq 2) {

            # due to some errors observed in environments, we need to wrap the conversion in a try/catch block
            # that way we can continue processing the remaining properties and not fail the entire function
            try {
                $propertyName = $subValue[0].Trim()
                $propertyValue = [System.Convert]::ToBoolean($subValue[1].Trim())
            }
            catch {
                "Unable to process value {0} for {1}`r`n`t{2}" -f $subValue[1].Trim(), $propertyName, $_.Exception | Trace-Output -Level:Warning
                continue
            }

            switch ($propertyName) {
                # update the VfpPortState properties
                'Enabled' { $object.Enabled = $propertyValue }
                'Blocked' { $object.Blocked = $propertyValue }
                'BlockedOnRestore' { $object.BlockOnRestore = $propertyValue }
                'BlockedLayerCreation' { $object.BlockLayerCreation = $propertyValue }
                'DTLS Offload Enabled' { $object.DtlsOffloadEnabled = $propertyValue }
                'GFT Offload Enabled' { $object.GftOffloadEnabled = $propertyValue }
                'QoS Hardware Transmit Cap Offload Enabled' { $object.QosHardwareCapsEnabled = $propertyValue }
                'QoS Hardware Transmit Reservation Offload Enabled' { $object.QosHardwareReservationsEnabled = $propertyValue }
                'Preserving Vlan' { $object.PreserveVlan = $propertyValue }
                'VM Context Set' { $object.IsVmContextSet = $propertyValue }

                # update the OffLoadStateDetails properties
                'NVGRE LSO Offload Enabled' { $object.PortState.LsoV2Supported = $propertyValue}
                'NVGRE RSS Enabled' { $object.PortState.RssSupported = $propertyValue }
                'NVGRE Transmit Checksum Offload Enabled' { $object.PortState.TransmitChecksumOffloadSupported = $propertyValue }
                'NVGRE Receive Checksum Offload Enabled' { $object.PortState.ReceiveChecksumOffloadSupported = $propertyValue }
                'NVGRE VMQ Enabled' { $object.PortState.VmqSupported = $propertyValue }
                'VXLAN LSO Offload Enabled' { $object.PortState.LsoV2SupportedVxlan = $propertyValue }
                'VXLAN RSS Enabled' { $object.PortState.RssSupportedVxlan = $propertyValue }
                'VXLAN Transmit Checksum Offload Enabled' { $object.PortState.TransmitChecksumOffloadSupportedVxlan = $propertyValue }
                'VXLAN Receive Checksum Offload Enabled' { $object.PortState.ReceiveChecksumOffloadSupportedVxlan = $propertyValue }
                'VXLAN VMQ Enabled' { $object.PortState.VmqSupportedVxlan = $propertyValue }
                'Inner MAC VMQ Enabled' { $object.PortState.InnerMacVmqEnabled = $propertyValue }

                default {
                    $propertyName = $propertyName.Replace(' ','').Trim()

                    try {
                        $object.$propertyName = $propertyValue
                    }
                    catch {
                        $object | Add-Member -MemberType NoteProperty -Name $propertyName -Value $propertyValue
                        continue
                    }
                }
            }
        }
        else {
            # if the line does not have key/value pairs, then continue to next line
            continue
        }
    }

    return $object
}

function Get-VfpVMSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within VFP.
    #>

    $arrayList = [System.Collections.ArrayList]::new()
    $vfpResults = vfpctrl /list-vmswitch-port
    if([string]::IsNullOrEmpty($vfpResults)) {
        $msg = "Unable to retrieve vmswitch ports from vfpctrl"
        throw New-Object System.NullReferenceException($msg)
    }

    # if the line contains a failure, then throw an error and exit the function
    # this is typically the first line in the output
    if ($vfpResults[0] -ilike "ERROR:*") {
        $msg = $vfpResults[0].Split(':')[1].Trim()
        throw New-Object System.Exception($msg)
    }

    foreach ($line in $vfpResults) {
        $line = $line.Trim()

        if ([string]::IsNullOrEmpty($line)) {
            continue
        }

        # lines in the VFP output that contain : contain properties and values
        # need to split these based on count of ":" to build key and values
        # some values related to ingress packet drops have multiple ":" so need to account for that
        # example: {property} : {reason} : {value}
        # example: {property} : {value}
        if ($line.Contains(":")) {
            [System.String[]]$results = $line.Split(':').Trim()
            if ($results.Count -eq 3) {
                $key    = $results[1].Replace(' ','').Trim() # we want the key to align with the {reason}
                $value  = $results[2].Trim()

                if ($results[0].Trim() -eq 'Ingress packet drops') {
                    $object.NicStatistics.IngressDropReason.$key = $value
                }
                elseif($results[0].Trim() -eq 'Egress packet drops') {
                    $object.NicStatistics.EgressDropReason.$key = $value
                }
            }
            elseif ($results.Count -eq 2) {
                $key    = $results[0].Trim() # we want the key to align with the {property}
                $value  = $results[1].Trim()

                switch ($key) {
                    # all ports start with the port name property
                    # so we will key off this property to know when to add the object to the array
                    # and to create a new object
                    'Port name' {
                        if ($object) {
                            [void]$arrayList.Add($object)
                        }

                        $object = [VfpVmSwitchPort]@{
                            PortName = $value
                        }

                        continue
                    }

                    "SR-IOV Weight" { $object.SRIOVWeight = $value }
                    "SR-IOV Usage" { $object.SRIOVUsage = $value }

                    # populate the NicStatistics object
                    'Bytes Sent' { $object.NicStatistics.BytesSent = $value }
                    'Bytes Received' { $object.NicStatistics.BytesReceived = $value }
                    'Ingress Packet Drops' { $object.NicStatistics.IngressPacketDrops = $value }
                    'Egress Packet Drops' { $object.NicStatistics.EgressPacketDrops = $value }
                    'Ingress VFP Drops' { $object.NicStatistics.IngressVfpDrops = $value }
                    'Egress VFP Drops' { $object.NicStatistics.EgressVfpDrops = $value }

                    # populate the VmNicStatistics object
                    'Packets Sent' { $object.VmNicStatistics.PacketsSent = $value }
                    'Packets Received' { $object.VmNicStatistics.PacketsReceived = $value }
                    'Interrupts Received' { $object.VmNicStatistics.InterruptsReceived = $value }
                    'Send Buffer Allocation Count' { $object.VmNicStatistics.SendBufferAllocationSize = $value }
                    'Send Buffer Allocation Size' { $object.VmNicStatistics.SendBufferAllocationSize = $value }
                    'Receive Buffer Allocation Count' { $object.VmNicStatistics.ReceiveBufferAllocationCount = $value }
                    'Receive Buffer Allocation Size' { $object.VmNicStatistics.ReceiveBufferAllocationSize = $value }
                    'Pending Link Change' { $object.VmNicStatistics.PendingLinkChange = $value }
                    'Ring Buffer Full Errors' { $object.VmNicStatistics.RingBufferFullErrors = $value }
                    'Pending Routed Packets' { $object.VmNicStatistics.PendingRoutedPackets = $value }
                    'Insufficient Receive Buffers' { $object.VmNicStatistics.InsufficientReceiveBuffers = $value }
                    'Insufficient Send Buffers' { $object.VmNicStatistics.InsufficientSendBuffers = $value }
                    'Insufficient RNDIS Operations Buffers' { $object.VmNicStatistics.InsufficientRndisOperationsBuffers = $value }
                    'Quota Exceeded Errors' { $object.VmNicStatistics.QuotaExceededErrors = $value }
                    'Vsp Paused' { $object.VmNicStatistics.VspPaused = $value }

                    # most of the property names, we can just trim and remove the white spaces
                    # which will align to the class property names
                    default {
                        try {
                            $key = $key.Replace(' ','').Trim()
                            $object.$key = $value
                        }
                        catch {
                            $_ | Trace-Exception
                            $object | Add-Member -MemberType NoteProperty -Name $key -Value $value
                            continue
                        }
                    }
                }
            }
        }
        else {
            switch -Wildcard ($line) {
                "Port is*" { $object.PortState = $line.Split(' ')[2].Replace('.','').Trim() }
                "MAC Learning is*" { $object.MacLearning = $line.Split(' ')[3].Replace('.','').Trim() }
                "NIC is*" { $object.NicState = $line.Split(' ')[2].Replace('.','').Trim() }
                "*list-vmswitch-port*" {
                    # we have reached the end of the file at this point
                    # and should add any remaining objects to the array
                    if ($object) {
                        [void]$arrayList.Add($object)
                    }
                }
                default {
                    # the line does not contain anything we looking for
                    # and we can skip it and proceed to next
                    continue
                }
            }
        }
    }

    return $arrayList
}

function Get-SdnNetAdapterEncapOverheadConfig {
    <#
    .SYNOPSIS
        Retrieves the EncapOverhead and JumboPacket properties of each network interface attached to a vfp enabled vmswitch
    .PARAMETER Name
        Specifies the name of the virtual switch to be retrieved.
    .PARAMETER Id
        Specifies the ID of the virtual switch to be retrieved.
    .EXAMPLE
        PS> Get-SdnNetAdapterEncapOverheadConfig
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [string]$Id
    )

    $switchArrayList = @()

    try {
        # enumerate each of the vmswitches that are vfp enabled
        $vfpSwitch = Get-SdnVMSwitch @PSBoundParameters -VfpEnabled
        foreach ($switch in $vfpSwitch) {
            $interfaceArrayList = @()
            $supportsEncapOverhead = $false
            $encapOverheadValue = $null
            $supportsJumboPacket = $false
            $jumboPacketValue = $null

            # enumerate each of the physical network adapters that are bound to the vmswitch
            foreach ($physicalNicIfDesc in $switch.NetAdapterInterfaceDescriptions) {

                # get the encap overhead settings for each of the network interfaces within the vm switch team
                $encapOverhead = Get-NetAdapterAdvancedProperty -InterfaceDescription $physicalNicIfDesc -RegistryKeyword "*Encapoverhead" -ErrorAction Ignore
                if ($encapoverhead) {
                    $supportsEncapOverhead = $true
                    [int]$encapOverheadValue = $encapoverhead.DisplayValue
                }

                # get the jumbo packet settings for each of the network interfaces within the vm switch team
                $jumboPacket = Get-NetAdapterAdvancedProperty -InterfaceDescription $physicalNicIfDesc -RegistryKeyword "*JumboPacket" -ErrorAction Ignore
                if ($jumboPacket) {
                    $supportsJumboPacket = $true
                    [int]$jumboPacketValue = $jumboPacket.RegistryValue[0]
                }

                $object = [PSCustomObject]@{
                    Switch                         = $switch.Name
                    Id                             = $switch.Id
                    NetAdapterInterfaceDescription = $physicalNicIfDesc
                    EncapOverheadEnabled           = $supportsEncapOverhead
                    EncapOverheadValue             = $encapOverheadValue
                    JumboPacketEnabled             = $supportsJumboPacket
                    JumboPacketValue               = $jumboPacketValue
                }

                # add each network interface to the interface array
                $interfaceArrayList += $object
            }

            # add each of the switches to the array
            $switchArrayList += $interfaceArrayList
        }

        return $switchArrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnNetAdapterRdmaConfig {
    <#
    .SYNOPSIS
        Checks numerous settings within a network adapter to validate RDMA status.
    .PARAMETER InterfaceIndex
        Interface index of the adapter for which RDMA config is to be verified.
    .EXAMPLE
        PS> Get-SdnNetAdapterRdmaConfig -InterfaceIndex 25
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [uint32]$InterfaceIndex
    )

    try {
        [System.String]$adapterType = $null
        [bool]$rdmaEnabled = $false
        [bool]$maxQueueConfigIsValid = $false
        [bool]$smbInterfaceRdmaCapable = $false
        [bool]$qosEnabled = $false
        [bool]$qosOperationalFlowControlEnabled = $false

        $rdmaAdapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex
        if ($null -eq $rdmaAdapter) {
            throw New-Object System.NullReferenceException("Adapter with interface index $InterfaceIndex was not found")
        }

        "Determining adapter type based on interface description '{0}'" -f $rdmaAdapter.InterfaceDescription | Trace-Output -Level:Verbose
        switch -Wildcard ($rdmaAdapter.InterfaceDescription) {
            'Hyper-V Virtual Ethernet Adapter*' {
                $adapterType = "vNIC"
            }

            'Microsoft Hyper-V Network Adapter*' {
                $adapterType = "vmNIC"
            }

            default {
                $adapterType = "pNIC"
            }
        }

        "Network adapter {0} (Name: {1}) is a {2}" -f $rdmaAdapter.InterfaceIndex, $rdmaAdapter.Name, $adapterType | Trace-Output -Level:Verbose

        $rdmaCapabilities = Get-NetAdapterRdma -InterfaceDescription $rdmaAdapter.InterfaceDescription
        if($null -eq $rdmaCapabilities -or $rdmaCapabilities.Enabled -ieq $false) {
            $rdmaEnabled = $false
            "Network adapter {0} is not enabled for RDMA" -f $rdmaAdapter.InterfaceIndex | Trace-Output -Level:Warning
        }
        else {
            $rdmaEnabled = $rdmaCapabilities.Enabled
        }

        if ($rdmaCapabilities.MaxQueuePairCount -eq 0 -or $rdmaCapabilities.MaxCompletionQueueCount -eq 0) {
            $maxQueueConfigIsValid = $false
            "RDMA capabilities for adapter {0} are not valid. MaxQueuePairCount and MaxCompletionQueueCount cannot be set to 0" -f $rdmaAdapter.InterfaceIndex | Trace-Output -Level:Warning
        }
        else {
            $maxQueueConfigIsValid = $true
        }

        $rdmaAdapterSmbClientNetworkInterface = Get-SmbClientNetworkInterface | Where-Object {$_.InterfaceIndex -ieq $InterfaceIndex}
        if ($null -eq $rdmaAdapterSmbClientNetworkInterface) {
            "No interfaces found within SMB Client Network Interfaces that match interface index {0}" -f $InterfaceIndex | Trace-Output -Level:Warning
        }
        else {
            if ($rdmaAdapterSmbClientNetworkInterface.RdmaCapable -eq $false) {
                $smbInterfaceRdmaCapable = $false
                "SMB did not detect network adapter {0} as RDMA capable. Make sure the adapter is bound to TCP/IP and not to other protocol like vmSwitch." -f $rdmaAdapter.InterfaceIndex | Trace-Output -Level:Warning
            }
            else {
                $smbInterfaceRdmaCapable = $true
            }
        }

        if ($adapterType -eq "vNIC") {
            "Retrieving vSwitch bound to the virtual adapter" | Trace-Output -Level:Verbose
            $virtualAdapter = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.DeviceId -eq $rdmaAdapter.DeviceID}
            $vSwitch = Get-VMSwitch -Name $virtualAdapter.SwitchName
            if ($vSwitch) {
                "Found vSwitch: {0}" -f $vSwitch.Name | Trace-Output -Level:Verbose

                $rdmaAdapters = Get-NetAdapter -InterfaceDescription $vSwitch.NetAdapterInterfaceDescriptions
                if ($rdmaAdapters) {
                    "Found the following physical adapter(s) bound to vSwitch:`r`n`n {0}" -f `
                    ($rdmaAdapters.InterfaceDescription `
                    | Select-Object @{n="Description";e={"`t$($_)"}} `
                    | Select-Object -ExpandProperty Description `
                    | Out-String ) | Trace-Output -Level:Verbose
                }
            }
        }

        if ($null -ne $rdmaAdapters -and $adapterType -ne "vmNIC") {
            "Checking if QoS/DCB/PFC are configured on each physical adapter(s)" | Trace-Output -Level:Verbose

            # set these values to $true as we are looping multiple interfaces
            # we want to ensure if one interface is false for either value, that the object is reset back to $false
            # this ensures we don't get a false positive if some interfaces are enabled vs others are disabled

            $qosEnabled = $true
            $qosOperationalFlowControlEnabled = $true

            foreach ($qosAdapter in $rdmaAdapters) {
                "Checking {0}" -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Verbose
                $qos = Get-NetAdapterQos -Name $qosAdapter.Name

                "NetAdapterQos is currently set to {0}" -f $qos.Enabled | Trace-Output -Level:Verbose
                if ($qos.Enabled -eq $false) {
                    $qosEnabled = $false
                    "QoS is not enabled for adapter {0}. This is required for RDMA over Converged Ethernet (RoCE)." -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }

                "OperationalFlowControl is currently set to {0}" -f $qos.OperationalFlowControl | Trace-Output -Level:Verbose
                if ($qos.OperationalFlowControl -eq "All Priorities Disabled") {
                    $qosOperationalFlowControlEnabled = $false
                    "Flow control priorities are disabled for adapter {0}. This is required for RDMA over Converged Ethernet (RoCE)." -f $qosAdapter.InterfaceDescription | Trace-Output -Level:Warning
                }
            }
        }

        $object = [PSCustomObject]@{
            Name                                = $rdmaAdapter.Name
            InterfaceDescription                = $rdmaAdapter.InterfaceDescription
            InterfaceIndex                      = $InterfaceIndex
            AdapterType                         = $adapterType
            MaxQueueConfigIsValid               = $maxQueueConfigIsValid
            QoSEnabled                          = $qosEnabled
            QoSOperationalFlowControlEnabled    = $qosOperationalFlowControlEnabled
            RdmaEnabled                         = $rdmaEnabled
            SMBInterfaceRdmaCapable             = $smbInterfaceRdmaCapable
        }

        return $object
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnOvsdbAddressMapping {
    <#
    .SYNOPSIS
        Gets the address mappings from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnOvsdbAddressMapping -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbAddressMapping } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-OvsdbAddressMapping
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnOvsdbFirewallRule {
    <#
    .SYNOPSIS
        Gets the firewall rules from OVSDB firewall database
    .PARAMETER RuleId
        The rule ID of the firewall rule to return. This is the InstanceID of the rule associated with accessControlLists from Network Controller.
    .PARAMETER VirtualNicId
        The virtual NIC ID of the firewall rule to return. This is the InstanceID of the Network Interface object from Network Controller.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -RuleId '2152523D-333F-4082-ADE4-107D8CA75F5B' -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbFirewallRule -VirtualNicId '2152523D-333F-4082-ADE4-107D8CA75F5B' -ComputerName 'Server01'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'RuleId')]
        [GUID]$RuleId,

        [Parameter(Mandatory = $false, ParameterSetName = 'VirtualNicId')]
        [GUID]$VirtualNicId,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RuleId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VirtualNicId')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'RuleId')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VirtualNicId')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbFirewallRule } -Credential $Credential
        }
        else {
            $results = Get-OvsdbFirewallRuleTable
        }

        # filter the results to only return the rules that match the specified parameters
        switch ($PSCmdlet.ParameterSetName) {
            'RuleId' { return ($results | Where-Object { $_.RuleId -eq $RuleId }) }
            'VirtualNicId' { return ($results | Where-Object { $_.VirtualNicId -eq $VirtualNicId }) }
            default { return $results }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnOvsdbGlobalTable {
    <#
    .SYNOPSIS
        Gets the global table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbGlobalTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbGlobalTable } -Credential $Credential
        }
        else {
            Get-OvsdbGlobalTable
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnOvsdbPhysicalPort {
    <#
    .SYNOPSIS
        Gets the physical port table results from OVSDB MS_VTEP database.
    .PARAMETER PortName
        The port name of the physical port to return.
    .PARAMETER Name
        The name of the physical port to return. This is the InstanceID the Network Interface object from Network Controller.
    .PARAMETER VMName
        The name of the virtual machine to return the physical port(s) for.
    .PARAMETER MacAddress
        The MAC address of the network interface to return the physical port(s) for.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPort -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbPhysicalPort -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'PortName')]
        [GUID]$PortName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [GUID]$Name,

        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [System.String]$VMName,

        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'PortName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'PortName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $result = Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbPhysicalPort } -Credential $Credential
        }
        else {
            $result = Get-OvsdbPhysicalPortTable
        }

        # once we have the results, filter based on the parameter set
        switch ($PSCmdlet.ParameterSetName) {
            'PortName' { return ($result | Where-Object { $_.vm_nic_port_id -eq $PortName }) }
            'Name' { return ($result | Where-Object { $_.Name -eq $Name }) }
            'VMName' { return ($result | Where-Object { $_.vm_nic_vm_name -eq $VMName }) }
            'MacAddress' {
                $macAddresswithDashes = Format-MacAddressWithDashes -MacAddress $MacAddress
                $macAddressnoDashes = Format-MacAddressNoDashes -MacAddress $MacAddress
                return ($result | Where-Object { $_.vm_nic_macaddress -eq $macAddresswithDashes -or $_.vm_nic_macaddress -eq $macAddressnoDashes })
            }
            default { return $result }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnOvsdbRouterTable {
    <#
    .SYNOPSIS
        Gets the logical router table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbRouterTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbRouterTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbRouterTable } -Credential $Credential
        }
        else {
            Get-OvsdbRouterTable
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnOvsdbUcastMacRemoteTable {
    <#
    .SYNOPSIS
        Gets the ucast mac remote table results from OVSDB.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnOvsdbUcastMacRemoteTable -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnOvsdbUcastMacRemoteTable } -Credential $Credential
        }
        else {
            Get-OvsdbUcastMacRemoteTable
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnProviderAddress {
    <#
    .SYNOPSIS
        Retrieves the Provider Address that is assigned to the computer.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER AsJob
        Switch indicating to trigger a background job to perform the operation.
    .PARAMETER PassThru
        Switch indicating to wait for background job completes and display results to current session.
    .PARAMETER Timeout
        Specify the timeout duration to wait before job is automatically terminated. If omitted, defaults to 300 seconds.
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -AsJob
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -AsJob -PassThru
    .EXAMPLE
        PS> Get-SdnProviderAddress -ComputerName 'Server01','Server02' -AsJob -PassThru -Timeout 600
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-SdnProviderAddress } -Credential $Credential `
                -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
        }
        else {
            Get-ProviderAddress
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnServerCertificate {
    <#
        .SYNOPSIS
        Returns the certificate used by the SDN Host Agent.
    #>

    [CmdletBinding()]
    param()

    try {
        $serverCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostAgentCertificateCName'
        $subjectName = "CN={0}" -f $serverCert
        $certificate = Get-SdnCertificate -Subject $subjectName -Path 'Cert:\LocalMachine\My' -NetworkControllerOid
        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVfpPortGroup {
    <#
    .SYNOPSIS
        Enumerates the groups contained within the specific Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortName
        The port name for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
    .PARAMETER Name
        Returns the specific group name. If omitted, will return all groups within the VFP layer.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Name 'SLB_GROUP_NAT_IPv4_IN'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Direction 'IN'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Type 'IPv4'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Direction 'IN' -Type 'IPv4'
    .EXAMPLE
        PS> Get-SdnVfpPortGroup -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -ComputerName 'RemoteComputer' -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [System.String]$Layer,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4','IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [System.String]$Name,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $params = @{
            PortName = $PortName
            Layer = $Layer
        }

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param ([guid]$arg0, [string]$arg1)
                Get-SdnVfpPortGroup -PortName $arg0 -Layer $arg1
            } -ArgumentList @($params.PortName, $params.Layer)
        }
        else {
            $results = Get-VfpPortGroup @params
        }


        switch ($PSCmdlet.ParameterSetName) {
            'Name' {
                return ($results | Where-Object { $_.Group -eq $Name })
            }

            'Default' {
                if ($Type) {
                    $results = $results | Where-Object {$_.Type -ieq $Type}
                }
                if ($Direction) {
                    $results = $results | Where-Object {$_.Direction -ieq $Direction}
                }

                return ($results | Sort-Object -Property Priority)
            }
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVfpPortLayer {
    <#
    .SYNOPSIS
        Enumerates the layers contained within Virtual Filtering Platform (VFP) for specified for the port.
    .PARAMETER PortName
        The Port name for the network interface
    .PARAMETER Name
        Returns the specific layer name. If omitted, will return all layers within VFP.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortLayer
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B'
    .EXAMPLE
        PS> Get-SdnVfpPortLayer -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -ComputerName SDN-HOST01 -Credential (Get-Credential)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'PortName')]
        [GUID]$PortName,

        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $params = @{
            PortName = $PortName
        }

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param([guid]$arg0)
                Get-SdnVfpPortLayer -PortName $arg0
            } -ArgumentList @($params.PortName)
        }
        else {
            $results = Get-VfpPortLayer @params
        }

        if ($Name) {
            return ($results | Where-Object { $_.Layer -eq $Name })
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVfpPortRule {
    <#
    .SYNOPSIS
        Enumerates the rules contained within the specific group within Virtual Filtering Platform (VFP) layer specified for the port.
    .PARAMETER PortName
        The port name for the network interface.
    .PARAMETER Layer
        Specify the target layer.
    .PARAMETER Group
        Specify the group layer.
    .PARAMETER Name
        Returns the specific rule name. If omitted, will return all rules within the VFP group.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN'
    .EXAMPLE
        PS> Get-SdnVfpPortRule -PortName '2152523D-333F-4082-ADE4-107D8CA75F5B' -Layer 'SLB_NAT_LAYER' -Group 'SLB_GROUP_NAT_IPv4_IN' -Name 'SLB_DEFAULT_RULE'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName,

        [Parameter(Mandatory = $true)]
        [System.String]$Layer,

        [Parameter(Mandatory = $true)]
        [System.String]$Group,

        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $params = @{
            PortName = $PortName
            Layer = $Layer
            Group = $Group
        }

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param([guid]$arg0, [string]$arg1, [string]$arg2)
                Get-SdnVfpPortRule -PortName $arg0 -Layer $arg1 -Group $arg2
            } -ArgumentList @($params.PortName, $params.Layer, $params.Group)
        }
        else {
            $results = Get-VfpPortRule @params
        }

        if ($Name) {
            return ($results | Where-Object {$_.Rule -ieq $Name -or $_.'FriendlyName' -ieq $Name})
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $port' to return back the current state of the port specified.
    .PARAMETER PortName
        The port name to return the state for.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortState -PortName 3DC59D2B-9BFE-4996-AEB6-2589BD20B559
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName,

        [Parameter(Mandatory = $false)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $params = @{
        PortName = $PortName
    }

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param ([guid]$arg0)
                Get-SdnVfpPortState -PortName $arg0
            } -ArgumentList @($params.PortName)
        }
        else {
            $results = Get-VfpPortState @params
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVfpVmSwitchPort {
    <#
    .SYNOPSIS
        Returns a list of ports from within virtual filtering platform.
    .PARAMETER PortName
        The port name of the VFP interface
    .PARAMETER VMName
        The Name of the Virtual Machine
    .PARAMETER VMID
        The ID of the Virtual Machine
    .PARAMETER MacAddress
        The MacAddress of the interface
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -ComputerName 'RemoteComputer' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -VMName 'SDN-MUX01'
    .EXAMPLE
        PS> Get-SdnVfpVmSwitchPort -VMID 699FBDA2-15A0-4D73-A6EF-9D55623A27CE
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Port')]
        [GUID]$PortName,

        [Parameter(Mandatory = $false, ParameterSetName = 'VMID')]
        [System.String]$VMID,

        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [System.String]$VMName,

        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Port')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMID')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Port')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMID')]
        [Parameter(Mandatory = $false, ParameterSetName = 'VMName')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MacAddress')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Get-SdnVfpVmSwitchPort }
        }
        else {
            $results = Get-VfpVMSwitchPort
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Port' { return ($results | Where-Object {$_.PortName -ieq $PortName}) }
            'VMID' { return ($results | Where-Object {$_.VMID -ieq $VMID}) }
            'VMName' { return ($results | Where-Object {$_.VMName -ieq $VMName}) }
            'MacAddress' {
                $MacAddress = Format-MacAddressWithDashes -MacAddress $MacAddress
                return ($results | Where-Object {$_.MacAddress -ieq $MacAddress})
            }

            default { return $results }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVMNetworkAdapter {
    <#
    .SYNOPSIS
        Retrieves the virtual machine network adapters that are allocated on a hyper-v host
    .PARAMETER All
        Specifies all virtual network adapters in the system, regardless of whether the virtual network adapter is in the management operating system or in a virtual machine.
    .PARAMETER VMName
        Specifies the name of the virtual machine whose network adapters are to be retrieved.
    .PARAMETER Name
        Specifies the name of the network adapter to be retrieved.
    .PARAMETER MacAddress
        Specifies the MAC address of the network adapter to be retrieved.
    .PARAMETER ManagementOS
        Specifies the management operating system, i.e. the virtual machine host operating system.
    .PARAMETER SwitchName
        Specifies the name of the virtual switch whose network adapters are to be retrieved. (This parameter is available only for virtual network adapters in the management operating system.)
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. To specify the local computer, type the computer name, localhost, or a dot (.). When the computer is in a different domain than the user, the fully qualified domain name is required
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02'
    .EXAMPLE
        PS> Get-SdnVMNetworkAdapter -ComputerName 'Server01','Server02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$All,

        [Parameter(Mandatory = $false)]
        [string]$VMName,

        [Parameter(Mandatory = $false)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [string]$MacAddress,

        [Parameter(Mandatory = $false)]
        [switch]$ManagementOS,

        [Parameter(Mandatory = $false)]
        [string]$SwitchName,

        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($null -eq (Get-Module -Name Hyper-V)) {
        Import-Module -Name Hyper-V -Force -ErrorAction Stop
    }

    $vmNetworkAdaptersParams = $PSBoundParameters
    [void]$vmNetworkAdaptersParams.Remove('MacAddress')
    if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
        [void]$vmNetworkAdaptersParams.Remove('Credential')
    }

    try {
        $adapters = Get-VMNetworkAdapter @vmNetworkAdaptersParams

        if ($MacAddress) {
            $macAddress = Format-SdnMacAddress -MacAddress $MacAddress
            $macAddress1 = Format-SdnMacAddress -MacAddress $MacAddress -Dashes
            $adapters = $adapters | Where-Object { $_.MacAddress -eq $MacAddress -or $_.MacAddress -eq $macAddress1 }
        }

        return ($adapters | Sort-Object -Property Name)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Retrieves the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine to be retrieved.
    .PARAMETER All
        Switch to indicate to get all the virtual machines network interfaces on the hypervisor host.
    .PARAMETER ManagementOS
        When true, displays Port Profiles of Host VNics. Otherwise displays Port Profiles of Vm VNics.
    .EXAMPLE
        Get-SdnVMNetworkAdapterPortProfile -VMName 'VM01'
    .EXAMPLE
        Get-SdnVMNetworkAdapterPortProfile -All
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'VM')]
        [System.String]$VMName,

        [Parameter(Mandatory = $false, ParameterSetName = 'VM')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Management')]
        [System.String]$Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'All')]
        [Switch]$All,

        [Parameter(Mandatory = $true, ParameterSetName = 'Management')]
        [switch]$ManagementOS
    )

    [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
    $array = @()

    try {
        $netAdapters = Get-SdnVMNetworkAdapter @PSBoundParameters
        foreach ($adapter in $netAdapters) {
            $object = [VMNetAdapterPortProfile]@{
                VMName      = $adapter.VMName
                Name        = $adapter.Name
                MacAddress  = $adapter.MacAddress
            }

            $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $adapter
            if ($currentProfile) {
                $object.ProfileId   = $currentProfile.SettingData.ProfileId
                $object.ProfileData = $currentProfile.SettingData.ProfileData
            }

            # we will typically see multiple port data values for each adapter, however the deviceid should be the same across all of the objects
            # defensive coding in place for situation where vm is not in proper state and this portdata is null
            $portData = (Get-VMSwitchExtensionPortData -VMNetworkAdapter $adapter)
            if ($portData) {
                $object.PortName = $portData[0].data.deviceid
            }

            $array += $object
        }

        return ($array | Sort-Object -Property Name)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnServerCertificate {
    <#
    .SYNOPSIS
        Generate new self-signed certificate to be used by the Hyper-V host and distributes to the Network Controller(s) within the environment.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER Path
        Specifies the file path location where a .cer file is exported automatically.
    .PARAMETER FabricDetails
        The SDN Fabric details derived from Get-SdnInfrastructureInfo.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user
    .EXAMPLE
        New-SdnServerCertificate -NotAfter (Get-Date).AddYears(1) -FabricDetails $Global:SdnDiagnostics.EnvironmentInfo
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\ServerCert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnModuleConfiguration -Role 'Server'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a Server, run this on Server.")
    }

    # ensure that the module is running as local administrator
    Confirm-IsAdmin

    try {
        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        $serverCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters' -Name 'HostAgentCertificateCName'
        $subjectName = "CN={0}" -f $serverCert
        $certificate = New-SdnSelfSignedCertificate -Subject $subjectName -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate and save the file to directory
        # This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$cerFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $subjectName.ToString().ToLower().Replace('.','_').Replace("=",'_').Trim()).cer"
        "Exporting certificate to {0}" -f $cerFilePath | Trace-Output
        $exportedCertificate = Export-Certificate -Cert $certificate -FilePath $cerFilePath -Type CERT
        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -FabricDetails $FabricDetails -ServerNodeCert -Credential $Credential

        $certObject = [PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        }

        return $certObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Set-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Configures the port profile applied to the virtual machine network interfaces.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER ProfileId
        The InstanceID of the Network Interface taken from Network Controller. If ommited, defaults to an empty GUID to enable network connectivity for non-NC managed VMs.
    .PARAMETER ProfileData
        1 = VfpEnabled, 2 = VfpDisabled, 6 = VfpEnabledDHCP. If ommited, defaults to 1.
    .PARAMETER HostVmNic
        Indicates if NIC is a host NIC. If ommited, defaults to false.
    .PARAMETER HyperVHost
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the computer that is hosting the virtual machine.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E -ProfileId <InstanceIDFromNC> -ProfileData 1
    .EXAMPLE
        Set-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E -ProfileData 2
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$VMName,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Guid]$ProfileId = [System.Guid]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Int]$ProfileData = 1,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [switch]$HostVmNic,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String]$HyperVHost,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    function Set-VMNetworkAdapterPortProfile {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, Position = 0)]
            [System.String]$VMName,

            [Parameter(Mandatory = $true, Position = 1)]
            [System.String]$MacAddress,

            [Parameter(Mandatory = $true, Position = 2)]
            [System.Guid]$ProfileId,

            [Parameter(Mandatory = $false, Position = 3)]
            [System.Int16]$ProfileData = 1,

            [Parameter(Mandatory = $false, Position = 4)]
            [switch]$HostVmNic
        )

        if ($null -eq (Get-Module -Name Hyper-V)) {
            Import-Module -Name Hyper-V -Force -ErrorAction Stop
        }

        [System.Guid]$portProfileFeatureId = "9940cd46-8b06-43bb-b9d5-93d50381fd56"
        [System.Guid]$vendorId  = "1FA41B39-B444-4E43-B35A-E1F7985FD548"
        $vmAdapterParams = @{
            VMName = $VMName
            MacAddress = $MacAddress
        }
        if ($HostVmNic) {
            $vmAdapterParams.Add('ManagementOS', $true)
        }

        $vmNic = Get-SdnVmNetworkAdapter @vmAdapterParams
        if ($null -eq $vmNic) {
            throw New-Object System.ArgumentException("Unable to locate VM $VMName with MacAddress $MacAddress")
        }

        $portProfileDefaultSetting = Get-VMSystemSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -ErrorAction Stop
        $portProfileDefaultSetting.SettingData.ProfileId = $ProfileId.ToString("B")
        $portProfileDefaultSetting.SettingData.NetCfgInstanceId = "{56785678-a0e5-4a26-bc9b-c0cba27311a3}"
        $portProfileDefaultSetting.SettingData.CdnLabelString = "TestCdn"
        $portProfileDefaultSetting.SettingData.CdnLabelId = 1111
        $portProfileDefaultSetting.SettingData.ProfileName = "Testprofile"
        $portProfileDefaultSetting.SettingData.VendorId = $vendorId.ToString("B")
        $portProfileDefaultSetting.SettingData.VendorName = "NetworkController"
        $portProfileDefaultSetting.SettingData.ProfileData = $ProfileData

        $currentProfile = Get-VMSwitchExtensionPortFeature -FeatureId $portProfileFeatureId -VMNetworkAdapter $vmNic
        if ($null -eq $currentProfile) {
            Add-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature  $portProfileDefaultSetting -VMNetworkAdapter $vmNic
        }
        else {
            "Current Settings: ProfileId [{0}] ProfileData [{1}]" -f $currentProfile.SettingData.ProfileId, $currentProfile.SettingData.ProfileData | Trace-Output

            $currentProfile.SettingData.ProfileId = $ProfileId.ToString("B")
            $currentProfile.SettingData.ProfileData = $ProfileData
            $currentProfile.SettingData.VendorId = $vendorId.ToString("B")

            Set-VMSwitchExtensionPortFeature -VMSwitchExtensionFeature $currentProfile -VMNetworkAdapter $vmNic
        }

        "Successfully created/added Port Profile for VM [{0})], Adapter [{1}], PortProfileId [{2}], ProfileData [{3}]" -f $vmNic.VMName, $vmNic.Name, $ProfileId.ToString(), $ProfileData | Trace-Output
    }

    $splat = @{
        VMName = $VMName
        MacAddress = $MacAddress
        ProfileId = $ProfileId
        ProfileData = $ProfileData
        HostVmNic = $HostVmNic
    }

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                Invoke-PSRemoteCommand -ComputerName $HyperVHost -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][String]$param1,
                        [Parameter(Position = 1)][String]$param2,
                        [Parameter(Position = 2)][Guid]$param3,
                        [Parameter(Position = 3)][Int]$param4,
                        [Parameter(Position = 4)][Switch]$param5
                    )

                    # we need to call the exported function Set-VMNetworkAdapterPortProfile
                    Set-SdnVMNetworkAdapterPortProfile -VMName $param1 -MacAddress $param2 -ProfileId $param3 -ProfileData $param4
                } -ArgumentList @($splat.VMName, $splat.MacAddress, $splat.ProfileId, $splat.ProfileData, $splat.$HostVmNic)
            }
            'Local' {
                # we can call the function directly
                Set-VMNetworkAdapterPortProfile @splat
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Show-SdnVfpPortConfig {
    <#
    .SYNOPSIS
        Enumerates the VFP layers, groups and rules contained within Virtual Filtering Platform (VFP) for the specified port.
    .PARAMETER PortName
        The port name for the network interface.
    .PARAMETER Direction
        Specify the direction
    .PARAMETER Type
        Specifies an array of IP address families. The cmdlet gets the configuration that matches the address families
    .EXAMPLE
        PS Show-SdnVfpPortConfig -PortName 8440FB77-196C-402E-8564-B0EF9E5B1931
    .EXAMPLE
        PS> Show-SdnVfpPortConfig -PortName 8440FB77-196C-402E-8564-B0EF9E5B1931 -Direction IN
    .EXAMPLE
        PS> Show-SdnVfpPortConfig -PortName 8440FB77-196C-402E-8564-B0EF9E5B1931 -Direction IN -Type IPv4
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [GUID]$PortName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IPv4','IPv6')]
        [System.String]$Type,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [ValidateSet('IN','OUT')]
        [System.String]$Direction
    )

    try {
        $vfpLayers = Get-SdnVfpPortLayer -PortName $PortName
        if ($null -eq $vfpLayers) {
            "Unable to locate PortName {0}" -f $PortName | Trace-Output -Level:Error
            return $null
        }

        foreach ($layer in $vfpLayers) {
            "== Layer: {0} ==" -f $layer.LAYER | Write-Host -ForegroundColor:Magenta

            if ($Direction) {
                $vfpGroups = Get-SdnVfpPortGroup -PortName $PortName -Layer $layer.LAYER -Direction $Direction
            }
            else {
                $vfpGroups = Get-SdnVfpPortGroup -PortName $PortName -Layer $layer.LAYER
            }

            if ($Type) {
                $vfpGroups = $vfpGroups | Where-Object {$_.Type -ieq $Type}
            }

            foreach ($group in $vfpGroups) {
                "== Group: {0} ==" -f $group.GROUP | Write-Host -ForegroundColor:Yellow
                Get-SdnVfpPortRule -PortName $PortName -Layer $layer.LAYER -Group $group.GROUP | Format-Table -AutoSize
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Start-SdnServerCertificateRotation {
    <#
    .SYNOPSIS
        Performs a certificate rotation operation for the Servers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action on the Server and Network Controller nodes. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPath
        Path directory where certificate(s) .pfx files are located for use with certificate rotation.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include appropriate certificate thumbprints for server nodes.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [System.String]$CertPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [hashtable]$CertRotateConfig,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [switch]$Force
    )

    # these are not yet supported and will take a bit more time to implement as it touches on core framework for rotate functionality
    # however majority of the environments impacted are using sdnexpress which leverage self-signed certificates.
    if ($CertRotateConfig -or $CertPath) {
        "This feature is not yet supported and is under development. Please use -GenerateCertificate or reference {0} for manual steps." `
        -f  'https://learn.microsoft.com/en-us/azure-stack/hci/manage/update-network-controller-certificates?tabs=manual-renewal' | Trace-Output -Level:Warning
        return
    }

    # ensure that the module is running as local administrator
    Confirm-IsAdmin

    $array = @()
    $ncRestParams = @{
        NcUri = $null
    }
    $putRestParams = @{
        Body = $null
        Content = "application/json; charset=UTF-8"
        Headers = @{"Accept"="application/json"}
        Method = 'Put'
        Uri = $null
        UseBasicParsing = $true
    }
    $confirmStateParams = @{
        TimeoutInSec = 600
        UseBasicParsing = $true
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        $putRestParams.Add('Certificate', $NcRestCertificate)
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        $putRestParams.Add('Credential', $NcRestCredential)
    }
    $confirmStateParams += $restCredParam


    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        if ([String]::IsNullOrEmpty($CertPath)) {
            [System.String]$CertPath = "$(Get-WorkingDirectory)\ServerCert_{0}" -f (Get-FormattedDateTimeUTC)

            if (-NOT (Test-Path -Path $CertPath -PathType Container)) {
                $null = New-Item -Path $CertPath -ItemType Directory -Force
            }
        }

        [System.IO.FileSystemInfo]$CertPath = Get-Item -Path $CertPath -ErrorAction Stop
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @restCredParam -ErrorAction Stop
        if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
            throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
        }

        $ncRestParams.NcUri = $sdnFabricDetails.NcUrl
        $servers = Get-SdnServer @ncRestParams -ErrorAction Stop

        # before we proceed with anything else, we want to make sure that all the Network Controllers and Servers within the SDN fabric are running the current version
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ErrorAction Stop
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.Server -Credential $Credential -ErrorAction Stop

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            # retrieve the corresponding managementAddress from each of the server resources
            # and invoke remote operation to the server to generate the self-signed certificate
            foreach ($server in $servers) {
                $serverConnection = $server.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }
                $managementAddress = $serverConnection.managementAddresses[0]

                $serverCert = Invoke-PSRemoteCommand -ComputerName $managementAddress -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][DateTime]$param1,
                        [Parameter(Position = 1)][PSCredential]$param2,
                        [Parameter(Position = 2)][String]$param3,
                        [Parameter(Position = 3)][System.Object]$param4
                    )

                    New-SdnServerCertificate -NotAfter $param1 -Credential $param2 -Path $param3 -FabricDetails $param4
                } -ArgumentList @($NotAfter, $Credential, $CertPath.FullName, $sdnFabricDetails)

                $array += [PSCustomObject]@{
                    ManagementAddress = $managementAddress
                    ResourceRef = $server.resourceRef
                    Certificate = $serverCert.Certificate
                }
            }
        }

        # loop through all the objects to perform PUT operation against the server resource
        # to update the base64 encoding for the certificate that NC should use when communicating with the server resource
        foreach ($obj in $array) {
            "Updating certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            $server = Get-SdnResource @ncRestParams -ResourceRef $obj.ResourceRef
            $encoding = [System.Convert]::ToBase64String($obj.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

            if ($server.properties.certificate) {
                $server.properties.certificate = $encoding
            }
            else {
                # in instances where the certificate property does not exist, we will need to add it
                # this typically will occur if converting from CA issued certificate to self-signed certificate
                $server.properties | Add-Member -MemberType NoteProperty -Name 'certificate' -Value $encoding -Force
            }
            $putRestParams.Body = ($server | ConvertTo-Json -Depth 100)

            $endpoint = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $server.resourceRef
            $putRestParams.Uri = $endpoint

            $null = Invoke-RestMethodWithRetry @putRestParams
            if (-NOT (Confirm-ProvisioningStateSucceeded -NcUri $putRestParams.Uri @confirmStateParams)) {
                throw New-Object System.Exception("ProvisioningState is not succeeded")
            }
            else {
                "Successfully updated the certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            }

            # after we have generated the certificates and updated the servers to use the new certificate
            # we will want to go and locate certificates that may conflict with the new certificate
            "Checking certificates on {0} that match {1}" -f $obj.managementAddress, $obj.Certificate.Subject | Trace-Output
            $certsToExamine = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                param([Parameter(Mandatory = $true)]$param1)
                $certs = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject $param1.Subject
                if ($certs.Count -ge 2) {
                    $certToRemove = $certs | Where-Object {$_.Thumbprint -ine $param1.Thumbprint}

                    return $certToRemove
                }
            } -ArgumentList $obj.Certificate

            if ($certsToExamine) {
                "`nMultiple certificates detected for Subject: {0}. Examine the certificates and cleanup if no longer needed." -f $obj.Certificate.Subject | Trace-Output -Level:Warning
                foreach ($cert in $certsToExamine) {
                    "`t[{0}] Thumbprint: {1}" -f $cert.PSComputerName, $cert.Thumbprint | Trace-Output -Level:Warning
                }

                Write-Host "" # insert empty line for better readability
            }

            # restart nchostagent on server
            $null = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                Restart-Service -Name NcHostAgent -Force
            }
        }

        "Certificate rotation for Servers has completed" | Trace-Output -Level:Success
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-SdnProviderAddressConnectivity {
    <#
    .SYNOPSIS
        Tests whether jumbo packets can be sent between the provider addresses on the current host to the remote provider addresses defined.
    .PARAMETER ProviderAddress
        The IP address assigned to a hidden network adapter in a non-default network compartment.
    .EXAMPLE
        PS> Test-SdnProviderAddressConnectivity -ProviderAddress (Get-SdnProviderAddress -ComputerName 'Server01','Server02').ProviderAddress
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ProviderAddress
    )

    $maxEncapOverhead = 160
    $defaultMTU = 1500
    $icmpHeader = 28

    $jumboPacket = ($maxEncapOverhead + $defaultMTU) - $icmpHeader
    $standardPacket = $defaultMTU - $icmpHeader
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        $sourceProviderAddress = (Get-ProviderAddress).ProviderAddress
        if ($null -eq $sourceProviderAddress) {
            return $null
        }

        $compartmentId = (Get-NetCompartment | Where-Object { $_.CompartmentDescription -ieq 'PAhostVNic' }).CompartmentId
        if ($null -eq $compartmentId) {
            "No compartment that matches description PAhostVNic" | Trace-Output -Level:Warning
            return $null
        }

        foreach ($srcAddress in $sourceProviderAddress) {
            if ($srcAddress -ilike "169.*") {
                # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                "Skipping validation of {0} as it's an APIPA address" -f $srcAddress | Trace-Output -Level:Verbose
                continue
            }

            foreach ($dstAddress in $ProviderAddress) {
                if ($dstAddress -ilike "169.*") {
                    # if the PA address is an APIPA, it's an indication that host has been added to SDN data plane, however no tenant workloads have yet been provisioned onto the host
                    "Skipping validation of {0} as it's an APIPA address" -f $dstAddress | Trace-Output -Level:Verbose
                    continue
                }

                "Testing connectivity between {0} and {1}" -f $srcAddress, $dstAddress | Trace-Output -Level:Verbose
                $results = Test-Ping -DestinationAddress $dstAddress -SourceAddress $srcAddress -CompartmentId $compartmentId -BufferSize $jumboPacket, $standardPacket -DontFragment
                [void]$arrayList.Add($results)
            }
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Test-SdnVfpPortTuple {
    <#
    .SYNOPSIS
        Simulates the processing of a packet by the Virtual Filtering Platform (VFP) for a specific port.
    .PARAMETER PortName
        The name of the VFP switch port.
    .PARAMETER Direction
        The direction of the traffic.
    .PARAMETER SourceIP
        The source IP address relative to the direction of the traffic.
    .PARAMETER SourcePort
        The source port relative to the direction of the traffic.
    .PARAMETER DestinationIP
        The destination IP address relative to the direction of the traffic.
    .PARAMETER DestinationPort
        The destination port relative to the direction of the traffic.
    .PARAMETER Protocol
        The protocol to use for the test.
    .EXAMPLE
        PS> Test-SdnVfpPortTuple -PortName 86650519-25b4-43a0-bae6-7f7a4561c8d9 -Direction OUT -Protocol TCP -SourceIP 10.0.0.6 -SourcePort 55555 -DestinationIP 10.0.0.9 -DestinationPort 443
    .EXAMPLE
        PS> Test-SdnVfpPortTuple -PortName 86650519-25b4-43a0-bae6-7f7a4561c8d9 -Direction IN -Protocol TCP -SourceIP 10.0.0.9 -SourcePort 443 -DestinationIP 10.0.0.6 -DestinationPort 55555
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$PortName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('IN','OUT')]
        [String]$Direction,

        [Parameter(Mandatory = $true)]
        [ipaddress]$SourceIP,

        [Parameter(Mandatory = $true)]
        [int]$SourcePort,

        [Parameter(Mandatory = $true)]
        [ipaddress]$DestinationIP,

        [Parameter(Mandatory = $true)]
        [int]$DestinationPort,

        [Parameter(Mandatory = $false)]
        [ValidateSet('TCP','UDP')]
        [String]$Protocol = 'TCP'
    )

    # convert the protocol to the appropriate ID
    switch ($Protocol) {
        'TCP' {
            $protocolID = 6
        }
        'UDP' {
            $protocolID = 17
        }
    }

    try {
        # make sure the port exists otherwise throw an exception
        $vfpSwitchPort = Get-SdnVfpVmSwitchPort -PortName $PortName -ErrorAction Stop
        if ($null -ieq $vfpSwitchPort) {
            throw New-Object System.Exception("Unable to locate VFP switch port $PortName")
        }

        # command is structured as follows:
        # vfpctrl /port <portname> /process-tuples '<protocolId> <sourceIP> <sourcePort> <destinationIP> <destinationPort> <direction> <flags>'
        # protocolId: 6 = TCP, 17 = UDP
        # direction: 1 = IN, 2 = OUT
        # SourceIP: Source IP address or direction of the traffic relative to the direction
        # SourcePort: Source port or direction of the traffic relative to the direction
        # DestinationIP: Destination IP address or direction of the traffic relative to the direction
        # DestinationPort: Destination port or direction of the traffic relative to the direction
        # flags: 1 = TCP SYN, 2 = Monitoring Ping
        $cmd = "vfpctrl /port $PortName /process-tuples '$protocolId $SourceIP $SourcePort $DestinationIP $DestinationPort $Direction 1'"
        Invoke-Expression $cmd
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnVMSwitch {
    <#
    .SYNOPSIS
        Gets virtual switches from the hypervisor.
    .PARAMETER Name
        Specifies the name of the virtual switch to be retrieved.
    .PARAMETER Id
        Specifies the ID of the virtual switch to be retrieved.
    .PARAMETER VfpEnabled
        Specifies whether the virtual switch has VFP enabled.
    .EXAMPLE
        PS> Get-SdnVMSwitch -Name 'Virtual Switch'
    .EXAMPLE
        PS> Get-SdnVMSwitch -Id '8440FB77-196C-402E-8564-B0EF9E5B1931'
    .EXAMPLE
        PS> Get-SdnVMSwitch -VfpEnabled
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Name')]
        [string]$Name,

        [Parameter(Mandatory = $true, ParameterSetName = 'Id')]
        [string]$Id,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Id')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Name')]
        [switch]$VfpEnabled
    )

    Confirm-IsServer
    if ($PSBoundParameters.ContainsKey('VfpEnabled')) {
        [void]$PSBoundParameters.Remove('VfpEnabled')
    }

    $array = @()
    try {
        $vmSwitch = Get-VMSwitch @PSBoundParameters
        foreach ($switch in $vmSwitch) {
            if ($VfpEnabled) {
                $vfpExtension = $switch.Extensions | Where-Object { $_.Name -eq 'Microsoft Azure VFP Switch Extension' }
                if ($vfpExtension.Enabled -ieq $true) {
                    $array += $switch
                }
            }
            else {
                $array += $switch
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    return $array
}

function Repair-SdnVMNetworkAdapterPortProfile {
    <#
    .SYNOPSIS
        Repairs the port profile applied to the virtual machine network interfaces.
    .DESCRIPTION
        This cmdlet repairs the port profile applied to the virtual machine network interfaces by retrieving the network interface from Network Controller and applying the port profile to the VM network adapter.
    .PARAMETER VMName
        Specifies the name of the virtual machine.
    .PARAMETER MacAddress
        Specifies the MAC address of the VM network adapter.
    .PARAMETER NcUri
        Specifies the URI of the Network Controller REST API.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. If omitted, the current user is used.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
    .PARAMETER HyperVHost
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the computer that is hosting the virtual machine.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action on the HyperVHost. The default is the current user. If omitted, the current user is used.
    .EXAMPLE
        Repair-SdnVMNetworkAdapterPortProfile -VMName 'TestVM01' -MacAddress 001DD826100E -NcUri 'https://nc.contoso.com' -HyperVHost 'Contoso-N01'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VMName,

        [Parameter(Mandatory = $true)]
        [System.String]$MacAddress,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $true)]
        [System.String]$HyperVHost,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($PSBoundParameters.ContainsKey('NcRestCertificate') -and $PSBoundParameters.ContainsKey('NcRestCredential')) {
        throw "NcRestCertificate and NcRestCredential are mutually exclusive"
    }

    $repairRequired = $false
    $ncRestParams = @{
        NcUri    = $NcUri
        Resource = 'NetworkInterfaces'
    }
    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
    }
    else {
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
    }

    $repairPortProfileParams = @{
        VMName      = $VMName
        MacAddress  = [System.String]::Empty
        ProfileId   = [System.Guid]::Empty
        ProfileData = 2
    }

    try {
        # format the mac address to match the format used by Network Controller
        # then invoke request to retrieve the network interfaces that match the MAC address
        # we need the InstanceId of the network interface
        $formattedMacAddress = Format-SdnMacAddress -MacAddress $MacAddress
        $networkInterface = Get-SdnResource @ncRestParams -ErrorAction Stop | Where-Object { $_.properties.privateMacAddress -eq $formattedMacAddress }
        if ($null -eq $networkInterface) {
            throw New-Object System.ArgumentException("Unable to locate NetworkInterface with MAC Address $formattedMacAddress.")
        }

        # throw an exception if there are multiple network interfaces with the same MAC address
        # as this is not expected and will cause other issues in the environment
        if ($networkInterface.Count -gt 1) {
            throw New-Object System.ArgumentException("Multiple networkInterface found with MAC Address $formattedMacAddress. Please ensure that the MAC address is unique across the environment.")
        }

        # we want to ensure that the network interface is not a load balancer mux interface
        # as we do not support this currently
        if ($networkInterface.properties.loadBalancerMuxExternal -or $networkInterface.properties.loadBalancerMuxInternal -or $networkInterface.properties.gateway) {
            throw New-Object System.NotSupportedException("NetworkInterface $($networkInterface.resourceRef) with MAC Address $formattedMacAddress is a Gateway or LoadBalancerMux interface and cannot be repaired using this cmdlet.")
        }

        # we will need to determine the port profile settings that we want to apply to the VM network adapter
        # this can be determined by looking at the IP configuration of the network interface
        # LNETs w/ DHCP enabled workloads will have ProfileData set to 6
        # else we would set it to 1 (VfpEnabled)
        $ipConfig = $networkInterface.properties.ipConfigurations[0]
        if ($ipConfig.properties.privateIPAllocationMethod -ieq "Unmanaged" -and $ipConfig.properties.subnet.resourceRef -ilike "/logicalNetworks/*") {
            $repairPortProfileParams.ProfileData = 6
        }
        else {
            $repairPortProfileParams.ProfileData = 1
        }

        $repairPortProfileParams.MacAddress = $formattedMacAddress
        $repairPortProfileParams.ProfileId = $networkInterface.InstanceId

        # check to see if the Hyper-V host is local or remote host
        if (Test-ComputerNameIsLocal -ComputerName $HyperVHost) {
            $vmNetworkAdapters = Get-SdnVMNetworkAdapterPortProfile -VMName $VMName -ErrorAction Stop
            $currentPortProfileSettings = $vmNetworkAdapters | Where-Object {$_.MacAddress -eq $formattedMacAddress}
        }
        else {
            $repairPortProfileParams.Add('HyperVHost', $HyperVHost)
            $repairPortProfileParams.Add('Credential', $Credential)

            $currentPortProfileSettings = Invoke-SdnCommand -ComputerName $HyperVHost -Credential $Credential -ScriptBlock {
                param($vmName, $macAddress)

                $vmNetworkAdapters = Get-SdnVMNetworkAdapterPortProfile -VMName $vmName
                return ($vmNetworkAdapters | Where-Object {$_.MacAddress -eq $macAddress})
            } -ArgumentList @($VMName, $formattedMacAddress) -ErrorAction Stop
        }
        if ($null -ieq $currentPortProfileSettings) {
            throw New-Object System.ArgumentException("Unable to locate Port Profile for VM $VMName with MAC Address $formattedMacAddress.")
        }

        # ensure that the profile id matches the instance id of the networkinterface
        $formattedCurrentProfileId = [System.Guid]::Parse($currentPortProfileSettings.ProfileId).Guid
        if ($formattedCurrentProfileId -ne $repairPortProfileParams.ProfileId) {
            $repairPortProfileParams.ProfileId = $networkInterface.InstanceId
            "Current ProfileId [{0}] does not match expected ProfileId [{1}]." -f $formattedCurrentProfileId, $repairPortProfileParams.ProfileId | Trace-Output -Level:Information
            $repairRequired = $true
        }

        # ensure that the profile data matches what we expect
        if ($currentPortProfileSettings.ProfileData -ne $repairPortProfileParams.ProfileData) {
            "Current ProfileData [{0}] does not match expected ProfileData [{1}]." -f $currentPortProfileSettings.ProfileData, $repairPortProfileParams.ProfileData | Trace-Output -Level:Information
            $repairRequired = $true
        }

        if ($repairRequired) {
            "Repairing Port Profile for VM $VMName with MAC Address $formattedMacAddress." | Trace-Output
            Set-SdnVMNetworkAdapterPortProfile @repairPortProfileParams
        }
        else {
            "Port Profile for VM $VMName with MAC Address $formattedMacAddress is already in the correct state." | Trace-Output -Level:Information
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
