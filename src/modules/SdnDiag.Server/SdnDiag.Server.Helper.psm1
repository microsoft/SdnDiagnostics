# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
    [string]$VirtualSwitchId # maps to the name property of the Logical_Switch table of ms_vtep database
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

class OvsdbPhysicalPort : OvsdbCore {
    [string]$Description
    [string]$Name
}

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
    [int64]$PacketsSent
    [int64]$PacketsReceived
    [int64]$IngressPacketDrops
    [int64]$EgressPacketDrops
    [int64]$IngressVfpDrops
    $IngressPacketDropType = [DropStatistics]::new()
    [int64]$EgressVfpDrops
    $EgressPacketDropType = [DropStatistics]::new()
}

class VmNicStatistics {
    [int64]$InterruptsReceived
    [int64]$PendingLinkChange
    [int64]$RingBufferFullErrors
    [int64]$PendingRoutedPackets
    [int64]$InsufficientReceiveBuffers
    [int64]$InsufficientSendBuffers
    [int64]$InsufficientRndisOperations
    [int64]$QuotaExceeded
    [int64]$VspPaused
    [int64]$SendBufferAllocationCount
    [int64]$SendBufferAllocationSize
    [int64]$ReceiveBufferAllocationCount
    [int64]$ReceiveBufferAllocationSize
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
