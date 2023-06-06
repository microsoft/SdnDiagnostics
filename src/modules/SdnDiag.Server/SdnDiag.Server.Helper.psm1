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
    [guid]$Description #maps to the description property of the Logical_Router table of ms_vtep database
    [string]$EnableLogicalRouter # maps to the enable_logical_router property of the Logical_Router table of ms_vtep database
    [guid]$VirtualNetworkId # maps to the name property of the Logical_Switch table of ms_vtep database
    [string[]]$StaticRoutes # maps to the static_routes property of the Logical_Router table of ms_vtep database
    [string[]]$SwitchBinding # maps to the switch_binding property of the Logical_Router table of ms_vtep database
}

class OvsdbPhysicalPort : OvsdbCore {
    [string]$Description
    [string]$Name
}
