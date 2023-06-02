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
    hidden [guid]$uuid
}

class OvsdbFirewallRule : OvsdbCore {
    [string]$action
    [string]$direction
    [string]$logging_state
    [int]$priority
    [string]$protocols
    [string]$src_ip_addresses
    [string]$src_ports
    [string]$dst_ip_addresses
    [string]$dst_ports
    [guid]$rule_id
    [string]$rule_state
    hidden [String]$rule_type
    [guid]$vnic_id
}
