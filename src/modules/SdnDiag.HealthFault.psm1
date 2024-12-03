# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.FC.psm1
Import-Module $PSScriptRoot\SdnDiag.NetworkController.SF.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

class SdnFaultInfo {
    [datetime] $OccurrenceTime
    [string] $KeyFaultingObjectDescription
    [string] $KeyFaultingObjectID
    [string] $KeyFaultingObjectType
    [string] $FaultingObjectLocation
    [string] $FaultDescription
    [string] $FaultActionRemediation
}


##########################
#### FAULT HELPERS #######
##########################

# pInvoke definition for fault APIs
$signature=@'
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

function CreateorUpdateFault {
    param(
        [SdnFaultInfo] $Fault,
        [switch] $Verbose
    )

    InitFaults

    if($Verbose) {
        Write-Host "CreateorUpdateFault $($Fault.KeyFaultingObjectDescription) $($Fault.KeyFaultingObjectID) $($Fault.KeyFaultingObjectType)"
    }
    
    if([string]::IsNullOrEmpty($script:subsystemId)) {
        $script:subsystemId = (get-storagesubsystem Cluster*).UniqueId
        $script:entityTypeSubSystem = "Microsoft.Health.EntityType.Subsystem"
    }  
    [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyFault( `
        $Fault.KeyFaultingObjectDescription, # $entityType, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $Fault.KeyFaultingObjectDescription, # "E Desc", `
        $Fault.FaultingObjectLocation, # $entityLocation, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $HCI_MODIFY_FAULT_ACTION_MODIFY, #action `
        $Fault.KeyFaultingObjectType, # $faultType, `
        $HEALTH_URGENCY_UNHEALTHY, # `
        "Fault Title", `
        $Fault.FaultDescription, # fault description
        $Fault.FaultActionRemediation, # fault remediation action
        $HCI_MODIFY_FAULT_FLAG_NONE)

    [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyRelationship(
        $Fault.KeyFaultingObjectDescription, # $entityType, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $Fault.KeyFaultingObjectDescription,  # $entityDescription
        $Fault.FaultingObjectLocation, # $entityLocation, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $HCI_MODIFY_RELATIONSHIP_ACTION_MODIFY, `
        $script:entityTypeSubSystem, `
        $script:subsystemId, `
        $null, `
        $null, `
        $script:subsystemId, `
        "TestGroupKey", `
        $HEALTH_URGENCY_UNHEALTHY, `
        $HEALTH_RELATIONSHIP_COLLECTION, `
        $HCI_MODIFY_RELATIONSHIP_FLAG_NONE)
}

function DeleteFault {
    param(
        [SdnFaultInfo] $Fault,
        [switch] $Verbose
    )

    InitFaults

    if($Verbose) {
        Write-Host "DeleteFault $($Fault.KeyFaultingObjectDescription) $($Fault.KeyFaultingObjectID) $($Fault.KeyFaultingObjectType)"
    }

    if([string]::IsNullOrEmpty($script:subsystemId)) {
        $script:subsystemId = (get-storagesubsystem Cluster*).UniqueId
        $script:entityTypeSubSystem = "Microsoft.Health.EntityType.Subsystem"
    }  
    [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyFault( `
        $Fault.KeyFaultingObjectDescription, # $entityType, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $Fault.KeyFaultingObjectDescription, # "E Desc", `
        $Fault.FaultingObjectLocation, # $entityLocation, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $HCI_MODIFY_FAULT_ACTION_REMOVE, #action `
        $Fault.KeyFaultingObjectType, # $faultType, `
        $HEALTH_URGENCY_UNHEALTHY, # `
        "Fault Title", `
        $Fault.FaultDescription, # fault description
        $Fault.FaultActionRemediation, # fault remediation action
        $HCI_MODIFY_FAULT_FLAG_NONE)
}

function GetAllFaults {

}
function InitFaults {    

    if (-not ("Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils" -as [type])) {
        Add-Type -MemberDefinition $signature -Name "HciHealthUtils" -Namespace "Microsoft.NetworkHud.FunctionalTests.Module" | Out-Null
        New-Variable -Name 'HCI_MODIFY_FAULT_ACTION_MODIFY' -Scope 'Global' -Force -Value 0 -Option Constant
        New-Variable -Name 'HCI_MODIFY_FAULT_ACTION_REMOVE' -Scope 'Global' -Force -Value 1 -Option Constant
    
        New-Variable -Name 'HCI_MODIFY_RELATIONSHIP_ACTION_MODIFY' -Scope 'Global' -Force -Value 0 -Option Constant
        New-Variable -Name 'HCI_MODIFY_RELATIONSHIP_ACTION_REMOVE' -Scope 'Global' -Force -Value 1 -Option Constant
    
        New-Variable -Name 'HEALTH_RELATIONSHIP_UNKNOWN' -Scope 'Global' -Force -Value 0 -Option Constant
        New-Variable -Name 'HEALTH_RELATIONSHIP_COMPOSITION' -Scope 'Global' -Force -Value 1 -Option Constant
        New-Variable -Name 'HEALTH_RELATIONSHIP_CONTAINMENT' -Scope 'Global' -Force -Value 2 -Option Constant
        New-Variable -Name 'HEALTH_RELATIONSHIP_COLLECTION' -Scope 'Global' -Force -Value 3 -Option Constant
    
        New-Variable -Name 'HEALTH_URGENCY_UNKNOWN' -Scope 'Global' -Force -Value 255  -Option Constant
        New-Variable -Name 'HEALTH_URGENCY_HEALTHY' -Scope 'Global' -Force -Value 0  -Option Constant
        New-Variable -Name 'HEALTH_URGENCY_WARNING' -Scope 'Global' -Force -Value 1  -Option Constant
        New-Variable -Name 'HEALTH_URGENCY_UNHEALTHY' -Scope 'Global' -Force -Value 2 -Option Constant
    
        New-Variable -Name 'HCI_MODIFY_FAULT_FLAG_NONE' -Scope 'Global' -Force -Value 0 -Option Constant
        New-Variable -Name 'HCI_MODIFY_RELATIONSHIP_FLAG_NONE' -Scope 'Global' -Force -Value 0 -Option Constant
    }
}

function IsSdnFcClusterServiceRole {
    param([string] $ServiceName)
    
    # Define the list of valid service roles
    $validServiceRoles = @(
        "ApiService",
        "ControllerService",
        "FirewallService",
        "FnmService",
        "GatewayManager",
        "ServiceInsertion",
        "VSwitchService"
    )

    # Check if the provided service role name is in the list
    return $validServiceRoles -contains $ServiceName
}
function IsSdnService {
    param([string] $serviceName) 
    return $serviceName -in @( "NCHostAgent", "SlbHostAgent")
}
function IsCurrentNodeClusterOwner {
    $activeNode = Get-ClusterResource  | ? {$_.OwnerGroup -eq "Cluster Group" -and $_.ResourceType -eq "IP Address" -and $_.Name -eq "Cluster IP Address"}
    if( $null -eq $activeNode ) {
        # todo : generate a fault on failing to generate a fault (or switch to different algorithm for picking the primary node)
        return $false
    } 
    if($activeNode.OwnerNode -eq $env:COMPUTERNAME) {
        return $true
    } else {
        return $false
    }
}

