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

function ValidateFault {
    param(
        [SdnFaultInfo] $Fault
    )

    if([string]::IsNullOrEmpty($Fault.KeyFaultingObjectDescription)) {
        throw "KeyFaultingObjectDescription is required"
    }

    if([string]::IsNullOrEmpty($Fault.KeyFaultingObjectID)) {
        throw "KeyFaultingObjectID is required"
    }

    if([string]::IsNullOrEmpty($Fault.KeyFaultingObjectType)) {
        throw "KeyFaultingObjectType is required"
    }
}
function LogWmiHealthFault {
    param(
        [object] $fault
    )
    Write-Host "WmiFault:"
    Write-Host "    (FaultId) $($fault.FaultId)"
    Write-Host "    (FaultingObjectDescription) $($fault.FaultingObjectDescription)"
    Write-Host "    (FaultingObjectLocation) $($fault.FaultingObjectLocation)"
    Write-Host "    (FaultingObjectType) $($fault.FaultingObjectType)"
    Write-Host "    (FaultingObjectUniqueId) $($fault.FaultingObjectUniqueId)"
    Write-Host "    (FaultTime) $($fault.FaultTime)"
    Write-Host "    (FaultType) $($fault.FaultType)"
    Write-Host "    (Reason) $($fault.Reason)"    
}
function CreateorUpdateFault {
    param(
        [SdnFaultInfo] $Fault,
        [switch] $Verbose
    )

    ValidateFault -Fault $Fault

    InitFaults

    if($Verbose) {
        Write-Host "CreateorUpdateFault:"
        Write-Host "    (KeyFaultingObjectDescription) $($Fault.KeyFaultingObjectDescription)"
        Write-Host "    (KeyFaultingObjectID) $($Fault.KeyFaultingObjectID) "
        Write-Host "    (KeyFaultingObjectType) $($Fault.KeyFaultingObjectType)"
        Write-Host "    (FaultingObjectLocation) $($Fault.FaultingObjectLocation)"
        Write-Host "    (FaultDescription) $($Fault.FaultDescription)"
        Write-Host "    (FaultActionRemediation) $($Fault.FaultActionRemediation)"
    }
    
    if([string]::IsNullOrEmpty($script:subsystemId)) {
        $script:subsystemId = (get-storagesubsystem Cluster*).UniqueId
        $script:entityTypeSubSystem = "Microsoft.Health.EntityType.Subsystem"
    }  
    $retValue = [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyFault( `
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
        $HCI_MODIFY_FAULT_FLAG_NONE)  *> $null

        $retValue = [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyRelationship(
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
        $HCI_MODIFY_RELATIONSHIP_FLAG_NONE) | Out-Null
}

<#
    .SYNOPSIS
    Deletes a fault by its key properties, those with empty or a * will be ignored while comaprison for a broader clear operation

    .PARAMETER KeyFaultingObjectDescription
    The description of the faulting object

    .PARAMETER KeyFaultingObjectID
    The unique ID of the faulting object

    .PARAMETER KeyFaultingObjectType
    The type of the faulting object

    .PARAMETER FaultingObjectLocation
    The location of the faulting object
#>
function DeleteFaultBy {
    param(
        [string] $KeyFaultingObjectDescription,
        [string] $KeyFaultingObjectID,
        [string] $KeyFaultingObjectType,
        [string] $FaultingObjectLocation,
        [switch] $Verbose
    )

    if($Verbose) {
        Write-Host "DeleteFaultByinvoked: "
        Write-Host "    (KeyFaultingObjectDescription) $($KeyFaultingObjectDescription)"
        Write-Host "    (KeyFaultingObjectID) $($KeyFaultingObjectID)"
        Write-Host "    (KeyFaultingObjectType) $($KeyFaultingObjectType)"
        Write-Host "    (FaultingObjectLocation) $($FaultingObjectLocation)"
    }

    InitFaults

    # get all the system faults
    $faults = Get-HealthFault
    [bool] $match = $true
    [string[]] $matchFaultsId = @()
    foreach($fault in $faults) {
        # delete the one(s) that match the filter
        # KeyFaultingObjectDescription, KeyFaultingObjectID, KeyFaultingObjectType may be empty , in which case
        # we will not consider them for comparison
        $match = [string]::IsNullOrEmpty($KeyFaultingObjectDescription) -or $KeyFaultingObjectDescription -eq "*" -or  `
            $KeyFaultingObjectDescription -eq $fault.FaultingObjectDescription;
        Write-Host "KeyFaultingObjectDescription $match "

        $match = $match -and ([string]::IsNullOrEmpty($KeyFaultingObjectID) -or $KeyFaultingObjectID -eq "*" -or `
            $KeyFaultingObjectID -eq $fault.FaultingObjectUniqueId)
        Write-Host "KeyFaultingObjectID $match"

        $match = $match -and ([string]::IsNullOrEmpty($KeyFaultingObjectType) -or $KeyFaultingObjectType -eq "*" -or `
            $KeyFaultingObjectType -eq $fault.FaultingObjectType)
        Write-Host "KeyFaultingObjectType $match"

        if($match) {
            Write-Host "Deleting fault (ID) $($fault.FaultId)"
            $matchFaultsId += $fault.FaultId
        }
    }
    if($matchFaultsId.Count -eq 0) {
        Write-Host "No faults found to delete"
        return
    } else {
        Write-Host "Found $($matchFaultsId.Count) faults to delete"
    }

    foreach($faultId in $matchFaultsId) {
        if($Verbose) {
            Write-Host "Deleting fault (ID) $faultId"
        }
        DeleteFaultById -faultUniqueID $faultId
    }
}

<#
    .SYNOPSIS
    Deletes a fault by its unique ID

    .PARAMETER faultUniqueID
    The unique ID of the fault to delete
#>
function DeleteFaultById
{
    param(
        [string] $faultUniqueID
    )
    
    InitFaults

    if([string]::IsNullOrEmpty($faultUniqueID)) {
        throw "Empty faultID"
    }

    $fault = Get-HealthFault | ?{ $_.FaultId -eq $faultUniqueID }

    if($null -eq $fault) {
        throw "Fault with ID $faultUniqueID not found"
    } else {
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
        $HCI_MODIFY_FAULT_FLAG_NONE)
}

function ShowFaultSet {
    param([object[]]$faults)

    Write-Host "Sucess Set:"
    Write-Host "==========="
    $faults[0]
    Write-Host "Failure Set:"
    Write-Host "==========="
    $faults[1]
}

function UpdateFaultSet {

    param(
        [object[]]$successFaults, 
        [object[]]$failureFaults
    )

    foreach($fault in $successFaults) {
        DeleteFaultBy -KeyFaultingObjectDescription $fault.KeyFaultingObjectDescription -Verbose
    }
    
    foreach($fault in $failureFaults) {
        CreateOrUpdateFault -Fault $fault -Verbose
    }
}

function DeleteFault {
    param(
        [SdnFaultInfo] $Fault,
        [switch] $Verbose
    )

    ValidateFault -Fault $Fault
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
    return $true
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

