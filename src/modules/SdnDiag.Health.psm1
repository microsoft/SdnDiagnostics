# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Common.psm1
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

function ValidateFault {
    param(
        [SdnFaultInfo] $Fault
    )

    if ([string]::IsNullOrEmpty($Fault.KeyFaultingObjectDescription)) {
        throw "KeyFaultingObjectDescription is required"
    }

    if ([string]::IsNullOrEmpty($Fault.KeyFaultingObjectID)) {
        throw "KeyFaultingObjectID is required"
    }

    if ([string]::IsNullOrEmpty($Fault.KeyFaultingObjectType)) {
        throw "KeyFaultingObjectType is required"
    }
}
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

function LogHealthFault {

    <#
        .SYNOPSIS
        Logs the health fault

        .PARAMETER fault
        The fault to log
    #>

    param(
        [object] $fault
    )
    Write-Verbose "    HealthFault:"
    Write-Verbose "    (KeyFaultingObjectDescription) $($fault.KeyFaultingObjectDescription)"
    Write-Verbose "    (KeyFaultingObjectID) $($fault.KeyFaultingObjectID)"
    Write-Verbose "    (KeyFaultingObjectType) $($fault.KeyFaultingObjectType)"
    Write-Verbose "    (FaultingObjectLocation) $($fault.FaultingObjectLocation)"
    Write-Verbose "    (FaultDescription) $($fault.FaultDescription)"
    Write-Verbose "    (FaultActionRemediation) $($fault.FaultActionRemediation)"
}

function LogHealthFaultToEventLog {

    <#
        .SYNOPSIS
        Logs the health fault to the event log

        .PARAMETER fault
        The fault to log
    #>

    [CmdletBinding()]
    param(
        [object] $fault,

        [ValidateSet("Create", "Delete")]
        [string] $operation
    )

    if ([string]::IsNullOrEmpty($operation) ) {
        $operation = ""
    }

    $eventLogMessage = "SDN HealthServiceHealth Fault: $($fault.FaultDescription)"
    $eventLogMessage += "`r`n"
    $eventLogMessage += "Faulting Object Description: $($fault.KeyFaultingObjectDescription)"
    $eventLogMessage += "`r`n"
    $eventLogMessage += "Faulting Object ID: $($fault.KeyFaultingObjectID)"
    $eventLogMessage += "`r`n"
    $eventLogMessage += "Faulting Object Type: $($fault.KeyFaultingObjectType)"
    $eventLogMessage += "`r`n"
    $eventLogMessage += "Faulting Object Location: $($fault.FaultingObjectLocation)"
    $eventLogMessage += "`r`n"
    $eventLogMessage += "Fault Action Remediation: $($fault.FaultActionRemediation)"
    $eventLogMessage += "`r`n"
    $eventLogMessage += "Fault Operation: $($operation)"
    $eventLogJson = (ConvertTo-Json -InputObject $fault -Depth 5)

    $eventInstance = [System.Diagnostics.EventInstance]::new(1, 1)
    $evtObject = New-Object System.Diagnostics.EventLog;
    $evtObject.Log = $LOG_NAME
    $evtObject.Source = $LOG_SOURCE

    Write-Verbose "Source : $($LOG_SOURCE) Log : $($LOG_NAME) Message : $($eventLogMessage)"
    $evtObject.WriteEvent($eventInstance, @($eventLogMessage, $eventLogJson, $operation))
}

function CreateorUpdateFault {
    param(
        [SdnFaultInfo] $Fault
    )

    ValidateFault -Fault $Fault
    InitFaults
    Write-Verbose "CreateorUpdateFault:"
    LogHealthFault -fault $Fault
    LogHealthFaultToEventLog -fault $Fault -operation Create

    if ([string]::IsNullOrEmpty($script:subsystemId)) {
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
        $HCI_MODIFY_FAULT_FLAG_NONE) | Out-Null

    $retValue = [Microsoft.NetworkHud.FunctionalTests.Module.HciHealthUtils]::HciModifyRelationship(
        $Fault.KeyFaultingObjectDescription, # $entityType, `
        $Fault.KeyFaultingObjectID, # $entityId, `
        $Fault.KeyFaultingObjectDescription, # $entityDescription
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

function DeleteFaultBy {
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
    param(
        [string] $KeyFaultingObjectDescription,
        [string] $KeyFaultingObjectID,
        [string] $KeyFaultingObjectType,
        [string] $FaultingObjectLocation,
        [switch] $Verbose
    )

    Write-Verbose "DeleteFault: "
    Write-Verbose "(KeyFaultingObjectDescription) $($KeyFaultingObjectDescription)"
    Write-Verbose "(KeyFaultingObjectID) $($KeyFaultingObjectID)"
    Write-Verbose "(KeyFaultingObjectType) $($KeyFaultingObjectType)"
    Write-Verbose "(FaultingObjectLocation) $($FaultingObjectLocation)"

    InitFaults

    # get all the system faults
    $faults = Get-HealthFault
    [bool] $match = $true
    [string[]] $matchFaultsId = @()
    foreach ($fault in $faults) {
        # delete the one(s) that match the filter
        # KeyFaultingObjectDescription, KeyFaultingObjectID, KeyFaultingObjectType may be empty , in which case
        # we will not consider them for comparison
        $match = [string]::IsNullOrEmpty($KeyFaultingObjectDescription) -or $KeyFaultingObjectDescription -eq "*" -or `
            $KeyFaultingObjectDescription -eq $fault.FaultingObjectDescription;

        Write-Verbose "KeyFaultingObjectDescription $match"

        $match = $match -and ([string]::IsNullOrEmpty($KeyFaultingObjectID) -or $KeyFaultingObjectID -eq "*" -or `
                $KeyFaultingObjectID -eq $fault.FaultingObjectUniqueId)
        Write-Verbose "KeyFaultingObjectID $match"

        $match = $match -and ([string]::IsNullOrEmpty($KeyFaultingObjectType) -or $KeyFaultingObjectType -eq "*" -or `
                $KeyFaultingObjectType -eq $fault.FaultingObjectType)
        Write-Verbose "KeyFaultingObjectType $match"

        if ($match) {
            Write-Verbose "Deleting fault (ID) $($fault.FaultId)"
            $matchFaultsId += $fault.FaultId
        }
    }
    if ($matchFaultsId.Count -eq 0) {
        Write-Verbose "No faults found to delete"
        return
    }
    else {
        Write-Verbose "Found $($matchFaultsId.Count) faults to delete"
    }

    foreach ($faultId in $matchFaultsId) {
        DeleteFaultById -faultUniqueID $faultId
    }
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
    $fault = Get-HealthFault | ? { $_.FaultId -eq $faultUniqueID }

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

function ShowFaultSet {
    <#
        .SYNOPSIS
        Shows the fault set

        .PARAMETER faults
        The fault set to show
    #>

    param([object[]]$faults)

    Write-Verbose "Success Faults (for rest res):"
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        if ($null -eq $faults[0] -or $faults[0].Count -eq 0) {
            Write-Verbose "(none)"
            return
        }
        foreach ($fault in $faults[0]) {
            LogHealthFault -fault $fault
        }
    }

    Write-Verbose "Failure Faults (for rest res):"
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        if ($null -eq $faults[1] -or $faults[1].Count -eq 0) {
            Write-Verbose "(none)"
            return
        }
        foreach ($fault in $faults[1]) {
            LogHealthFault -fault $fault
        }
    }
}

function UpdateFaultSet {

    <#
        .SYNOPSIS
        Updates the fault set

        .PARAMETER successFaults
        The set of faults that were successful

        .PARAMETER failureFaults
        The set of faults that failed
    #>

    param(
        [object[]]$successFaults,
        [object[]]$failureFaults
    )

    foreach ($fault in $successFaults) {
        DeleteFaultBy -KeyFaultingObjectDescription $fault.KeyFaultingObjectDescription
    }

    foreach ($fault in $failureFaults) {
        CreateOrUpdateFault -Fault $fault
    }
}

function DeleteFault {
    <#
        .SYNOPSIS
        Deletes a fault

        .PARAMETER Fault
        The fault to delete
    #>

    [CmdletBinding()]
    param(
        [SdnFaultInfo] $Fault
    )

    ValidateFault -Fault $Fault
    InitFaults

    Write-Verbose "DeleteFault $($Fault.KeyFaultingObjectDescription) $($Fault.KeyFaultingObjectID) $($Fault.KeyFaultingObjectType)"

    if ([string]::IsNullOrEmpty($script:subsystemId)) {
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
        $HCI_MODIFY_FAULT_FLAG_NONE) | Out-Null
}
function ShowVars {
    write-host "subsystemId: $($script:subsystemId)"
    write-host "LogNameS: $($script:LOG_NAME)"
    write-host "LogSourceS: $($script:LOG_SOURCE)"

    write-host "LogName: $($LOG_NAME)"
    write-host "LogSource: $($LOG_SOURCE)"

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

    try {

        # create an event log source if it does not exist
        if (-not (Get-EventLog -LogName $script:LOG_NAME -Source $script:LOG_SOURCE -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName $script:LOG_NAME -Source $script:LOG_SOURCE -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Error "Failed to create event log source"
        throw $_
    }
}

function IsSdnFcClusterServiceRole {

    <#
        .SYNOPSIS
        Checks if the provided service role is an SDN cluster service role

        .PARAMETER ServiceName
        The name of the service role to check
    #>

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

    <#
        .SYNOPSIS
        Checks if the provided service name is an SDN agent service

        .PARAMETER serviceName
        The name of the service to check
    #>

    param([string] $serviceName)

    return $serviceName -in @( "NCHostAgent", "SlbHostAgent")
}
function IsCurrentNodeClusterOwner {
    <#
        .SYNOPSIS
        Checks if the current node is the owner of the cluster

        .NOTES
        This function is used to determine if the current node is the owner of the cluster. This is used to determine if the current node is the primary node in a cluster.
    #>

    $activeNode = Get-ClusterResource  | ? { $_.OwnerGroup -eq "Cluster Group" -and $_.ResourceType -eq "IP Address" -and $_.Name -eq "Cluster IP Address" }

    if ( $null -eq $activeNode ) {
        # todo : generate a fault on failing to generate a fault (or switch to different algorithm for picking the primary node)
        return $false
    }

    return ($activeNode.OwnerNode -eq $env:COMPUTERNAME)
}

function GetFaultFromConfigurationState {
    <#
        .SYNOPSIS
        Generates a fault from the configuration state

        .PARAMETER resources
        The resources to generate the fault from
    #>

    param(
        [object[]] $resources
    )

    $healthFaults = @()
    # successful faults are just a stub holder for the resource
    # these are not created, but used for clearing out any older unhealthy states
    # these have KeyFaultingObjectType set to string.empty
    $successFaults = @()

    foreach ($resource in $resources) {

        ##########################################################################################
        ## ServiceState Fault Template (ServerResource)
        ##########################################################################################
        # $KeyFaultingObjectDescription    (SDN ID)    : [ResourceRef]
        # $KeyFaultingObjectID             (ARC ID)    : [ResourceMetadataID (if available) else ResourceRef]
        # $KeyFaultingObjectType           (CODE)      : "ConfgiStateCode" (if 2 more errors are found with same other properties will be concat)
        # $FaultingObjectLocation          (SOURCE)    : "Source (if keys of 2 errors collide they will be concatanated)"
        # $FaultDescription                (MESSAGE)   : "ConfigStateMessage (2 or more if errors collide)."
        # $FaultActionRemediation          (ACTION)    : "See <href> for more information on how to resolve this issue."
        # * Config state faults issued only from the primary Node
        ##########################################################################################


        if ($null -ne $resource.Properties.ConfigurationState -and $null -ne $resource.Properties.ConfigurationState.DetailedInfo -and `
                $resource.Properties.ConfigurationState.DetailedInfo.Count -gt 0) {

            foreach ($detailedInfo in $resource.Properties.ConfigurationState.DetailedInfo) {

                # supression check for some of the known configuration states
                if (IsConfigurationStateSkipped -Source $detailedInfo.Source -Message $detailedInfo.Message -Code $detailedInfo.Code) {
                    continue
                }

                # handle success cases
                if ($detailedInfo.Code -eq "Success") {

                    $successFault = [SdnFaultInfo]::new()
                    $successFault.KeyFaultingObjectDescription = $resource.ResourceRef
                    $successFault.KeyFaultingObjectID = $resource.ResourceRef
                    $successFault.KeyFaultingObjectType = [string]::Empty
                    $successFault.FaultingObjectLocation = [string]::Empty
                    $successFault.FaultDescription = [string]::Empty
                    $successFaults += $successFault

                }
                else {

                    # find any existing overlapping fault
                    $existingFault = $healthFaults | Where-Object { $_.KeyFaultingObjectDescription -eq $resource.ResourceRef -and `
                            $_.KeyFaultingObjectType -eq $detailedInfo.Code }

                    if ($null -ne $existingFault) {

                        $existingFault.FaultDescription += ("; " + $detailedInfo.Message)
                        $existingFault.FaultingObjectLocation += ("; " + $detailedInfo.Source)

                    }
                    else {

                        $healthFault = [SdnFaultInfo]::new()
                        $healthFault.KeyFaultingObjectDescription = $resource.ResourceRef
                        $healthFault.KeyFaultingObjectType = $detailedInfo.Code
                        $healthFault.FaultingObjectLocation = $detailedInfo.Source
                        $healthFault.FaultDescription += $detailedInfo.Message

                        # add resource metadata if available
                        if ($null -ne $resource.Properties.ResourceMetadata) {
                            $healthFault.KeyFaultingObjectID = $resource.Properties.ResourceMetadata
                        }
                        else {
                            $healthFault.KeyFaultingObjectID = $resource.ResourceRef
                        }
                    }
                    $healthFaults += $healthFault
                }
            }
        }
        else {
            # if configuration state is not available, we will clear out any existing faults
            if ($healthFaults.Count -eq 0) {
                $successFault = [SdnFaultInfo]::new()
                $successFault.KeyFaultingObjectDescription = $resource.ResourceRef
                $successFault.KeyFaultingObjectType = [string]::Empty
                $successFault.FaultingObjectLocation = [string]::Empty
                $successFault.FaultDescription = [string]::Empty
                $successFault.KeyFaultingObjectID = $resource.ResourceRef
                $successFaults += $successFault
            }
        }
    }

    foreach ($fault in $healthFaults) {
        LogWmiHealthFault -fault $fault
    }

    @($successFaults, $healthFaults)
}

function IsConfigurationStateSkipped {

    <#
        .SYNOPSIS
        Checks if the configuration state should be skipped

        .PARAMETER Source
        The source of the configuration state

        .PARAMETER Message
        The message of the configuration state

        .PARAMETER Code
        The code of the configuration state
    #>

    param(
        [string] $Source,
        [string] $Message,
        [string] $Code
    )

    if ($Source -eq "SoftwareLoadbalancerManager") {
        if ($Code -eq "HostNotConnectedToController") {
            return $true
        }
    }

    $false
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

        return $result.Role | Where-Object { $_.Role -like "*$wordToComplete*" } | Sort-Object
    }
    Name = {
        param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
        $result = (Get-SdnFabricInfrastructureResult).RoleTest.HealthTest
        if ([string]::IsNullOrEmpty($wordToComplete)) {
            return ($result.Name | Sort-Object -Unique)
        }

        return $result.Name | Where-Object { $_.Name -like "*$wordToComplete*" } | Sort-Object
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
        HealthFault    = [PSCustomObject]@()
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
        $outputString += "Remediation:`r`n`t - $($Remediation -join "`r`n`t - ")`r`n"
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

            $restApiParams = @{
                NcUri = $sdnFabricDetails.NcUrl
            }
            $restApiParams += $restCredParam

            # before proceeding with tests, ensure that the computer objects we are testing against are running the latest version of SdnDiagnostics
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.ComputerName -Credential $Credential

            $params = @{
                ComputerName = $sdnFabricDetails.ComputerName
                Credential   = $Credential
                ScriptBlock  = $null
                ArgumentList = @($restApiParams)
            }

            switch ($object) {
                'Gateway' { $params.ScriptBlock = { param($boundParams) Debug-SdnGateway @boundParams } }
                'LoadBalancerMux' { $params.ScriptBlock = { param($boundParams) Debug-SdnLoadBalancerMux @boundParams } }
                'NetworkController' { $params.ScriptBlock = { param($boundParams) Debug-SdnNetworkController @boundParams } }
                'Server' { $params.ScriptBlock = { param($boundParams) Debug-SdnServer @boundParams } }
            }

            $healthReport = Invoke-SdnCommand @params

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

function Start-SdnHealthFault {

    <#
.SYNOPSIS
Executes a series of fabric validation tests to validate the state and health of the underlying components within the SDN fabric.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [bool] $GenerateFault = $false,

        [Parameter(Mandatory = $false)]
        [bool] $Poll = $false,

        [Parameter(Mandatory = $false)]
        [int] $PollIntervalSeconds = 30
    )

    Write-Verbose "Starting SDN Health Faults"
    [bool] $transcriptStarted = $false
    try {

        # todo : change logpath
        $transcriptFile = Join-Path -Path  $Env:TEMP  -ChildPath "SdnDiag.log"
        Start-Transcript -Path $transcriptFile -Append
        $transcriptStarted = $true

        do {

            # Test encapoverhead settings
            Test-EncapOverhead -GenerateFault $true -Verbose

            # Test all SDN Services
            $validServiceRoles = @(
                "ApiService",
                "ControllerService",
                "FirewallService",
                "FnmService",
                "GatewayManager",
                "ServiceInsertion",
                "VSwitchService"
            )
            Test-SdnClusterServiceState -ServiceName $validServiceRoles -GenerateFault $true

            # Test all agent services
            $agentServices = @(
                'NcHostAgent',
                'SlbHostAgent'
            )
            Test-ServiceState -ServiceName $agentServices -GenerateFault $true

            # Test certificate related faults
            Test-NonSelfSignedCertificateInTrustedRootStore -GenerateFault $true -Verbose

            # Test tenant configuration states
            Test-ConfigurationState -NcUri $NcUri -GenerateFault $true

            if ($Poll) {

                Start-Sleep -Seconds $PollIntervalSeconds -Verbose
            }

        } until($Poll -eq $false);
    }
    catch {
        $_ | Write-Error
    }
    finally {
        if ($transcriptStarted) {
            Stop-Transcript
        }
    }
}

function IsVerbose {
    <#
        .SYNOPSIS
        Checks if the current session is in verbose mode
    #>

    # check if verbose flag was passed
    return $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
}

function GetSdnResourceFromNc {
    <#
        .SYNOPSIS
        Retrieves a list of SDN resource from the Network Controller.
        NOTE: this is specifically for ASZ env because the nc cmdlets do not work there

        .PARAMETER NcUri
        The base URI of the Network Controller. (https://<nc rest name>)

        .PARAMETER Resource
        The resource to retrieve from the Network Controller.

        .PARAMETER Version
        (optional) The version of the resource to retrieve from the Network Controller.
        note: if nothing is specified, v1 is queried

    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string] $NcUri,

        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'Servers', `
                'NetworkInterfaces', `
                'VirtualNetworks', `
                'LogicalNetworks'
        )]
        [String]$ResourceType,

        [Parameter(Mandatory = $false)]
        [String]$Version = 'v1'
    )

    try {


        $NcUri = $NcUri.TrimEnd('/')
        $NcUri += "/networking/$Version/$ResourceType"

        # detect authentication strategy
        # for ASZ/HCI environments:
        # - try without certificates
        # - try all certificates from machine store (using hostagent's PeerCName as a hint)

        # kerberos is not supported yet
        $resources = $null
        try {
            Write-Verbose "Retrieving $NcUri without certificate"
            $resources = ((Invoke-WebRequest -UseBasicParsing -Uri $NcUri -Verbose).Content | ConvertFrom-Json).Value

            return $resources
        }
        catch {
            $_ | Write-Error
        }

        # try all certificates from machine store
        $certName = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\
        $certs = Get-ChildItem -Path Cert:\LocalMachine\My | ? { $_.Subject -eq "CN=$certName" }

        foreach ($cert in $certs) {

            $cred = @{
                NcUri       = $NcUri
                Certificate = $cert
            }

            try {

                Write-Verbose "Retrieving $NcUri with certificate $($cert.Subject) thumbprint $($cert.Thumbprint)"
                $resources = ((Invoke-WebRequest -UseBasicParsing -Uri $ruri -Verbose).Content | ConvertFrom-Json).Value
                return $resources
            }
            catch {
                $_ | Write-Error
            }
        }

        return $null

    }
    finally {

        if ($null -ne $resources) {
            Write-Verbose "Retrieved $($resources.Count) resources for $ResourceType"
        }
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
        # execute tests based on the cluster type
        switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
            'ServiceFabric' {
                $healthReport.HealthTest += {
                    Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
                }
            }
            'FailoverCluster' {
                $healthReport.HealthTest += {
                    Test-DiagnosticsCleanupTaskEnabled -TaskName 'FcDiagnostics'
                }
            }
        }

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
        $muxVirtualServer = $virtualServers | Where-Object { $_.properties.connections.managementaddresses -contains $muxCertRegKey.MuxCert }
        $loadBalancerMux = Get-SdnLoadBalancerMux @ncRestParams | Where-Object { $_.properties.virtualserver.resourceRef -ieq $muxVirtualServer.resourceRef }
        $peerRouters = $loadBalancerMux.properties.routerConfiguration.peerRouterConfigurations.routerIPAddress

        $healthReport.HealthTest += @(
            Test-NonSelfSignedCertificateInTrustedRootStore
            Test-ServiceState -ServiceName $services
            Test-DiagnosticsCleanupTaskEnabled -TaskName 'SDN Diagnostics Task'
            Test-MuxConnectionStateToSlbManager
            Test-NetworkControllerApiNameResolution -NcUri $NcUri
        )

        # these tests have dependencies on network controller rest API being available
        # and will only be executed if we have been able to get the data from the network controller
        if ($muxVirtualServer) {
            $healthReport.HealthTest += @(
                Test-MuxConnectionStateToRouter -RouterIPAddress $peerRouters
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
    param (
        [Parameter(Mandatory = $false)]
        [bool] $GenerateFault = $false
    )


    Write-Verbose "Test-NonSelfSignedCertificateInTrustedRootStore invoked"
    $sdnHealthTest = New-SdnHealthTest
    $array = @()

    try {
        $rootCerts = Get-ChildItem -Path 'Cert:LocalMachine\Root' | Where-Object { $_.Issuer -ne $_.Subject }
        if ($rootCerts -or $rootCerts.Count -gt 0) {
            $sdnHealthTest.Result = 'FAIL'

            $rootCerts | ForEach-Object {
                $sdnHealthTest.Remediation += "Remove Certificate Thumbprint: $($_.Thumbprint) Subject: $($_.Subject)"
                $array += [PSCustomObject]@{
                    Thumbprint = $_.Thumbprint
                    Subject    = $_.Subject
                    Issuer     = $_.Issuer
                }
            }
        }
        $sdnHealthTest.Properties = $array
        if ($GenerateFault) {

            ##########################################################################################
            ## ServiceState Fault Template
            ##########################################################################################
            # $KeyFaultingObjectDescription    (SDN ID)    : [HostName]
            # $KeyFaultingObjectID             (ARC ID)    : [HostName]
            # $KeyFaultingObjectType           (CODE)      : "NonSelfSignedCertificateInTrustedRootStore"
            # $FaultingObjectLocation          (SOURCE)    : "CertificateConfiguration"
            # $FaultDescription                (MESSAGE)   : "A non self signed ceritificate was found in trusted root store. This may lead to authentication problems."
            # $FaultActionRemediation          (ACTION)    : "Investigate and remove certificate with subject [SubjectNamesCsv]"
            # * Fault may be issued from each node
            ##########################################################################################
            if ($array.Subject -ne $null -and $array.Subject.Count -gt 0) {
                $subjectNames = [string]::Join(",", $array.Subject)
            }
            else {
                $subjectNames = ""
            }
            $healthFault = [SdnFaultInfo]::new()
            $healthFault.KeyFaultingObjectDescription = $Env:COMPUTERNAME
            $healthFault.KeyFaultingObjectID = $Env:COMPUTERNAME
            $healthFault.KeyFaultingObjectType = "NonSelfSignedCertificateInTrustedRootStore"
            $healthFault.FaultingObjectLocation = "CertificateConfiguration"
            $healthFault.FaultDescription = "A non self signed ceritificate was found in trusted root store. This may lead to authentication problems."
            $healthFault.FaultActionRemediation = "Investigate and remove certificate with subject(s) $($subjectNames)."

            if ( $rootCerts -or $rootCerts.Count -gt 0) {
                CreateorUpdateFault -Fault $healthFault -Verbose
            }
            else {
                DeleteFault -Fault $healthFault -Verbose
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }
    finally {
        Write-Verbose "Returning from Test-NonSelfSignedCertificateInTrustedRootStore"
    }

    return $sdnHealthTest
}

function Test-ServiceState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$ServiceName,

        [Parameter(Mandatory = $false)]
        [String]$GenerateFault = $false
    )

    Write-Verbose "Test-ServiceState invoked for $($ServiceName)"
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

            # generate/clear fault
            if ($GenerateFault -eq $true) {
                ##########################################################################################
                ## ServiceState Fault Template
                ##########################################################################################
                # $KeyFaultingObjectDescription    (SDN ID)    : [HostName]
                # $KeyFaultingObjectID             (ARC ID)    : [ServiceName]
                # $KeyFaultingObjectType           (CODE)      : [ServiceDown]
                # $FaultingObjectLocation          (SOURCE)    : [ServiceName]
                # $FaultDescription                (MESSAGE)   : Service [ServiceName] is not up.
                # $FaultActionRemediation          (ACTION)    : [ServiceName] Start the service
                # *ServiceState faults will be reported from each node
                ##########################################################################################

                $healthFault = [SdnFaultInfo]::new()
                $healthFault.KeyFaultingObjectDescription = $Env:COMPUTERNAME
                $healthFault.KeyFaultingObjectID = $service
                $healthFault.KeyFaultingObjectType = "ServiceDown"
                $healthFault.FaultingObjectLocation = $service
                $healthFault.KeyFaultingObjectDescription = "Start the cluster service role $($service)"
                $healthFault.FaultingObjectLocation = $service

                if ($result.Status -ine 'Running') {
                    Write-Verbose "Creating fault for $($service) status $($result.Status)"
                    CreateorUpdateFault -Fault $healthFault
                }
                else {
                    Write-Verbose "No fault(s) on $($service) clearing any existing ones"
                    DeleteFault -Fault $healthFault
                }
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
        Write-Verbose "Error occured: $_"
        $sdnHealthTest.Result = 'FAIL'
    }
    finally {
        Write-Verbose "Returning from Test-ServiceState"
    }

    return $sdnHealthTest
}


function Test-SdnClusterServiceState {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String[]]$ServiceName,

        [Parameter(Mandatory = $false)]
        [String[]]$GenerateFault = $false
    )

    if (IsCurrentNodeClusterOwner -eq $false) {
        Write-Verbose "This node is not the cluster owner. Skipping health tests."
        return
    }

    Write-Verbose "Test-SdnClusterServiceState invoked"
    $sdnHealthObject = New-SdnHealthTest
    $failureDetected = $false
    $array = @()

    try {
        foreach ($service in $ServiceName) {
            $result = Get-ClusterGroup -Name $service -ErrorAction Ignore
            if ($result) {
                $array += [PSCustomObject]@{
                    ServiceName = $result.Name
                    Status      = $result.State
                }
                Write-Verbose "$service state $($result.State)"
                if ($result.State -ine 'Online') {
                    $failureDetected = $true
                    $sdnHealthObject.Remediation += "[$service] Start the service"
                }

                # Write-Host "here1"
                # write-host (IsCurrentNodeClusterOwner -eq $true)
                # write-host (IsSdnFcClusterServiceRole -ServiceName $ServiceName)

                # generate/clear fault
                if ($GenerateFault) {

                    ##########################################################################################
                    ## FailoverClusterServiceState Fault Template
                    ##########################################################################################
                    # $KeyFaultingObjectDescription    (SDN ID)    : [ServiceName]
                    # $KeyFaultingObjectID             (ARC ID)    : [ServiceName]
                    # $KeyFaultingObjectType           (CODE)      : ServiceUnavailable
                    # $FaultingObjectLocation          (SOURCE)    : [ServiceName]
                    # $FaultDescription                (MESSAGE)   : Service [ServiceName] is not up.
                    # $FaultActionRemediation          (ACTION)    : [ServiceName] Start the service
                    # *ServiceState faults will be reported only on one (primary) cluster node
                    ##########################################################################################

                    $healthFault = [SdnFaultInfo]::new()
                    $healthFault.KeyFaultingObjectDescription = $service
                    $healthFault.KeyFaultingObjectID = $service
                    $healthFault.KeyFaultingObjectType = "ServiceUnavailable"
                    $healthFault.FaultingObjectLocation = $service
                    $healthFault.FaultDescription = "Service $($service) is $($result.State) on Failover Cluster"
                    $healthFault.FaultActionRemediation = "Start the cluster service role $($service)"

                    if ($result.State -ine 'Online') {
                        Write-Verbose "Creating fault for $($service)"
                        CreateorUpdateFault -Fault $healthFault -Verbose
                    }
                    else {
                        Write-Verbose "No fault(s) on $($service)"
                        DeleteFault -Fault $healthFault
                    }
                }
            }
            else {
                # todo: handle cluster errors when FC fails to return a cluster group
            }
        }

        if ($failureDetected) {
            $sdnHealthObject.Result = 'FAIL'
        }
        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
    finally {
        Write-Verbose "Returning from Test-SdnClusterServiceState"
    }
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
        $_ | Trace-Exception
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
    param (
        [Parameter(Mandatory = $false)]
        [bool] $GenerateFault = $false
    )

    Write-Verbose "Test-EncapOverhead invoked"

    [int]$encapOverheadExpectedValue = 160
    [int]$jumboPacketExpectedValue = 1674 # this is default 1514 MTU + 160 encap overhead
    $sdnHealthTest = New-SdnHealthTest
    [bool] $misconfigurationFound = $false
    [string[]] $misconfiguredNics = @()

    try {
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
                        $misconfigurationFound = $true
                        $misconfiguredNics += $_.NetAdapterInterfaceDescriptio
                    }

                }

                # in this case, the encapoverhead is enabled but the value is less than the expected value
                if ($_.EncapOverheadEnabled -and $_.EncapOverheadValue -lt $encapOverheadExpectedValue) {
                    # do nothing here at this time as may be expected if no workloads deployed to host
                }
            }

            if ($GenerateFault) {
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

                if ($misconfigurationFound -eq $true) {
                    CreateorUpdateFault -Fault $sdnHealthFault -Verbose
                }
                else {
                    Write-Verbose "No fault(s) on EncapOverhead, clearing any existing ones"
                    # clear all existing faults for host($FAULTNAME)
                    # todo: validate multiple hosts reporting the same fault
                    DeleteFaultBy -KeyFaultingObjectDescription $env:COMPUTERNAME `
                        -KeyFaultingObjectType $FAULTNAME
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
        $_ | Trace-Exception
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

    $sdnHealthTest = New-SdnHealthTest

    try {
        $vmNetAdapters = Get-SdnVMNetworkAdapter
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

function Test-ProviderNetwork {
    [CmdletBinding()]
    param ()

    $sdnHealthTest = New-SdnHealthTest

    try {
        $addressMapping = Get-SdnOvsdbAddressMapping
        if (-NOT ($null -eq $addressMapping -or $addressMapping.Count -eq 0)) {
            $providerAddreses = $addressMapping.ProviderAddress | Sort-Object -Unique
            $connectivityResults = Test-SdnProviderAddressConnectivity -ProviderAddress $providerAddreses

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
        $_ | Trace-Exception
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
        $_ | Trace-Exception
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
        $_ | Trace-Exception
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}

function Test-ConfigurationState {
    [CmdletBinding()]
    param (
        [bool] $GenerateFault = $false,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'RestCredential')]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate
    )

    Write-Verbose "Test-ConfigurationState invoked"
    try {

        if (IsCurrentNodeClusterOwner -eq $false) {
            Write-Verbose "This node is not the cluster owner. Skipping health tests."
            return
        }

        if (-not $GenerateFault) {
            Write-Verbose "Skipping fault generation"
        }

        # servers
        $items = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\NcHostAgent\Parameters\
        $NcUri = "https://$($items.PeerCertificateCName)"

        # generate faults for servers
        $servers = Get-SdnResource -NcUri $NcUri -ResourceType 'Servers'
        $faultSet = GetFaultFromConfigurationState -resources $servers
        ShowFaultSet -faults $faultSet

        UpdateFaultSet -successFaults $faultSet[0] -FailureFaults $faultSet[1]

        # generate faults for vnics
        # asz workaround
        # $vnics = Get-NetworkControllerNetworkInterface -ConnectionUri $NcUri
        $vnics = Get-SdnResource -NcUri $NcUri -Resource 'NetworkInterfaces'
        $faultSet = GetFaultFromConfigurationState -resources $vnics
        ShowFaultSet -faults $faultSet
        UpdateFaultSet -successFaults $faultSet[0] -FailureFaults $faultSet[1]

    }
    catch {
        $_ | Write-Error
    }
    finally {
        Write-Verbose "Returning from Test-ConfigurationState"
    }
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
        $_ | Trace-Exception
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
        $_ | Trace-Exception
        $sdnHealthTest.Result = 'FAIL'
    }

    return $sdnHealthTest
}
