# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnKIServiceFabricPartitionDatabaseSize {
    <#
    .SYNOPSIS
        Validate the Service Fabric partition size for each of the services running on Network Controller.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Test-SdnKIServiceFabricPartitionDatabaseSize
    .EXAMPLE
        PS> Test-SdnKIServiceFabricPartitionDatabaseSize -NetworkController 'NC01','NC02'
    .EXAMPLE
        PS> Test-SdnKIServiceFabricPartitionDatabaseSize -NetworkController 'NC01','NC02' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.InfrastructureInfo.NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validate the size of the Service Fabric Partition Databases for Network Controller services" | Trace-Output

        if($null -eq $NetworkController){
            throw New-Object System.NullReferenceException("Please specify NetworkController parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('Credential')){
            if($Global:SdnDiagnostics.Credential){
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $NetworkController -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        foreach($node in $ncNodes){
            if($node.NodeStatus -ine 'Up'){
                "{0} is reporting status {1}" -f $node.NodeName, $node.NodeStatus | Trace-Output -Level:Warning
            }

            $ncAppWorkDir = (Invoke-SdnServiceFabricCommand -NetworkController $NetworkController -Credential $Credential `
                -ScriptBlock {Get-ServiceFabricDeployedApplication -ApplicationName 'fabric:/NetworkController' -NodeName $using:node.NodeName}).WorkDirectory
            if($null -eq $ncAppWorkDir){
                throw New-Object System.NullReferenceException("Unable to retrieve working directory path")
            }

            # Only stateful service have the database file
            $ncServices = Get-SdnServiceFabricService -NetworkController $NetworkController -Credential $Credential | Where-Object {$_.ServiceKind -eq "Stateful"}

            foreach ($ncService in $ncServices){
                $replica = Get-SdnServiceFabricReplica -NetworkController $NetworkController -ServiceName $ncService.ServiceName -Credential $Credential | Where-Object {$_.NodeName -eq $node.NodeName}
                $imosStorePath = Join-Path -Path $ncAppWorkDir -ChildPath "P_$($replica.PartitionId)\R_$($replica.ReplicaId)\ImosStore"
                $session = New-PSRemotingSession -ComputerName $node.NodeName -Credential $Credential
                $imosStoreFile = Invoke-Command -Session $session -ScriptBlock {
                    if(Test-Path $using:imosStorePath){
                        return Get-Item $using:imosStorePath
                    }
                    else {
                        return $null
                    }
                }

                if($null -ne $imosStoreFile){
                    $imosInfo = [PSCustomObject]@{
                        Node = $node.NodeName
                        Service = $ncService.ServiceName
                        ImosSize = $($imosStoreFile.Length/1MB)
                    }
                    # if the imos database file exceeds 4GB, want to indicate failure as it should not grow to be larger than this size
                    if([float]$($imosStoreFile.Length/1MB) -gt 4096){
                        "[{0}] Service {1} is reporting {2} MB in size" -f $node.NodeName, $ncService.ServiceName, $($imosStoreFile.Length/1MB) | Trace-Output -Level:Warning

                        $issueDetected = $true
                        [void]$arrayList.Add($imosInfo)
                    }
                    else {
                        "[{0}] Service {1} is reporting {2} MB in size" -f $node.NodeName, $ncService.ServiceName, $($imosStoreFile.Length/1MB) | Trace-Output -Level:Verbose
                    }
                }
                else {
                    "No ImosStore file for service {0} found on node {1} from {2}" -f $ncService.ServiceName, $node.NodeName, $imosStorePath | Trace-Output -Level:Warning
                }
            }
        }

        return [PSCustomObject]@{
            Result = $issueDetected
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
