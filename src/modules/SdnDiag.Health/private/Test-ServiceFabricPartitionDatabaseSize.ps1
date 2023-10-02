function Test-ServiceFabricPartitionDatabaseSize {
    <#
    .SYNOPSIS
        Validate the Service Fabric partition size for each of the services running on Network Controller.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnFabricEnvObject]$SdnEnvironmentObject,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealth]::new()
    $array = @()

    try {
        "Validate the size of the Service Fabric Partition Databases for Network Controller services" | Trace-Output

        $ncNodes = Get-SdnServiceFabricNode -NetworkController $SdnEnvironmentObject.ComputerName -Credential $credential
        if($null -eq $ncNodes){
            throw New-Object System.NullReferenceException("Unable to retrieve service fabric nodes")
        }

        foreach($node in $ncNodes){
            $ncApp = Invoke-SdnServiceFabricCommand -NetworkController $SdnEnvironmentObject.ComputerName -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 0)][String]$param1)
                Get-ServiceFabricDeployedApplication -ApplicationName 'fabric:/NetworkController' -NodeName $param1
            } -ArgumentList @($node.NodeName.ToString())

            $ncAppWorkDir = $ncApp.WorkDirectory
            if($null -eq $ncAppWorkDir){
                throw New-Object System.NullReferenceException("Unable to retrieve working directory path")
            }

            # Only stateful service have the database file
            $ncServices = Get-SdnServiceFabricService -NetworkController $SdnEnvironmentObject.ComputerName -Credential $Credential | Where-Object {$_.ServiceKind -eq "Stateful"}

            foreach ($ncService in $ncServices){
                $replica = Get-SdnServiceFabricReplica -NetworkController $SdnEnvironmentObject.ComputerName -ServiceName $ncService.ServiceName -Credential $Credential | Where-Object {$_.NodeName -eq $node.NodeName}
                $imosStorePath = Join-Path -Path $ncAppWorkDir -ChildPath "P_$($replica.PartitionId)\R_$($replica.ReplicaId)\ImosStore"
                $imosStoreFile = Invoke-PSRemoteCommand -ComputerName $node.NodeName -Credential $Credential -ScriptBlock {
                    param([Parameter(Position = 0)][String]$param1)
                    if (Test-Path -Path $param1) {
                        return (Get-Item -Path $param1)
                    }
                    else {
                        return $null
                    }
                } -ArgumentList @($imosStorePath)

                if($null -ne $imosStoreFile){
                    $formatedByteSize = Format-ByteSize -Bytes $imosStoreFile.Length

                    $imosInfo = [PSCustomObject]@{
                        Node = $node.NodeName
                        Service = $ncService.ServiceName
                        ImosSize = $formatedByteSize.GB
                    }

                    # if the imos database file exceeds 4GB, want to indicate failure as it should not grow to be larger than this size
                    # need to perform InvariantCulture to ensure that the decimal separator is a period
                    if([float]::Parse($formatedByteSize.GB, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture) -gt 4){
                        "[{0}] Service {1} is reporting {2} GB in size" -f $node.NodeName, $ncService.ServiceName, $formatedByteSize.GB | Trace-Output -Level:Warning

                        $sdnHealthObject.Result = 'FAIL'
                        $sdnHealthObject.Remediation = "Engage Microsoft CSS for further support"
                    }
                    else {
                        "[{0}] Service {1} is reporting {2} GB in size" -f $node.NodeName, $ncService.ServiceName, $formatedByteSize.GB | Trace-Output -Level:Verbose
                    }

                    $array += $imosInfo
                }
                else {
                    "No ImosStore file for service {0} found on node {1} from {2}" -f $ncService.ServiceName, $node.NodeName, $imosStorePath | Trace-Output -Level:Warning
                }
            }
        }

        $sdnHealthObject.Properties = $array
        return $sdnHealthObject
    }
    catch {
       $_ | Trace-Output -Level:Error
    }
}
