# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-NetworkControllerClusterConfig {
    <#
    .SYNOPSIS
        Update the Network Controller Application Cluster Config with new certificate info.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $NcVMs,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcVMs.Count -eq 0) {
            Trace-Output "No NC VMs found" -Level:Error
            return
        }
        
        foreach ($ncVM in $NcVMs) {
            Invoke-Command -ComputerName $ncVM -ScriptBlock {
                function GetServiceFabricNodeKey {
                    Connect-ServiceFabricCluster | Out-Null
                    $client = [System.Fabric.FabricClient]::new()
                    $result = $null
                    $method = [System.Fabric.NamedProperty].getmethod("GetValue").MakeGenericMethod([byte[]])
                    $name = $null
                    do {
                        $result = $client.PropertyManager.EnumeratePropertiesAsync("fabric:/NetworkController/ClusterConfiguration", $true, $result).Result
                        $result.GetEnumerator() | ForEach-Object {
                            $name = $_.Metadata.PropertyName
                        
                            if ($name -match $(HostName)) {
                                Write-Host "[$(HostName)] Key $name found in ClusterConfiguration"
                                $value = $method.Invoke($_, $null);
                                $currentCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($value)
                                Write-Host "[$(HostName)] Current Cert: $currentCert"
                                break
                            }
                        }
                    }
                    while ($result.HasMoreData)
                    return $name
                }
    
                function PutProperty {
                    param(
                        $Uri = "fabric:/NetworkController/ClusterConfiguration",
                        [Parameter(Mandatory)]
                        $Property,
                        [Parameter(Mandatory)]
                        $Value
                    )
    
                    try {
                        $task = $null
                        $client = $null
                        Connect-ServiceFabricCluster | Out-Null
                        $client = [System.Fabric.FabricClient]::new()
                        $task = $client.PropertyManager.PutPropertyAsync($Uri, $Property, $value)
                        $task.Wait()
                    }
                    catch {
                        throw
                    }
                    finally {
                        if ($null -ne $client) {
                            $client.Dispose()
                        }
                    }
                }
    
                Write-Host "[$(HostName)] Updating ClusterConfiguration"
                $propertyToUpdate = GetServiceFabricNodeKey
                if ($null -ne $propertyToUpdate) {
                    # Key found match local machine, Update with new cert
                    $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
                    $cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match $NodeFQDN }) | Sort-Object -Property NotBefore -Descending | Select-Object -First 1    
                    $certRaw = $cert.GetRawCertData()
                    PutProperty -Property $propertyToUpdate -Value $certRaw
                    Write-Host "[$(HostName)] Updated ClusterConfiguration with new cert: $cert"
                }
            } -Credential $Credential
        }
    
        # Write-Host "Wait for NC App to be healty"
    
        # $scriptBlock = {
        #     Connect-ServiceFabricCluster | Out-Null
        #     Get-ServiceFabricClusterHealth | Select-Object AggregatedHealthState, NodeHealthStates, ApplicationHealthStates | ft -AutoSize
        #     Get-ServiceFabricNode -StatusFilter All | ft Nodename, Nodestatus, HealthState, IpAddressOrFQDN, NodeUptime -autosize
        #     Get-ServiceFabricApplication -ApplicationName fabric:/NetworkController | ft ApplicationName, ApplicationStatus, HealthState -AutoSize
        #     Get-ServiceFabricService -ApplicationName fabric:/NetworkController | ft ServiceName, ServiceStatus, HealthState -AutoSize
        #     Get-ServiceFabricService -ApplicationName fabric:/System | ft ServiceName, ServiceStatus, HealthState -AutoSize
        # }
        # Invoke-Command -ComputerName $NcVMs[0] -ScriptBlock $scriptBlock -Credential $Credential
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}