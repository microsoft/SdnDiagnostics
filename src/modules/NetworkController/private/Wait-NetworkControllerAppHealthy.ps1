# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Wait-NetworkControllerAppHealthy {
    <#
    .SYNOPSIS
        Query the Network Controller App Health Status. Wait for the Network Controller App become healthy when $Interval specified.
    .PARAMETER NetworkController
        Specifies one of the Network Controller VM name.
	.PARAMETER Interval
		App healh status query interval until the App become healthy, default to 0 means no retry of the health status query.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $NetworkController,
        [Parameter(Mandatory = $false)]
        [Int32]
        $Interval = 0,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $scriptBlock = {
            param (
                [Int32]
                $Interval = 0
            )
            $isApplicationHealth = $false;
            Trace-Output "[$(HostName)] Query Network Controller App Health"
            while($isApplicationHealth -ne $true){
                #Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                #Cluster should have been back to normal when reach here use default parameters to connect
                Connect-ServiceFabricCluster | Out-Null
                $clusterHealth = Get-ServiceFabricClusterHealth
                if ($clusterHealth.AggregatedHealthState -ne "Ok") {
                    if ($clusterHealth.NodeHealthStates -ne "Ok") {
                        Get-ServiceFabricNode -StatusFilter All | Format-Table Nodename, Nodestatus, HealthState, IpAddressOrFQDN, NodeUptime -autosize
                    }
                    $applicationStatus = Get-ServiceFabricApplication -ApplicationName fabric:/NetworkController 
                    if ($applicationStatus.HealthState -ne "Ok") {
                        $applicationStatus | Format-Table ApplicationName, ApplicationStatus, HealthState -AutoSize
                        $services = Get-ServiceFabricService -ApplicationName fabric:/NetworkController
                        $allServiceHealth = $true;
                        foreach ($service in $services) {
                            if($service.HealthState -notlike "Ok"){
                                $allServiceHealth = $false;
                            }
                        }
                        if($allServiceHealth -and $services.Count -gt 0)
                        {
                            $isApplicationHealth = $true
                            break
                        }
    
                        $services | Format-Table ServiceName, ServiceStatus, HealthState -AutoSize
                    }
                    else {
                        $isApplicationHealth = $true
                    }
    
                    $systemStatus = Get-ServiceFabricService -ApplicationName fabric:/System
                    if ($systemStatus.HealthState -ne "Ok") {
                        $systemStatus | Format-Table ServiceName, ServiceStatus, HealthState -AutoSize
                    } 
                }else{
                    $isApplicationHealth = $true;
                }
    
                Write-Host "[$(HostName)] Current Network Controller Health Status: $isApplicationHealth"
                if($Interval -gt 0)
                {
                    Start-Sleep -Seconds $Interval
                }else{
                    break
                }
            }
        }
    
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController')))
        {
            Invoke-Command -ScriptBlock $scriptBlock -ArgumentList $Interval
        }
        else{
            Invoke-Command -ComputerName $NetworkController -ScriptBlock $scriptBlock -ArgumentList $Interval -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}