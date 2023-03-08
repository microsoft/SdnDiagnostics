function Wait-ServiceFabricClusterHealthy {
    <#
    .SYNOPSIS
        Start the FabricHostSvc on each of the Network Controller VM and wait for the service fabric service to become healthy.
    .PARAMETER NcVMs
        The list of Network Controller VMs.
    .PARAMETER ClusterCredentialType
        X509, Windows or None.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]
        $Restart
    )

    try {
        $currentNcNode = $null

        # Start Service Fabric Service for each NC
        foreach ($ncNode in $NcNodeList) {
            if(Test-ComputerNameIsLocal -ComputerName $ncNode.IpAddressOrFQDN){
                $currentNcNode = $ncNode
            }

            Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                if($using:Restart){
                    Stop-Service -Name 'FabricHostSvc' -Force
                    Start-Sleep -Seconds 5
                }

                Start-Service -Name 'FabricHostSvc'
            } -Credential $Credential
        }

        Trace-Output "Sleeping 60s to wait for Serice Fabric Service to be ready"
        Start-Sleep -Seconds 60
        "Waiting for service fabric service healthy" | Trace-Output
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        $certThumb = $CertRotateConfig[$currentNcNode.NodeName.ToLower()]

        $maxRetry = 10
        $clusterConnected = $false
        while ($maxRetry -gt 0) {
            if(!$clusterConnected){
                try{
                    "Service fabric cluster connect attempt $(11 - $maxRetry)/10" | Trace-Output
                    if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                        "Connecting to Service Fabric Cluster using cert with thumbprint: {0}" -f $certThumb | Trace-Output
                        Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                    }
                    else {
                        Connect-ServiceFabricCluster | Out-Null
                    }
                    $clusterConnected = $true
                }catch{
                    $maxRetry --
                    continue
                }
            }

            if($clusterConnected){
                $services = @()
                $services = Get-ServiceFabricService -ApplicationName fabric:/System
                $allServiceHealth = $true
                if ($services.Count -eq 0) {
                    "No service fabric services retrieved yet" | Trace-Output -Level:Warning
                }

                foreach ($service in $services) {
                    if ($service.ServiceStatus -ne "Active" -or $service.HealthState -ne "Ok" ) {
                        "$($service.ServiceName) ServiceStatus: $($service.ServiceStatus) HealthState: $($service.HealthState)" | Trace-Output -Level:Warning
                        $allServiceHealth = $false
                    }
                }
                if ($allServiceHealth -and $services.Count -gt 0) {
                    "All service fabric service has been healthy" | Trace-Output -Level:Warning
                    return $allServiceHealth
                }

                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
