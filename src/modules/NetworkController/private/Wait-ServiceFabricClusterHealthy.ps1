# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        [String[]]
        $NcVMs,
        [String]
        $ClusterCredentialType = "X509",
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        # Start Service Fabric Service for each NC
        foreach ($nc in $NcVMs) {
            Invoke-Command -ComputerName $nc -ScriptBlock {
                Write-Host "[$(HostName)] Startting Service Fabric Service"
                Start-Service FabricHostSvc
            }
        }

        Trace-Output "Sleeping 60s to wait for Serice Fabric Service to be ready"
        Start-Sleep -Seconds 60

        $sfServiceHealthScript = {
            param(
                [String]
                $ClusterCredentialType
            )
            Write-Host "waiting for service fabric service healthy"
            $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
            $cert = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -match "CN=$NodeFQDN" }) | Sort-Object -Property NotBefore -Descending | Select-Object -First 1    
            $certThumb = $cert.Thumbprint
            
            while ($true) {
                if ($ClusterCredentialType -eq "X509") {
                    Connect-ServiceFabricCluster -X509Credential -FindType FindByThumbprint -FindValue $certThumb  -ConnectionEndpoint "$($NodeFQDN):49006" | Out-Null
                }
                else {
                    Connect-ServiceFabricCluster | Out-Null
                }
                $services = @()
                $services = Get-ServiceFabricService -ApplicationName fabric:/System
                $allServiceHealth = $true
                if ($services.Count -eq 0) {
                    Write-Host "No service fabric services retrieved yet" -ForegroundColor Yellow
                }

                foreach ($service in $services) {
                    if ($service.ServiceStatus -ne "Active" -or $service.HealthState -ne "Ok" ) {
                        Write-Host "$($service.ServiceName) ServiceStatus: $($service.ServiceStatus) HealthState: $($service.HealthState)"
                        $allServiceHealth = $false
                    }
                } 
                if ($allServiceHealth -and $services.Count -gt 0) {
                    Write-Host "All service fabric service has been healthy"
                    return $allServiceHealth
                }
                Start-Sleep -Seconds 5
            }
        }

        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        if($NcVMs -contains $NodeFQDN){
            return Invoke-Command -ScriptBlock $sfServiceHealthScript -ArgumentList $ClusterCredentialType
        }
        else {
            return Invoke-Command -ComputerName $NcVMs[0] -ScriptBlock $sfServiceHealthScript -ArgumentList $ClusterCredentialType -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}