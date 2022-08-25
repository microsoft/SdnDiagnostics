# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnCertificateRotation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        # determine fabric information and current version settings for network controller
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        $ncSettings = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            return [PSCustomObject]@{
                NetworkControllerVersion        = (Get-NetworkController).Version
                NetworkControllerClusterVersion = (Get-NetworkControllerCluster).Version
            }
        }

        "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
        "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

        # return back a list of the current certificates used on the system
        $restCertificate = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerRestCertificate }
        $nodeCertificate = Invoke-PSRemoteCommand -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate }

        # confirm that the current certificates are not expired
        # as that is not currently covered under this function
        $currentCertificates = @()
        $currentCertificates += $restCertificate
        $currentCertificates += $nodeCertificate

        foreach ($currentCer in $currentCertificates) {
            if ($currentCer.NotAfter -le (Get-Date)) {
                $certIsExpired = $true
                "[Thumbprint: {0}] Certificate is expired" | Trace-Output -Level:Warning
            }
        }
        if ($certIsExpired) {
            throw New-Object System.Exception("Network Controller certificates are expired")
        }

        #####################################
        #
        # Rotate NC REST Certificate
        #
        #####################################

        $timeoutInMinutes = 10
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                Set-Networkcontroller -ServerCertificate $using:updatedRestCertificate
            } -Credential $Credential
        }
        catch [InvalidOperationException] {
            if ($_.FullyQualifiedErrorId -ilike "*UpdateInProgress*") {
                "Networkcontroller is being updated by another operation.`n`t{0}" -f $fullyQualifiedErrorId | Trace-Output -Level:Warning
            }
            else {
                $stopWatch.Stop()
                throw $_
            }
        }

        while ($true) {
            if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                throw New-Object System.TimeoutException("Rotate of NC REST certificate did not complete within the alloted time")
            }

            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                Get-Networkcontroller
            } -Credential $Credential

            if ($result.ServerCertificate.Thumbprint -ieq $updatedRestCertificate.Thumbprint) {
                break
            }
            else {
                "Expected and actual certificate thumbprint do not match. Waiting and will retry..." | Trace-Output
                Start-Sleep -Seconds 10
            }
        }

        $stopWatch.Stop()

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################



        #####################################
        #
        # Rotate NC Southbound Certificates
        #
        #####################################

        $headers = @{"Accept"="application/json"}
        $content = "application/json; charset=UTF-8"
        $timeoutInMinutes = 5

        $allCredentials = Get-SdnResource -ResourceType Credentials -Credential $NcRestCredential
        foreach ($cred in $allCredentials) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            if ($cred.properties.type -eq "X509Certificate") {
                "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $networkControllerRestCert.Thumbprint | Trace-Output
                $cred.properties.value = $networkControllerRestCert.Thumbprint
                $credBody = $cred | ConvertTo-Json -Depth 100

                [System.String]$uri = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $cred.resourceRef
                $null = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $NcRestCredential `
                -Headers $headers -ContentType $content -Body $credBody -UseBasicParsing

                while ($true) {
                    if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                        $stopWatch.Stop()
                        throw New-Object System.TimeoutException("Update of $($cred.resourceRef) did not complete within the alloted time")
                    }

                    $result = Invoke-WebRequestWithRetry -Method 'Get' -Uri $uri -Credential $NcRestCredential
                    switch ($result.Status) {
                        'Updating' {
                            "Status: {0}. Waiting for 5 seconds" -f $result.Status | Trace-Output
                            Start-Sleep -Seconds 5
                        }
                        'Failed' {
                            $stopWatch.Stop()
                            throw New-Object System.Exception("Failed to update $($cred.resourceRef)")
                        }
                        'Succeeded' {
                            "Successfully updated {0}" -f $cred.resourceRef | Trace-Output
                            break
                        }
                    }
                }
            }

            $stopWatch.Stop()
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
