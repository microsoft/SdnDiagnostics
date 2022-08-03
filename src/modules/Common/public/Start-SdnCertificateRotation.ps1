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
        $currentCertificates = @()
        $currentCertificates += Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerRestCertificate }
        $currentCertificates += Invoke-PSRemoteCommand -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate }

        # confirm that the current certificates are not expired
        # as that is not currently covered under this function
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

        $allCredentials = Get-SdnResource -ResourceType Credentials -Credential $NcRestCredential
        foreach ($cred in $allCredentials) {
            if ($cred.properties.type -eq "X509Certificate") {
                "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $networkControllerRestCert.Thumbprint | Trace-Output
                $cred.properties.value = $networkControllerRestCert.Thumbprint
                $credBody = $cred | ConvertTo-Json -Depth 100

                [System.String]$uri = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $cred.resourceRef
                $null = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $NcRestCredential `
                -Headers $headers -ContentType $content -Body $credBody -UseBasicParsing

                while ($true) {
                    $result = Invoke-WebRequestWithRetry -Method 'Get' -Uri $uri -Credential $NcRestCredential
                    switch ($result.Status) {
                        'Updating' {
                            "Status: {0}. Waiting for 5 seconds" -f $result.Status | Trace-Output
                            Start-Sleep -Seconds 5
                        }
                        'Failed' {
                            throw New-Object System.Exception("Failed to update $($cred.resourceRef)")
                        }
                        'Succeeded' {
                            "Successfully updated {0}" -f $cred.resourceRef | Trace-Output
                            break
                        }
                    }
                }
            }
        }


    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
