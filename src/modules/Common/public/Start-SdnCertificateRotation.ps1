# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operate
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    #>

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
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [Switch]$SelfSigned
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

        # return back a list of the current certificates used on the system and confirm that the current certificates are not expired
        $currentCertificates = @()
        $currentCertificates += Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerRestCertificate }
        $currentCertificates += Invoke-PSRemoteCommand -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate }

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
        # Parse the certificates within CertificatePath and then map to the appropriate nodes
        #
        #####################################

        $certificateConfig = @{
            NetworkController = @{}
            Server = @{}
            SoftwareLoadBalancer = @{}
            $RestCertificate = $null
        }

        $pfxCerts = Get-ChildItem -Path $CertificatePath.FullName -Filter '*.pfx'
        if ($null -eq $pfxCerts) {
            throw New-Object System.NullReferenceException("Unable to locate .pfx files under specified CertPath")
        }

        foreach ($pfxCert in $pfxCerts) {
            $pfxData = Get-PfxData -FilePath $pfxCert.FullName -Password $CertPassword
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        $timeoutInMinutes = 10
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                Set-Networkcontroller -ServerCertificate $using:newRestCertificate
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

            if ($result.ServerCertificate.Thumbprint -ieq $newRestCertificate.Thumbprint) {
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
        # Rotate Cluster Certificate
        #
        #####################################

        $timeoutInMinutes = 10
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        try {
            Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
                Set-NetworkControllerCluster -CredentialEncryptionCertificate $using:newRestCertificate
            }
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
                throw New-Object System.TimeoutException("Rotate of NC cluster certificate did not complete within the alloted time")
            }

            $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {
                Get-NetworkControllerCluster
            } -Credential $Credential

            if ($result.CredentialEncryptionCertificate.Thumbprint -ieq $newRestCertificate.Thumbprint) {
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

        foreach ($node in $sdnFabricDetails.NetworkController){
            $timeoutInMinutes = 10
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            $newNodeCertificate = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                # TODO: add the script logic to return what certificate should be configured here
            }

            try {
                Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    Set-NetworkControllerNode -Name $env:COMPUTERNAME -NodeCertificate $using:newNodeCertificate
                }
            }
            catch [InvalidOperationException] {
                $stopWatch.Stop()
                throw $_
            }

            while ($true) {
                if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                    throw New-Object System.TimeoutException("Rotate of NC cluster certificate did not complete within the alloted time")
                }

                $result = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                if ($result.NodeCertificate.Thumbprint -ieq $updatedRestCertificate.Thumbprint) {
                    break
                }
                else {
                    "Expected and actual certificate thumbprint do not match. Waiting and will retry..." | Trace-Output
                    Start-Sleep -Seconds 10
                }
            }

            $stopWatch.Stop()
        }

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
                "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $newRestCertificate.Thumbprint | Trace-Output
                $cred.properties.value = $newRestCertificate.Thumbprint
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
                            "Status: {0}" -f $result.Status | Trace-Output
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
