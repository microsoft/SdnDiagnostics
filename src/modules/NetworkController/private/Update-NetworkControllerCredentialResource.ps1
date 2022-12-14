# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Update-NetworkControllerCredentialResource {
    <#
    .SYNOPSIS
        Update the Credential Resource in Network Controller with new certificate.
    .PARAMETER NcUri
        The Network Controller REST URI.
    .PARAMETER NewRestCertThumbprint
        The new Network Controller REST Certificate Thumbprint to be used by credential resource.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        $NcUri,

        [Parameter(Mandatory = $true)]
        [System.String]
        $NewRestCertThumbprint,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $headers = @{"Accept"="application/json"}
    $content = "application/json; charset=UTF-8"
    $timeoutInMinutes = 10
    $array = @()

    $servers = Get-SdnServer -NcUri $NcUri -Credential $Credential
    foreach ($object in $servers) {
        "Processing X509 connections for {0}" -f $object | Trace-Output
        foreach ($connection in $servers.properties.connections | Where-Object {$_.credentialType -ieq 'X509Certificate'}) {
            $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

            $cred = Get-SdnResource -NcUri $NcUri -ResourceRef $connection.credential.resourceRef -Credential $Credential

            # if for any reason the certificate thumbprint has been updated, then skip the update operation for this credential resource
            if ($cred.properties.value -ieq $NewRestCertThumbprint) {
                "{0} has already been configured to {1}" -f $cred.resourceRef, $NewRestCertThumbprint | Trace-Output -Level:Verbose
                continue
            }

            "{0} will be updated from {1} to {2}" -f $cred.resourceRef, $cred.properties.value, $NewRestCertThumbprint | Trace-Output
            $cred.properties.value = $NewRestCertThumbprint
            $credBody = $cred | ConvertTo-Json -Depth 100

            [System.String]$uri = Get-SdnApiEndpoint -NcUri $NcUri -ResourceRef $cred.resourceRef
            $null = Invoke-WebRequestWithRetry -Method 'Put' -Uri $uri -Credential $Credential -UseBasicParsing `
            -Headers $headers -ContentType $content -Body $credBody

            while ($true) {
                if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
                    $stopWatch.Stop()
                    throw New-Object System.TimeoutException("Update of $($cred.resourceRef) did not complete within the alloted time")
                }

                $result = Invoke-RestMethodWithRetry -Method 'Get' -Uri $uri -Credential $Credential -UseBasicParsing
                switch ($result.properties.provisioningState) {
                    'Updating' {
                        "Status: {0}" -f $result.properties.provisioningState | Trace-Output
                        Start-Sleep -Seconds 15
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

            $array += $result
        }
    }

    return $array
}
