
function Invoke-CertRotateCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Set-NetworkController', 'Set-NetworkControllerCluster', 'Set-NetworkControllerNode')]
        [System.String]$Command,

        [Parameter(Mandatory = $false)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [System.String]$Thumbprint,

        [Parameter(Mandatory = $false)]
        [Int]$TimeoutInMinutes = 30,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRetry = 3
    )

    if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
        throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $retryAttempt = 0

    $params = @{
        'PassThru'  = $true
    }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }

    if (Test-ComputerNameIsLocal -ComputerName $NetworkController) {
        $cert = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $Thumbprint
    }
    else {
        $params.Add('ComputerName', $NetworkController)
        $cert = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
            param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][String]$param2)
            Get-SdnCertificate -Path $param1 -Thumbprint $param2
        } -ArgumentList @('Cert:\LocalMachine\My', $Thumbprint)
    }

    if ($null -eq $cert) {
        throw New-Object System.NullReferenceException("Unable to locate $($Thumbprint)")
    }
    if ($cert.Count -ge 2) {
        throw New-Object System.Exception("Duplicate certificates located that match $($Thumbprint)")
    }

    switch ($Command) {
        'Set-NetworkController' {
            $params.Add('ServerCertificate', $cert)
        }
        'Set-NetworkControllerCluster' {
            $params.Add('CredentialEncryptionCertificate', $cert)
        }
        'Set-NetworkControllerNode' {
            $ncNode = Get-SdnNetworkControllerSFNode -NetworkController $NetworkController -Name $Name -Credential $Credential

            $params.Add('Name', $ncNode.Name)
            $params.Add('NodeCertificate', $cert)
        }
    }

    $waitBeforeRetry = $false
    while ($true) {
        $retryAttempt++
        switch ($Command) {
            'Set-NetworkController' {
                $currentCertThumbprint = (Get-SdnNetworkControllerRestCertificate).Thumbprint
            }
            'Set-NetworkControllerCluster' {
                $currentCertThumbprint = (Get-NetworkControllerCluster).CredentialEncryptionCertificate.Thumbprint
            }
            'Set-NetworkControllerNode' {
                $currentCert = Invoke-PSRemoteCommand -ComputerName $NetworkController -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                } -ErrorAction Stop
                $currentCertThumbprint = $currentCert.Thumbprint
            }
        }

        # if the certificate already matches what has been configured, then break out of the loop
        if ($currentCertThumbprint -ieq $Thumbprint) {
            "{0} has been updated to use certificate thumbprint {1}" -f $Command.Split('-')[1], $currentCertThumbprint | Trace-Output
            break
        }

        if ($stopWatch.Elapsed.TotalMinutes -ge $timeoutInMinutes) {
            throw New-Object System.TimeoutException("Rotate of certificate did not complete within the alloted time.")
        }

        if ($retryAttempt -ge $MaxRetry) {
            throw New-Object System.Exception("Rotate of certificate exceeded maximum number of retries.")
        }

        # if we have not started operation, or we hit a retryable error
        # then invoke the command to start the certificate rotate
        try {
            if ($waitBeforeRetry) {
                "Waiting 5 minutes before retrying operation..." | Trace-Output
                Start-Sleep -Seconds 300
            }

            "Invoking {0} to configure thumbprint {1}" -f $Command, $cert.Thumbprint | Trace-Output
            "Command:{0} Params: {1}" -f $Command, ($params | ConvertTo-Json) | Trace-Output -Level:Verbose

            switch ($Command) {
                'Set-NetworkController' {
                    Set-NetworkController @params
                }
                'Set-NetworkControllerCluster' {
                    Set-NetworkControllerCluster @params
                }
                'Set-NetworkControllerNode' {
                    Set-NetworkControllerNode @params
                }
            }
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            switch -Wildcard ($_.Exception) {
                '*One or more errors occurred*' {
                    "Retryable exception caught`n`t$_" | Trace-Output -Level:Warning
                    $waitBeforeRetry = $true
                    break
                }

                '*A generic error has occurred*' {
                    "Retryable exception caught`n`t$_" | Trace-Output -Level:Warning
                    $waitBeforeRetry = $true
                    break
                }

                '*The I/O operation has been aborted because of either a thread exit or an application request*' {
                    "Retryable exception caught`n`t$_" | Trace-Output -Level:Warning
                    $waitBeforeRetry = $true
                    break
                }

                default {
                    $stopWatch.Stop()
                    throw $_
                }
            }
        }
        catch [InvalidOperationException] {
            if ($_.FullyQualifiedErrorId -ilike "*UpdateInProgress*") {
                "Networkcontroller is being updated by another operation.`n`t{0}" -f $fullyQualifiedErrorId | Trace-Output -Level:Warning
                $waitBeforeRetry = $true
            }
            else {
                $stopWatch.Stop()
                throw $_
            }
        }
        catch {
            $stopWatch.Stop()
            throw $_
        }
    }

    $stopWatch.Stop()
    return $currentCertThumbprint
}
