# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Copy-CertificateToFabric {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [System.String]$CertFile,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [System.Object]$FabricDetails,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Switch]$NetworkControllerRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerRest')]
        [System.Boolean]$InstallToSouthboundDevices = $false,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [Switch]$NetworkControllerNodeCert,

        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerNode')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    # if we are installing the rest certificate and need to seed certificate to southbound devices
    # then define the variables to know which nodes must be updated
    if ($PSCmdlet.ParameterSetName -ieq 'NetworkControllerRest' -and $InstallToSouthboundDevices) {
        $southBoundNodes = @()
        if ($null -ne $FabricDetails.SoftwareLoadBalancer) {
            $southBoundNodes += $FabricDetails.SoftwareLoadBalancer
        }

        if ($null -ne $FabricDetails.Server) {
            $southBoundNodes += $FabricDetails.Server
        }
    }

    $certFileInfo = Get-Item -Path $CertFile -ErrorAction Stop
    if ($certFileInfo) {
        "Retrieving PfxData for {0}" -f $certFileInfo.FullName | Trace-Output
        $pfxData = Get-PfxData -FilePath $certFileInfo.FullName -Password $CertPassword -ErrorAction Stop
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NetworkControllerRest' {
            # copy the pfx certificate for the rest certificate to all network controllers within the cluster
            # and import to localmachine\my cert directory
            foreach ($controller in $FabricDetails.NetworkController) {
                "Processing {0}" -f $controller | Trace-Output -Level:Verbose

                "[REST CERT] Importing certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                $pfxData.EndEntityCertificates.Subject, $pfxData.EndEntityCertificates.Thumbprint, $controller | Trace-Output

                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    $importCert = Import-SdnCertificate -FilePath $certFileInfo.FullName -CertPassword $CertPassword -CertStore 'Cert:\LocalMachine\My'

                    # if the certificate was detected as self signed
                    # we will then copy the .cer file returned from the previous command to all the southbound nodes to install
                    if ($importCert.SelfSigned -and $InstallToSouthboundDevices) {
                        Install-SdnDiagnostics -ComputerName $southBoundNodes -Credential $Credential -ErrorAction Stop

                        "[REST CERT] Installing self-signed certificate to southbound devices" | Trace-Output
                        Invoke-PSRemoteCommand -ComputerName $southBoundNodes -Credential $Credential -ScriptBlock {
                            if (-NOT (Test-Path -Path $using:importCert.CerFileInfo.Directory.FullName -PathType Container)) {
                                $null = New-Item -Path $using:importCert.CerFileInfo.Directory.FullName -ItemType Directory -Force
                            }
                        }

                        foreach ($sbNode in $southBoundNodes) {
                            "[REST CERT] Installing self-signed certificate to {0}" -f $sbNode | Trace-Output
                            Copy-FileToRemoteComputer -ComputerName $sbNode -Credential $Credential -Path $importCert.CerFileInfo.FullName -Destination $importCert.CerFileInfo.FullName
                            $null = Invoke-PSRemoteCommand -ComputerName $sbNode -Credential $Credential -ScriptBlock {
                                Import-SdnCertificate -FilePath $using:importCert.CerFileInfo.FullName -CertStore 'Cert:\LocalMachine\Root'
                            } -ErrorAction Stop
                        }
                    }
                }
                else {
                    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name
                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        if (-NOT (Test-Path -Path $using:certFileInfo.Directory.FullName -PathType Container)) {
                            New-Item -Path $using:certFileInfo.Directory.FullName -ItemType Directory -Force
                        }
                    }

                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $certFileInfo.FullName -Destination $remoteFilePath

                    $importCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        Import-SdnCertificate -FilePath $using:remoteFilePath -CertPassword $using:CertPassword -CertStore 'Cert:\LocalMachine\My'
                    }
                }
            }
        }

        'NetworkControllerNode' {
            foreach ($controller in $FabricDetails.NetworkController) {
                "Processing {0}" -f $controller | Trace-Output -Level:Verbose
                # if controller is self, then skip as the cert would have been installed into localmachine\my previously
                # and if was self-signed, would have already been added to localmachine\root
                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    "{0} is local. Skipping" -f $controller | Trace-Output -Level:Verbose
                    continue
                }

                # if the certificate being passed is self-signed, we will need to copy the certificate to the other controller nodes
                # within the fabric and install under localmachine\root as appropriate
                if ($pfxData.EndEntityCertificates.Subject -ieq $pfxData.EndEntityCertificates.Issuer) {
                    "[NODE CERT] Importing certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                    $pfxData.EndEntityCertificates.Subject, $pfxData.EndEntityCertificates.Thumbprint, $controller | Trace-Output

                    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name
                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        if (-NOT (Test-Path -Path $using:certFileInfo.Directory.FullName -PathType Container)) {
                            New-Item -Path $using:certFileInfo.Directory.FullName -ItemType Directory -Force
                        }
                    }

                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $certFileInfo.FullName -Destination $remoteFilePath

                    $importCert = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        Import-SdnCertificate -FilePath $using:remoteFilePath -CertPassword $using:CertPassword -CertStore 'Cert:\LocalMachine\Root'
                    } -ErrorAction Stop
                }

                else {
                    "No action required for {0}" -f $pfxData.EndEntityCertificates.Thumbprint | Trace-Output -Level:Verbose
                }
            }
        }
    }
}
