function Copy-CertificateToFabric {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LoadBalancerMuxNode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ServerNode')]
        [System.String]$CertFile,

        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerNode')]
        [Parameter(Mandatory = $false, ParameterSetName = 'LoadBalancerMuxNode')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ServerNode')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'LoadBalancerMuxNode')]
        [Parameter(Mandatory = $true, ParameterSetName = 'ServerNode')]
        [System.Object]$FabricDetails,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerRest')]
        [Switch]$NetworkControllerRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerRest')]
        [System.Boolean]$InstallToSouthboundDevices = $false,

        [Parameter(Mandatory = $true, ParameterSetName = 'NetworkControllerNode')]
        [Switch]$NetworkControllerNodeCert,

        [Parameter(Mandatory = $true, ParameterSetName = 'LoadBalancerMuxNode')]
        [Switch]$LoadBalancerMuxNodeCert,

        [Parameter(Mandatory = $true, ParameterSetName = 'ServerNode')]
        [Switch]$ServerNodeCert,

        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerRest')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NetworkControllerNode')]
        [Parameter(Mandatory = $false, ParameterSetName = 'LoadBalancerMuxNode')]
        [Parameter(Mandatory = $false, ParameterSetName = 'ServerNode')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    # if we are installing the rest certificate and need to seed certificate to southbound devices
    # then define the variables to know which nodes must be updated
    if ($PSCmdlet.ParameterSetName -ieq 'NetworkControllerRest' -and $InstallToSouthboundDevices) {
        $southBoundNodes = @()
        if ($null -ne $FabricDetails.LoadBalancerMux) {
            $southBoundNodes += $FabricDetails.LoadBalancerMux
        }

        if ($null -ne $FabricDetails.Server) {
            $southBoundNodes += $FabricDetails.Server
        }
    }

    $certFileInfo = Get-Item -Path $CertFile -ErrorAction Stop
    switch ($certFileInfo.Extension) {
        '.pfx' {
            if ($CertPassword) {
                $certData = (Get-PfxData -FilePath $certFileInfo.FullName -Password $CertPassword).EndEntityCertificates
            }
            else {
                $certData = Get-PfxCertificate -FilePath $certFileInfo.FullName
            }
        }

        '.cer' {
            $certData = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certData.Import($certFileInfo)
        }

        default {
            throw New-Object System.NotSupportedException("Unsupported certificate extension")
        }
    }

    switch ($PSCmdlet.ParameterSetName) {
        'LoadBalancerMuxNode' {
            foreach ($controller in $FabricDetails.NetworkController) {
                # if the certificate being passed is self-signed, we will need to copy the certificate to the other controller nodes
                # within the fabric and install under localmachine\root as appropriate
                if ($certData.Subject -ieq $certData.Issuer) {
                    "Importing certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                    $certData.Subject, $certData.Thumbprint, $controller | Trace-Output

                    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name
                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1)
                        if (-NOT (Test-Path -Path $param1 -PathType Container)) {
                            New-Item -Path $param1 -ItemType Directory -Force
                        }
                    } -ArgumentList $certFileInfo.Directory.FullName

                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $certFileInfo.FullName -Destination $remoteFilePath

                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][SecureString]$param2, [Parameter(Position = 2)][String]$param3)
                        Import-SdnCertificate -FilePath $param1 -CertPassword $param2 -CertStore $param3
                    } -ArgumentList @($remoteFilePath, $CertPassword, 'Cert:\LocalMachine\Root') -ErrorAction Stop
                }

                else {
                    "No action required for {0}" -f $certData.Thumbprint | Trace-Output -Level:Verbose
                }
            }
        }

        'NetworkControllerRest' {
            # copy the pfx certificate for the rest certificate to all network controllers within the cluster
            # and import to localmachine\my cert directory
            foreach ($controller in $FabricDetails.NetworkController) {
                "Processing {0}" -f $controller | Trace-Output -Level:Verbose

                "[REST CERT] Importing certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                $certData.Subject, $certData.Thumbprint, $controller | Trace-Output

                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    $importCert = Import-SdnCertificate -FilePath $certFileInfo.FullName -CertPassword $CertPassword -CertStore 'Cert:\LocalMachine\My'

                    # if the certificate was detected as self signed
                    # we will then copy the .cer file returned from the previous command to all the southbound nodes to install
                    if ($importCert.SelfSigned -and $InstallToSouthboundDevices) {
                        Install-SdnDiagnostics -ComputerName $southBoundNodes -Credential $Credential -ErrorAction Stop

                        "[REST CERT] Installing self-signed certificate to southbound devices" | Trace-Output
                        Invoke-PSRemoteCommand -ComputerName $southBoundNodes -Credential $Credential -ScriptBlock {
                            param([Parameter(Position = 0)][String]$param1)
                            if (-NOT (Test-Path -Path $param1 -PathType Container)) {
                                $null = New-Item -Path $param1 -ItemType Directory -Force
                            }
                        } -ArgumentList $importCert.CerFileInfo.Directory.FullName

                        foreach ($sbNode in $southBoundNodes) {
                            "[REST CERT] Installing self-signed certificate to {0}" -f $sbNode | Trace-Output
                            Copy-FileToRemoteComputer -ComputerName $sbNode -Credential $Credential -Path $importCert.CerFileInfo.FullName -Destination $importCert.CerFileInfo.FullName
                            $null = Invoke-PSRemoteCommand -ComputerName $sbNode -Credential $Credential -ScriptBlock {
                                param([Parameter(Position = 0)][String]$param1,[Parameter(Position = 1)][String]$param2)
                                Import-SdnCertificate -FilePath $param1 -CertStore $param2
                            } -ArgumentList @($importCert.CerFileInfo.FullName, 'Cert:\LocalMachine\Root') -ErrorAction Stop
                        }
                    }
                }
                else {
                    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name
                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1)
                        if (-NOT (Test-Path -Path $param1 -PathType Container)) {
                            New-Item -Path $param1 -ItemType Directory -Force
                        }
                    } -ArgumentList $certFileInfo.Directory.FullName

                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $certFileInfo.FullName -Destination $remoteFilePath

                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][SecureString]$param2, [Parameter(Position = 2)][String]$param3)
                        Import-SdnCertificate -FilePath $param1 -CertPassword $param2 -CertStore $param3
                    } -ArgumentList @($remoteFilePath, $CertPassword, 'Cert:\LocalMachine\My')
                }
            }
        }

        'NetworkControllerNode' {
            foreach ($controller in $FabricDetails.NetworkController) {
                "Processing {0}" -f $controller | Trace-Output -Level:Verbose

                # if the certificate being passed is self-signed, we will need to copy the certificate to the other controller nodes
                # within the fabric and install under localmachine\root as appropriate
                if ($certData.Subject -ieq $certData.Issuer) {
                    "Importing certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                    $certData.Subject, $certData.Thumbprint, $controller | Trace-Output

                    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name
                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1)
                        if (-NOT (Test-Path -Path $param1 -PathType Container)) {
                            New-Item -Path $param1 -ItemType Directory -Force
                        }
                    } -ArgumentList $certFileInfo.Directory.FullName

                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $certFileInfo.FullName -Destination $remoteFilePath

                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][SecureString]$param2, [Parameter(Position = 2)][String]$param3)
                        Import-SdnCertificate -FilePath $param1 -CertPassword $param2 -CertStore $param3
                    } -ArgumentList @($remoteFilePath, $CertPassword, 'Cert:\LocalMachine\Root') -ErrorAction Stop
                }

                else {
                    "No action required for {0}" -f $certData.Thumbprint | Trace-Output -Level:Verbose
                }
            }
        }

        # for ServerNodes, we must distribute the server certificate and install to the cert:\localmachine\root directory on each of the
        # network controller nodes
        'ServerNode' {
            foreach ($controller in $FabricDetails.NetworkController) {
                # if the certificate being passed is self-signed, we will need to copy the certificate to the other controller nodes
                # within the fabric and install under localmachine\root as appropriate
                if ($certData.Subject -ieq $certData.Issuer) {
                    "Importing certificate [Subject: {0} Thumbprint:{1}] to {2}" -f `
                    $certData.Subject, $certData.Thumbprint, $controller | Trace-Output

                    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name
                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1)
                        if (-NOT (Test-Path -Path $param1 -PathType Container)) {
                            New-Item -Path $param1 -ItemType Directory -Force
                        }
                    } -ArgumentList $certFileInfo.Directory.FullName

                    Copy-FileToRemoteComputer -ComputerName $controller -Credential $Credential -Path $certFileInfo.FullName -Destination $remoteFilePath

                    $null = Invoke-PSRemoteCommand -ComputerName $controller -Credential $Credential -ScriptBlock {
                        param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][SecureString]$param2, [Parameter(Position = 2)][String]$param3)
                        Import-SdnCertificate -FilePath $param1 -CertPassword $param2 -CertStore $param3
                    } -ArgumentList @($remoteFilePath, $CertPassword, 'Cert:\LocalMachine\Root') -ErrorAction Stop
                }

                else {
                    "No action required for {0}" -f $certData.Thumbprint | Trace-Output -Level:Verbose
                }
            }
        }
    }
}
