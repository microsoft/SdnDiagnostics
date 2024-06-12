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

    $createRemoteDirectorySB = {
        param([Parameter(Position = 0)][String]$param1)
        if (-NOT (Test-Path -Path $param1 -PathType Container)) {
            New-Item -Path $param1 -ItemType Directory -Force
        }
    }

    # scriptblock to import the certificate
    # this function will automatically install the certificate to the localmachine\root cert directory
    # if the certificate passed to it is self-signed and it is being installed to localmachine\my cert directory
    $importCertSB = {
        param([Parameter(Position = 0)][String]$param1, [Parameter(Position = 1)][SecureString]$param2, [Parameter(Position = 2)][String]$param3)
        Import-SdnCertificate -FilePath $param1 -CertPassword $param2 -CertStore $param3
    }

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
    [System.String]$remoteFilePath = Join-Path -Path $certFileInfo.Directory.FullName -ChildPath $certFileInfo.Name

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
            if (Confirm-IsCertSelfSigned -Certificate $certData) {
                $certStore = 'Cert:\LocalMachine\Root'
                $computersToInstallCert = $FabricDetails.NetworkController
            }
        }

        'NetworkControllerRest' {
            if (Confirm-IsCertSelfSigned -Certificate $certData) {
                if ($InstallToSouthboundDevices) {
                    # for southbound devices, if the certificate is self-signed, we will install the certificate under the localmachine\root cert directory
                    $certStore = 'Cert:\LocalMachine\Root'
                    $computersToInstallCert = $southBoundNodes
                }
                else {
                    # for network controller, we will install the certificate under the localmachine\my cert directory
                    $certStore = 'Cert:\LocalMachine\My'
                    $computersToInstallCert = $FabricDetails.NetworkController
                }
            }
        }

        'NetworkControllerNode' {
            if (Confirm-IsCertSelfSigned -Certificate $certData) {
                $certStore = 'Cert:\LocalMachine\Root'
                $computersToInstallCert = $FabricDetails.NetworkController
            }
        }

        # for ServerNodes, we must distribute the server certificate and install to the cert:\localmachine\root directory on each of the
        # network controller nodes
        'ServerNode' {
            if (Confirm-IsCertSelfSigned -Certificate $certData) {
                $certStore = 'Cert:\LocalMachine\Root'
                $computersToInstallCert = $FabricDetails.NetworkController
            }
        }
    }

    # create the remote directory we need to copy certificate to
    Invoke-PSRemoteCommand @{
        ComputerName = $computersToInstallCert
        Credential   = $Credential
        ScriptBlock  = $createRemoteDirectorySB
        ArgumentList = @($certFileInfo.Directory.FullName)
        ErrorAction  = 'Stop'
    }

    # copy the file
    Copy-FileToRemoteComputer @{
        ComputerName = $computersToInstallCert
        Credential   = $Credential
        Path         = $certFileInfo.FullName
        Destination  = $remoteFilePath
        ErrorAction  = 'Stop'
    }

    # import the certificate
    Invoke-PSRemoteCommand @{
        ComputerName = $computersToInstallCert
        Credential   = $Credential
        ScriptBlock  = $importCertSB
        ArgumentList = @($remoteFilePath, $CertPassword, $certStore)
        ErrorAction  = 'Stop'
    }
}
