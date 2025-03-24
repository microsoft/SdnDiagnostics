# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Common.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Common' -Scope 'Script' -Force -Value @{
    Cache = @{}
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

##########################
#### ARG COMPLETERS ######
##########################

##########################
####### FUNCTIONS ########
##########################

function Add-SdnDiagTraceMapping {
    param (
        [Parameter(Mandatory=$true)]
        [string]$MacAddress,

        [Parameter(Mandatory=$true)]
        [string]$InfraHost,

        [Parameter(Mandatory=$false)]
        [string]$PortId,

        [Parameter(Mandatory=$false)]
        [string]$PortName,

        [Parameter(Mandatory=$false)]
        [string]$NicName,

        [Parameter(Mandatory=$false)]
        [string]$VmName,

        [Parameter(Mandatory=$false)]
        [string]$VmInternalId,

        [Parameter(Mandatory=$false)]
        [string[]]$PrivateIpAddress
    )

    $cacheName = 'TraceMapping'
    $mapping = @{
        MacAddress = $MacAddress
        PortId = $PortId
        PortName = $PortName
        NicName = $NicName
        VmName = $VmName
        VmInternalId = $VmInternalId
        InfraHost = $InfraHost
        PrivateIpAddress = $PrivateIpAddress
    }

    if (!$Script:SdnDiagnostics_Common.Cache.ContainsKey($cacheName)) {
        $Script:SdnDiagnostics_Common.Cache.Add($cacheName, @{})
    }

    if (!$Script:SdnDiagnostics_Common.Cache[$cacheName].ContainsKey($InfraHost.ToLower())) {
        $Script:SdnDiagnostics_Common.Cache[$cacheName].Add($InfraHost.ToLower(), @{})
    }

    $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost.ToLower()][$MacAddress] += $mapping
}

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
                if (Confirm-IsCertSelfSigned -Certificate $certData) {
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
                if (Confirm-IsCertSelfSigned -Certificate $certData) {
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
                if (Confirm-IsCertSelfSigned -Certificate $certData) {
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


function Copy-UserProvidedCertificateToFabric {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$CertPath,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $true)]
        [System.Object]$FabricDetails,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$RotateNodeCerts = $false,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$NetworkControllerHealthy = $false,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $certificateCache = @()
    $certificateConfig = @{
        RestCert          = $null
        NetworkController = @{}
    }

    "Scanning certificates within {0}" -f $CertPath.FullName | Trace-Output
    $pfxFiles = Get-ChildItem -Path $CertPath.FullName -Filter '*.pfx'
    if ($null -eq $pfxFiles) {
        throw New-Object System.NullReferenceException("Unable to locate .pfx files under the specified CertPath location")
    }

    foreach ($pfxFile in $pfxFiles) {
        "Retrieving PfxData for {0}" -f $pfxFile.FullName | Trace-Output
        $pfxData = Get-PfxData -FilePath $pfxFile.FullName -Password $CertPassword -ErrorAction Stop

        $object = [PSCustomObject]@{
            FileInfo = $pfxFile
            PfxData  = $pfxData
            SelfSigned = $false
        }

        $certificateCache += $object
    }

    "Retrieving Rest Certificate" | Trace-Output -Level:Verbose
    $currentRestCertificate = Get-SdnNetworkControllerRestCertificate

    # enumerate the current certificates within the cache to isolate the rest certificate
    foreach ($cert in $certificateCache) {
        if ($cert.pfxdata.EndEntityCertificates.Subject -ieq $currentRestCertificate.Subject) {
            "Matched {0} [Subject: {1}; Thumbprint: {2}] to NC Rest Certificate" -f `
                $cert.pfxFile.FileInfo.FullName, $cert.pfxData.EndEntityCertificates.Subject, $cert.pfxData.EndEntityCertificates.Thumbprint | Trace-Output -Level:Verbose

            $cert | Add-Member -MemberType NoteProperty -Name 'CertificateType' -Value 'NetworkControllerRest'
            $restCertificate = $cert
            $certificateConfig.RestCert = $restCertificate.pfxData.EndEntityCertificates.Thumbprint
        }

        if (Confirm-IsCertSelfSigned -Certificate $cert.pfxdata.EndEntityCertificates) {
            $cert.SelfSigned = $true
        }
    }

    # enumerate the certificates for network controller nodes
    if ($RotateNodeCerts) {
        foreach ($node in $FabricDetails.NetworkController) {
            "Retrieving current node certificate for {0}" -f $node | Trace-Output
            $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node -Credential $Credential -ScriptBlock { Get-SdnNetworkControllerNodeCertificate } -ErrorAction Stop
            foreach ($cert in $certificateCache) {
                $updatedNodeCert = $null
                if ($cert.PfxData.EndEntityCertificates.Subject -ieq $currentNodeCert.Subject) {
                    $updatedNodeCert = $cert
                    "Matched {0} [Subject: {1}; Thumbprint: {2}] to {3}" -f `
                        $updatedNodeCert.FileInfo.Name, $cert.PfxData.EndEntityCertificates.Subject, $cert.PfxData.EndEntityCertificates.Thumbprint, $node | Trace-Output

                    $cert | Add-Member -MemberType NoteProperty -Name 'CertificateType' -Value 'NetworkControllerNode'
                    break
                }
            }

            $certificateConfig.NetworkController[$node] = @{
                Cert = $updatedNodeCert
            }
        }
    }

    # install the rest certificate to the network controllers to this node first
    # then seed out to the rest of the fabric
    $null = Import-SdnCertificate -FilePath $restCertificate.FileInfo.FullName -CertPassword $CertPassword -CertStore 'Cert:\LocalMachine\My'
    Copy-CertificateToFabric -CertFile $restCertificate.FileInfo.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
    -NetworkControllerRestCertificate -InstallToSouthboundDevices:$NetworkControllerHealthy -Credential $Credential

    # install the nc node certificate to other network controller nodes if self-signed
    if ($RotateNodeCerts) {
        foreach ($controller in $FabricDetails.NetworkController) {
            "Processing {0} for node certificates" -f $controller | Trace-Output -Level:Verbose
            $nodeCertConfig = $certificateConfig.NetworkController[$controller]

            # if we have identified a network controller node certificate then proceed
            # with installing the cert locally (if matches current node)
            if ($null -ne $nodeCertConfig.Cert.FileInfo.FullName) {
                if (Test-ComputerNameIsLocal -ComputerName $controller) {
                    $null = Import-SdnCertificate -FilePath $nodeCertConfig.Cert.FileInfo.FullName -CertPassword $CertPassword -CertStore 'Cert:\LocalMachine\My'
                }


                # pass the certificate to sub-function to be seeded across the fabric if necassary
                Copy-CertificateToFabric -CertFile $nodeCertConfig.Cert.FileInfo.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails -NetworkControllerNodeCert -Credential $Credential
            }
            else {
                "Unable to locate self-signed certificate file for {0}. Node certificate may need to be manually installed to other Network Controllers manually." -f $controller | Trace-Output -Level:Error
            }
        }
    }

    return $certificateCache
}

function Export-RegistryKeyConfigDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    try {
        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        foreach($regKeyPath in $Path){
            "Enumerating the registry key paths for {0}" -f $regkeyPath | Trace-Output -Level:Verbose

            $regKeyDirectories = @()
            $regKeyDirectories += Get-Item -Path $regKeyPath -ErrorAction SilentlyContinue
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -Recurse -ErrorAction SilentlyContinue
            $regKeyDirectories = $regKeyDirectories | Sort-Object -Unique

            [System.String]$filePath = "{0}\Registry_{1}.txt" -f $OutputDirectory.FullName, $($regKeyPath.Replace(':','').Replace('\','_'))
            foreach($obj in $RegKeyDirectories){
                "Scanning {0}" -f $obj.PsPath | Trace-Output -Level:Verbose
                try {
                    $properties = Get-ItemProperty -Path $obj.PSPath -ErrorAction Stop

                    # check to see if we are lookiing at cluster network controller registry key, if so, then redact the AESKey
                    if ($obj.PSPath -ilike "*Cluster\NetworkController*") {
                        $properties.'GlobalConfiguration.AESKey' = "removed_for_security_reasons"
                    }
                }
                catch {
                    "Unable to return results from {0}`n`t{1}" -f $obj.PSPath, $_.Exception | Trace-Output -Level:Warning
                    continue
                }

                $properties | Out-File -FilePath $filePath -Encoding utf8 -Append

                # if the registry key item is referencing a dll, then lets get the dll properties so we can see the version and file information
                if($properties.Path -like "*.dll" -or $properties.Path -like "*.exe"){
                    "Getting file properties for {0}" -f $properties.Path | Trace-Output -Level:Verbose
                    [System.String]$fileName = "FileInfo_{0}" -f $($properties.Path.Replace(':','').Replace('\','_').Replace('.','_'))
                    Get-Item -Path $properties.Path | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name $fileName -FileType txt -Format List
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-CommonConfigState {
    <#
        .SYNOPSIS
            Retrieves a common set of configuration details that is collected on any role, regardless of the role.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'
    [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState\Common"

    try {
        $config = Get-SdnModuleConfiguration -Role 'Common'
        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output
        if (-NOT (Initialize-DataCollection -FilePath $outDir -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        # Gather general configuration details from all nodes
        "Gathering system details" | Trace-Output -Level:Verbose
        Get-Service | Export-ObjectToFile -FilePath $outDir -FileType csv -Force
        Get-Process | Export-ObjectToFile -FilePath $outDir -FileType csv -Force
        Get-Volume | Export-ObjectToFile -FilePath $outDir -FileType txt -Format Table
        Get-ComputerInfo | Export-ObjectToFile -FilePath $outDir -FileType txt

        # gather network related configuration details
        "Gathering network details" | Trace-Output -Level:Verbose

        # nettcpip module commands
        Get-NetCompartment | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetIPAddress | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetIPConfiguration | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetIPInterface -IncludeAllCompartments | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetIPv4Protocol | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetIPv6Protocol | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetNeighbor -IncludeAllCompartments | Export-ObjectToFile -FilePath $outDir -FileType csv -Force
        Get-NetOffloadGlobalSetting | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetPrefixPolicy | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Export-ObjectToFile -FilePath $outDir -FileType csv -Force
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess -ErrorAction $ErrorActionPreference).ProcessName}} `
        | Export-ObjectToFile -FilePath $outDir -Name 'Get-NetTCPConnection' -FileType csv -Force
        Get-NetTCPSetting | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetTransportFilter | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetUDPEndpoint | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetUDPSetting | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        # netconnection module commands
        Get-NetConnectionProfile | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        # netadapter module commands
        Get-NetAdapter -IncludeHidden | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterAdvancedProperty | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterBinding | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterChecksumOffload | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterDataPathConfiguration | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterEncapsulatedPacketTaskOffload | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterHardwareInfo | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterIPsecOffload | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterLso | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterPacketDirect| Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterPowerManagement | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterQos | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterRdma | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterRsc | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterRss | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterSriov | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterSriovVf | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterStatistics | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterUso | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterVmq | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterVmqQueue | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-NetAdapterVPort | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        ipconfig /allcompartments /all | Export-ObjectToFile -FilePath $outDir -Name 'ipconfig_allcompartments' -FileType txt -Force
        netsh winhttp show proxy | Export-ObjectToFile -FilePath $outDir -Name 'netsh_winhttp_show_proxy' -FileType txt -Force

        Get-SmbClientNetworkInterface | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-SmbClientConfiguration | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        # Gather DNS client settings
        Get-DnsClient | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientCache | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientServerAddress | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientGlobalSetting | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientNrptGlobal | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientNrptPolicy | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientNrptRule | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List
        Get-DnsClientServerAddress | Export-ObjectToFile -FilePath $outDir -FileType txt -Format List

        # gather the certificates configured on the system
        $certificatePaths = @('Cert:\LocalMachine\My','Cert:\LocalMachine\Root')
        foreach ($path in $certificatePaths) {
            $fileName = $path.Replace(':','').Replace('\','_')
            Get-SdnCertificate -Path $path | Export-ObjectToFile -FilePath $outDir -Name "Get-SdnCertificate_$($fileName)" -FileType csv -Force
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

function Get-SdnRole {
    <#
    .SYNOPSIS
        Retrieve the SDN Role for a given computername
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $true)]
        [System.Object]$EnvironmentInfo
    )

    # get the NetBIOS and FQDN name of the computer
    $result = Get-ComputerNameFQDNandNetBIOS -ComputerName $ComputerName

    # enumerate the objects for each of the available SDN roles to find a match
    # once match is found, return the role name as string back to calling function
    foreach ($role in $EnvironmentInfo.Keys) {
        if ($role -ieq 'FabricNodes') {
            continue
        }

        foreach ($object in $EnvironmentInfo[$role]) {
            if ($object -ieq $result.ComputerNameNetBIOS -or $object -ieq $result.ComputerNameFQDN) {
                return $role.ToString()
            }
        }
    }

    # if we made it to here, we were unable to locate any specific SdnRole such as LoadBalancerMux, Gateway, etc.
    # so instead we will return Common as the role
    return ([string]"Common")
}

function Get-TraceProviders {
    <#
    .SYNOPSIS
        Get ETW Trace Providers based on Role
    .PARAMETER Role
        The SDN Roles
    .PARAMETER Providers
        Allowed values are Default,Optional And All to control what are the providers needed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default",

        [Parameter(Mandatory = $false)]
        [Switch]$AsString
    )

    $traceProvidersArray = @()

    try {
        $config = Get-SdnModuleConfiguration -Role $Role
        if ($null -eq $config.properties.EtwTraceProviders) {
            return $null
        }

        foreach ($key in $config.properties.EtwTraceProviders.Keys) {
            $traceProvider = $config.properties.EtwTraceProviders[$key]
            switch ($Providers) {
                "Default" {
                    if ($traceProvider.isOptional -ne $true) {
                        $traceProvidersArray += [PSCustomObject]@{
                            Name = $key
                            Properties = $traceProvider
                        }
                    }
                }
                "Optional" {
                    if ($traceProvider.isOptional -eq $true) {
                        $traceProvidersArray += [PSCustomObject]@{
                            Name = $key
                            Properties = $traceProvider
                        }
                    }
                }
                "All" {
                    $traceProvidersArray += [PSCustomObject]@{
                        Name = $key
                        Properties = $traceProvider
                    }
                }
            }
        }

        # we want to be able to return string value back so it can then be passed to netsh trace command
        # enumerate the properties that have values to build a formatted string that netsh expects
        if ($PSBoundParameters.ContainsKey('AsString') -and $traceProvidersArray) {
            [string]$formattedString = $null
            foreach ($traceProvider in $traceProvidersArray) {
                foreach ($provider in $traceProvider.Properties.Providers) {
                    $formattedString += "$(Format-NetshTraceProviderAsString -Provider $provider -Level $traceProvider.level -Keywords $traceProvider.keywords) "
                }
            }

            return $formattedString.Trim()
        }

        return $traceProvidersArray
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnDiagNetworkMappedShare {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.contains("\\") -and $_.contains("\")) {
                return $true
            }
            else {
                throw "The network share path must be in the format of \\server\share"
            }
        })]
        [System.String]$NetworkSharePath,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Creating new drive mapping to {0}" -f $NetworkSharePath | Trace-Output

        # create a new drive mapping to the network share path
        # if the credential is empty, we will not use a credential
        if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
            $null = New-PSDrive -Name "SdnDiag_NetShare_Logs" -PSProvider FileSystem -Root $NetworkSharePath -ErrorAction Stop
        }
        else {
            $null = New-PSDrive -Name "SdnDiag_NetShare_Logs" -PSProvider FileSystem -Root $NetworkSharePath -Credential $Credential -ErrorAction Stop
        }

        "Successfully created network share mapping to {0}" -f $NetworkSharePath | Trace-Output
        return $true
    }
    catch {
        $_ | Trace-Exception
        return $false
    }
}

function Reset-SdnDiagTraceMapping {
    $Script:SdnDiagnostics_Common.Cache['TraceMapping'] = @{}
}

function Start-EtwTraceSession {
    <#
    .SYNOPSIS
        Start the ETW trace with TraceProviders included.
    .PARAMETER TraceName
        The trace name to identify the ETW trace session
    .PARAMETER TraceProviders
        The trace providers in string format that you want to trace on
    .PARAMETER TraceFile
        The trace file that will be written.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1024.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TraceName,

        [Parameter(Mandatory = $true)]
        [string[]]$TraceProviders,

        [Parameter(Mandatory = $true)]
        [ValidateScript( {
                if ($_ -notmatch "(\.etl)") {
                    throw "The file specified in the TraceFile argument must be etl extension"
                }
                return $true
            })]
        [System.IO.FileInfo]$TraceFile,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024
    )

    try {
        $logmanCmd = "logman create trace $TraceName -ow -o $TraceFile -nb 16 16 -bs 1024 -mode Circular -f bincirc -max $MaxTraceSize -ets"
        $result = Invoke-Expression -Command $logmanCmd

        # Session create failure error need to be reported to user to be aware, this means we have one trace session missing.
        # Provider add failure might be ignored and exposed via verbose trace/log file only to debug.
        if ("$result".Contains("Error")) {
            "Create session {0} failed with error {1}" -f $TraceName, "$result" | Trace-Output -Level:Warning
        }
        else {
            "Created session {0} with result {1}" -f $TraceName, "$result" | Trace-Output -Level:Verbose
        }

        foreach ($provider in $TraceProviders) {
            $logmanCmd = 'logman update trace $TraceName -p "$provider" 0xffffffffffffffff 0xff -ets'
            $result = Invoke-Expression -Command $logmanCmd
            "Added provider {0} with result {1}" -f $provider, "$result" | Trace-Output -Level:Verbose
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Start-NetshTrace {
    <#
    .SYNOPSIS
        Enables netsh tracing. Supports pre-configured trace providers or custom provider strings.
    .PARAMETER TraceProviderString
        The trace providers in string format that you want to trace on.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1024.
    .PARAMETER Capture
        Optional. Specifies whether packet capture is enabled in addition to trace events. If unspecified, the default is No.
    .PARAMETER Overwrite
        Optional. Specifies whether this instance of the trace conversion command overwrites files that were rendered from previous trace conversions. If unspecified, the default is Yes.
    .PARAMETER Correlation
        Optional. Specifies whether related events will be correlated and grouped together. If unspecified, the default is disabled.
    .PARAMETER Report
        Optional. Specifies whether a complementing report will be generated in addition to the trace file report. If unspecified, the default is disabled.
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -TraceProviderString 'provider="{EB171376-3B90-4169-BD76-2FB821C4F6FB}" level=0xff' -Capture No
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -TraceProviderString 'provider="{EB171376-3B90-4169-BD76-2FB821C4F6FB}" level=0xff' -Capture Yes
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes -MaxTraceSize 2048 -Report Disabled
    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.String]$TraceProviderString,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [System.String]$Capture = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Physical', 'VMSwitch', 'Both')]
        [System.String]$CaptureType = 'Physical',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No', 'Disabled')]
        [System.String]$Report = 'Disabled',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No', 'Disabled')]
        [System.String]$Correlation = 'Disabled'
    )

    try {
        # ensure that we at least are attempting to configure NDIS tracing or ETW provider tracing, else the netsh
        # command will return a generic exception that is not useful to the operator
        if ($Capture -ieq 'No' -and !$TraceProviderString) {
            throw New-Object System.Exception("You must at least specify Capture or TraceProviderString parameter")
        }

        # ensure that the directory exists and specify the trace file name
        if (!(Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }
        $traceFile = "{0}\{1}_{2}_netshTrace.etl" -f $OutputDirectory.FullName, $env:COMPUTERNAME, (Get-FormattedDateTimeUTC)

        # build out the netsh trace command
        # if the TraceProviderString parameter is set, then we will use that to configure the trace
        # if the Capture parameter is set to Yes, then we will include the capturetype parameter
        $cmd = "netsh trace start capture=$Capture"
        if ($Capture -ieq 'Yes') {
            $cmd += " capturetype=$CaptureType"
        }
        if ($TraceProviderString) {
            $cmd += " $TraceProviderString"
        }
        $cmd += " tracefile=$traceFile maxsize=$MaxTraceSize overwrite=$Overwrite report=$Report correlation=$Correlation"

        "Starting netsh trace" | Trace-Output
        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose

        $expression = Invoke-Expression -Command $cmd
        if ($expression -ilike "*Running*") {
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status   = 'Running'
                    FileName = $traceFile
                }
            )
        }
        elseif ($expression -ilike "*A tracing session is already in progress*") {
            "A tracing session is already in progress" | Trace-Output -Level:Warning

            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Running'
                }
            )
        }
        else {
            # typically, the first line returned in scenarios where there was an error thrown will contain the error details
            $msg = $expression[0]
            throw New-Object System.Exception($msg)
        }

        return $object
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Stop-EtwTraceSession {
    <#
    .SYNOPSIS
        Stop ETW Trace Session
    .PARAMETER TraceName
        The trace name to identify the ETW trace session
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [string]$TraceName = $null
    )

    try {
        $logmanCmd = "logman stop $TraceName -ets"
        $result = Invoke-Expression -Command $logmanCmd
        if ("$result".Contains("Error")) {
            "Stop session {0} failed with error {1}" -f $TraceName, "$result" | Trace-Output -Level:Warning
        }
        else {
            "Stop session {0} with result {1}" -f $TraceName, "$result" | Trace-Output -Level:Verbose
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Stop-NetshTrace {
    <#
    .SYNOPSIS
        Disables netsh tracing.
    #>

    try {
        "Stopping trace" | Trace-Output

        $expression = Invoke-Expression -Command "netsh trace stop"
        if ($expression -ilike "*Tracing session was successfully stopped.*") {
            "Tracing was successfully stopped" | Trace-Output -Level:Verbose

            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Stopped'
                }
            )
        }
        elseif ($expression -ilike "*There is no trace session currently in progress.*") {
            "There is no trace session currently in progress" | Trace-Output -Level:Warning

            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Not Running'
                }
            )
        }
        else {
            # typically, the first line returned in scenarios where there was an error thrown will contain the error details
            $msg = $expression[0]
            throw New-Object System.Exception($msg)
        }

        return $object
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Update-SdnDiagTraceMapping {
    param (
        [Parameter(Mandatory=$true)]
        [string]$MacAddress,

        [Parameter(Mandatory=$true)]
        [string]$InfraHost,

        [Parameter(Mandatory=$false)]
        [string]$PortId,

        [Parameter(Mandatory=$false)]
        [string]$PortName,

        [Parameter(Mandatory=$false)]
        [string]$NicName,

        [Parameter(Mandatory=$false)]
        [string]$VmName,

        [Parameter(Mandatory=$false)]
        [string]$VmInternalId,

        [Parameter(Mandatory=$false)]
        [string[]]$PrivateIpAddress
    )

    $cacheName = 'TraceMapping'
    if($Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]){
        if($PortId){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['PortId'] = $PortId
        }
        if($PortName){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['PortName'] = $PortName
        }
        if($NicName){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['NicName'] = $NicName
        }
        if($VmName){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['VmName'] = $VmName
        }
        if($VmInternalId){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['VmInternalId'] = $VmInternalId
        }
        if($PrivateIpAddress){
            $Script:SdnDiagnostics_Common.Cache[$cacheName][$InfraHost][$MacAddress]['PrivateIpAddress'] = $PrivateIpAddress
        }
    }
}

function Convert-SdnEtwTraceToTxt {
    <#
    .SYNOPSIS
        Used to convert existing etw (.etl) provider traces into text readable format
    .PARAMETER FileName
        ETL trace file path and name to convert
    .PARAMETER Destination
        Output file name and directory. If omitted, will use the FileName path and base name.
    .PARAMETER Overwrite
        Overwrites existing files. If omitted, defaults to no.
    .PARAMETER Report
        Generates an HTML report. If omitted, defaults to no.
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl"
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Destination "C:\Temp\CSS_SDN_NEW\trace.txt"
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Overwrite Yes
    .EXAMPLE
        PS> Convert-SdnEtwTraceToTxt -FileName "C:\Temp\CSS_SDN\Trace.etl" -Report Yes
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript( {
            if ($_ -notmatch "(\.etl)") {
                throw "The file specified in the FileName argument must be etl extension"
            }
            return $true
        })]
        [System.String]$FileName,

        [Parameter(Mandatory = $false)]
        [System.String]$Destination,

        [Parameter(Mandatory = $false)]
        [ValidateSet('No', 'Yes')]
        [System.String]$Overwrite = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('No', 'Yes')]
        [System.String]$Report = 'No'
    )

    try {
        $fileInfo = Get-Item -Path $FileName -ErrorAction Stop

        if (-NOT $PSBoundParameters.ContainsKey('Destination')) {
            [System.String]$Destination = $fileInfo.DirectoryName
        }

        if (-NOT (Test-Path -Path $Destination -PathType Container)) {
            $null = New-Item -Path $Destination -ItemType Directory -Force
        }

        [System.String]$outputFile = "{0}.txt" -f (Join-Path -Path $Destination -ChildPath $fileInfo.BaseName)
        [System.String]$cmd = "netsh trace convert input={0} output={1} overwrite={2} report={3}" `
            -f $fileInfo.FullName, $outputFile, $Overwrite, $Report

        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose
        $expression = Invoke-Expression -Command $cmd

        # output returned is string objects, so need to manually do some mapping to correlate the properties
        # that can be then returned as psobject to the call
        if ($expression[5] -ilike "*done*") {
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Success'
                    FileName = $outputFile
                }
            )
        }
        else {
            # typically, the first line returned in scenarios where there was an error thrown will contain the error details
            $msg = $expression[0]
            throw New-Object System.Exception($msg)
        }

        return $object
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Enable-SdnVipTrace {
    <#
    .SYNOPSIS
        Enables network tracing on the SDN fabric infrastructure related to the specified VIP address.
    .PARAMETER VirtualIP
        Specify the Virtual IP address that you want to enable SDN fabric tracing for.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
        Specifies a user account that has permission to access the infrastructure nodes. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER OutputDirectory
        Optional. Specifies a specific path and folder in which to save the files.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1536.
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$VirtualIP,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.Scheme -ne "http" -and $_.Scheme -ne "https") {
                throw New-Object System.FormatException("Parameter is expected to be in http:// or https:// format.")
            }
            return $true
        })]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\NetworkTraces",

        [Parameter(Mandatory = $true, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1536
    )

    $networkTraceNodes = @()
    Reset-SdnDiagTraceMapping

    $ncRestParams = @{
        NcUri = $NcUri
        ErrorAction = 'Stop'
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        }
        'RestCredential' {
            $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        }
    }

    try {
        # lets try and locate the resources associated with the public VIP address
        # the SdnPublicIpPoolUsageSummary is useful for this scenario, as it has the logic to scan both publicIpAddresses and loadBalancers
        # to locate the VIP IP we are looking for
        $publicIpAddressUsage = Get-SdnPublicIPPoolUsageSummary @ncRestParams
        $publicIpResource = $publicIpAddressUsage | Where-Object {$_.IPAddress -ieq $VirtualIP}
        if ($null -ieq $publicIpResource) {
            throw "Unable to locate resources associated to $VirtualIP"
        }

        # get the load balancer muxes, as we will need to enable tracing on them
        $loadBalancerMuxes = Get-SdnLoadBalancerMux @ncRestParams -ManagementAddressOnly
        $networkTraceNodes += $loadBalancerMuxes

        # we want to query the servers within the SDN fabric so we can get a list of the vfp switch ports across the hyper-v hosts
        # as we will use this reference to locate where the resources are located within the fabric
        $servers = Get-SdnServer @ncRestParams -ManagementAddressOnly
        $Script:SdnDiagnostics_Common.Cache['VfpSwitchPorts'] = Get-SdnVfpVmSwitchPort -ComputerName $servers -Credential $Credential

        # determine the network interfaces associated with the public IP address
        $associatedResource = Get-SdnResource @ncRestParams -ResourceRef $publicIpResource.AssociatedResource
        switch -Wildcard ($associatedResource.resourceRef) {
            "/loadBalancers/*" {
                "{0} is associated with load balancer {1}" -f $VirtualIP, $associatedResource.resourceRef | Trace-Output

                # depending on the environments, the associatedResource may come back as the parent load balancer object
                # or may be the frontend IP configuration object so in either situation, we should just split the resourceRef string and query to get the
                # parent load balancer object to ensure consistency
                $parentResource = "{0}/{1}" -f $associatedResource.resourceRef.Split('/')[1], $associatedResource.resourceRef.Split('/')[2]
                $loadBalancer = Get-SdnResource @ncRestParams -ResourceRef $parentResource

                $ipConfigurations = $loadBalancer.properties.backendAddressPools.properties.backendIPConfigurations.resourceRef
            }
            "/networkInterfaces/*" {
                "{0} is associated with network interface {1}" -f $VirtualIP, $associatedResource.resourceRef | Trace-Output
                $ipConfigurations = $associatedResource.resourceRef
            }

            # public IP address(es) should only ever be associated to load balancer or network interface resources
            # except in the case for the gateway pool, which we would not expect in this scenario at this time
            default {
                throw "Unable to determine associated resource type"
            }
        }

        $ipConfigurations | ForEach-Object {
            $ipConfig = Get-SdnResource @ncRestParams -ResourceRef $_
            if ($null -ieq $ipConfig) {
                throw "Unable to locate resource for $($_)"
            }

            "Located associated resource {0} with DIP address {1}" -f $ipConfig.resourceRef, $ipconfig.properties.privateIPAddress | Trace-Output

            # we need the mac address of the network interface to locate the vfp switch port
            # since the ipConfiguration is a subobject of the network interface, we need to split the resourceRef to get the network interface resource
            # since we know the resourceRefs are defined as /networkInterfaces/{guid}/ipConfigurations/{guid}, we can split on the '/' and get the 3rd element
            $netInterface = Get-SdnResource @ncRestParams -ResourceRef "/networkInterfaces/$($_.Split('/')[2])"
            $macAddress = Format-MacAddress -MacAddress $netInterface.properties.privateMacAddress -Dashes
            $vfpPort = $Script:SdnDiagnostics_Common.Cache['VfpSwitchPorts'] | Where-Object {$_.MacAddress -ieq $macAddress}
            if ($null -ieq $vfpPort) {
                throw "Unable to locate vfp switch port for $macAddress"
            }

            "Located vfp switch port {0} on {1}" -f $vfpPort.PortName, $vfpPort.PSComputerName | Trace-Output

            # once we have the information we need, we can update our internal cache mapping
            Add-SdnDiagTraceMapping `
                -MacAddress $vfpPort.MacAddress `
                -InfraHost $vfpPort.PSComputerName `
                -PortId $vfpPort.PortId `
                -PortName $vfpPort.Portname `
                -NicName $vfpPort.NICname `
                -VmName $vfpPort.VMname `
                -VmInternalId $vfpPort.VMID `
                -PrivateIpAddress $ipConfig.properties.privateIPAddress
        }

        # once we have identified all the nodes we will enable tracing on
        # add the server(s) to the list of nodes we will enable tracing on
        # as this will be used to disable tracing once we are done
        $networkTraceNodes += $Script:SdnDiagnostics_Common.Cache['TraceMapping'].Keys
        $networkTraceNodes = $networkTraceNodes | Select-Object -Unique

        # ensure that we have SdnDiagnostics installed to the nodes that we need to enable tracing for
        Install-SdnDiagnostics -ComputerName $networkTraceNodes -Credential $Credential

        "Network traces will be enabled on:`r`n`t - LoadBalancerMux: {0}`r`n`t - Server: {1}`r`n" `
        -f ($loadBalancerMuxes -join ', '), ($Script:SdnDiagnostics_Common.Cache['TraceMapping'].Keys -join ', ') | Trace-Output

        # enable tracing on the infastructure
        $traceInfo = @()
        $traceInfo += Start-SdnNetshTrace -ComputerName $loadBalancerMuxes -Role 'LoadBalancerMux' -Credential $Credential -OutputDirectory $OutputDirectory -MaxTraceSize $MaxTraceSize
        $traceInfo += Start-SdnNetshTrace -ComputerName $Script:SdnDiagnostics_Common.Cache['TraceMapping'].Keys -Role 'Server' -Credential $Credential -OutputDirectory $OutputDirectory -MaxTraceSize $MaxTraceSize

        "Tracing has been enabled on the SDN infrastructure nodes {0}" -f ($traceInfo.PSComputerName -join ', ') | Trace-Output
        # at this point, tracing should be enabled on the sdn fabric and we can wait for user input to disable
        # once we receive user input, we will disable tracing on the infrastructure node(s)
        $null = Get-UserInput -Message "`r`nPress any key to disable tracing..."
        $null = Stop-SdnNetshTrace -ComputerName $networkTraceNodes -Credential $Credential

        "Tracing has been disabled on the SDN infrastructure. Saving configuration details to {0}\{1}_TraceMapping.json" -f (Get-WorkingDirectory), $VirtualIP | Trace-Output
        $Script:SdnDiagnostics_Common.Cache['TraceMapping'] | Export-ObjectToFile -FilePath (Get-WorkingDirectory) -Prefix $VirtualIP -Name 'TraceMapping' -FileType json -Depth 3

        $traceFileInfo = @()
        foreach ($obj in $traceInfo) {
            $traceFileInfo += [PSCustomObject]@{
                ComputerName = $obj.PSComputerName
                FileName = $obj.FileName
            }
        }

        return $traceFileInfo
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}


function Get-SdnCertificate {
    <#
        .SYNOPSIS
            Returns a list of the certificates within the given certificate store.
        .PARAMETER Path
            Defines the path within the certificate store. Path is expected to start with cert:\.
        .PARAMETER Subject
            Specifies the subject of the certificate to search for.
        .PARAMETER Thumbprint
            Specifies the thumbprint of the certificate to search for.
        .PARAMETER NetworkControllerOid
            Optional parameter that filters the certificates based on the Network Controller OID.
        .EXAMPLE
            PS> Get-SdnCertificate -Path "Cert:\LocalMachine\My"
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $false, ParameterSetName = 'Subject')]
        [ValidateNotNullorEmpty()]
        [System.String]$Subject,

        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [ValidateNotNullorEmpty()]
        [System.String]$Thumbprint,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Thumbprint')]
        [switch]$NetworkControllerOid
    )

    [string]$objectIdentifier = @('1.3.6.1.4.1.311.95.1.1.1') # this is a custom OID used for Network Controller
    $array = @()

    try {
        $certificateList = Get-ChildItem -Path $Path -Recurse | Where-Object {$_.PSISContainer -eq $false} -ErrorAction Stop
        if ($null -eq $certificateList) {
            throw New-Object System.NullReferenceException("No certificates found $Path")
        }

        if ($NetworkControllerOid) {
            $certificateList | ForEach-Object {
                if ($objectIdentifier -iin $_.EnhancedKeyUsageList.ObjectId) {
                    $array += $_
                }
            }

            # if no certificates are found based on the OID, search based on other criteria
            if ($null -eq $array) {
                "Unable to locate certificates that match Network Controller OID: {0}." -f $objectIdentifier | Trace-Output -Level:Warning
                $array = $certificateList
            }
        }
        else {
            $array = $certificateList
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $filteredCert = $array | Where-Object {$_.Subject -ieq $Subject}
            }
            'Thumbprint' {
                $filteredCert = $array | Where-Object {$_.Thumbprint -ieq $Thumbprint}
            }
            default {
                return $array
            }
        }

        if ($null -eq $filteredCert) {
            return $null
        }

        $filteredCert | ForEach-Object {
            if ($_.NotAfter -le (Get-Date)) {
                "Certificate [Thumbprint: {0} | Subject: {1}] is currently expired" -f $_.Thumbprint, $_.Subject | Trace-Output -Level:Warning
            }
        }

        return $filteredCert
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnDiagnosticLogFile {
    <#
    .SYNOPSIS
        Collect the default enabled logs from SdnDiagnostics folder.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 4 hours.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -LogDir "C:\Windows\Tracing\SdnDiagnostics" -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -LogDir "C:\Windows\Tracing\SdnDiagnostics" -FromDate (Get-Date).AddHours(-1)
    .EXAMPLE
        PS> Get-SdnDiagnosticLogFile -LogDir "C:\Windows\Tracing\SdnDiagnostics" -FromDate '2023-08-11 10:00:00 AM' -ToDate '2023-08-11 11:30:00 AM'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$LogDir,

        [Parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date),

        [Parameter(Mandatory = $false)]
        [bool]$ConvertETW = $true,

        [Parameter(Mandatory = $false)]
        [bool]$CleanUpFiles = $false,

        [Parameter(Mandatory = $false)]
        [string[]]$FolderNameFilter
    )

    begin {
        $fromDateUTC = $FromDate.ToUniversalTime()
        $toDateUTC = $ToDate.ToUniversalTime()
        $commonConfig = Get-SdnModuleConfiguration -Role 'Common'
    }

    process {
        $LogDir | ForEach-Object {
            $folder = Get-Item -Path $_ -ErrorAction SilentlyContinue

            # if the folder is not found, then log a message and continue to the next folder
            if ($null -ieq $folder) {
                "Unable to locate {0}" -f $_ | Trace-Output -Level:Verbose
                return
            }

            $logFiles = @()
            $getItemParams = @{
                Path         = $folder.FullName
                Include      = $commonConfig.LogFileTypes
                Recurse      = $true
                ErrorAction  = 'SilentlyContinue'
            }

            "Scanning for {0} in {1} between {2} and {3} UTC" -f ($commonConfig.LogFileTypes -join ', '), $folder.FullName, $fromDateUTC, $toDateUTC | Trace-Output -Level:Verbose
            if ($FolderNameFilter) {
                $FolderNameFilter | ForEach-Object {
                    [string]$filter = $_
                    $unfilteredlogFiles = Get-ChildItem @getItemParams | Where-Object { $_.LastWriteTime.ToUniversalTime() -ge $fromDateUTC -and $_.LastWriteTime.ToUniversalTime() -le $toDateUTC }

                    if ($unfilteredlogFiles) {
                        "Filtering logs related to DirectoryName contains '{0}'" -f $filter | Trace-Output -Level:Verbose
                        $logFiles += $unfilteredlogFiles | Where-Object { $_.DirectoryName -ilike "*$filter*" }
                    }
                }
            }
            else {
                $logFiles += Get-ChildItem @getItemParams | Where-Object { $_.LastWriteTime.ToUniversalTime() -ge $fromDateUTC -and $_.LastWriteTime.ToUniversalTime() -le $toDateUTC }
            }

            if ($logFiles) {
                # enumerate the group of log files based on the directory
                # and then create a dynamic directory based on the folder name in an effort to preserve the original directory structure
                $logDirectory = $logFiles | Group-Object -Property Directory
                $logDirectory | ForEach-Object {
                    $splitIndex = $_.Name.IndexOf($folder.Name)
                    [System.IO.DirectoryInfo]$outputPath = Join-Path -Path $OutputDirectory.FullName -ChildPath $_.Name.Substring($splitIndex)

                    # we want to call the initialize datacollection after we have identify the amount of disk space we will need to create a copy of the logs
                    # once the disk space is identified, we will initialize the data collection and copy the files to the output directory
                    $minimumDiskSpace = [float](Get-FolderSize -FileName $logFiles.FullName -Total).GB * 3.5
                    if (-NOT (Initialize-DataCollection -FilePath $outputPath.FullName -MinimumGB $minimumDiskSpace)) {
                        "Unable to copy files from {0} to {1}" -f $_.Name, $outputPath.FullName | Trace-Output -Level:Error
                        continue
                    }
                    else {
                        "Copying {0} files to {1}" -f $_.Group.Count, $outputPath.FullName | Trace-Output
                        $_.Group | Copy-Item -Destination $outputPath.FullName -Force -ErrorAction Continue
                    }

                    # convert the most recent etl trace file into human readable format without requirement of additional parsing tools
                    if ($ConvertETW) {
                        $convertFile = Get-ChildItem -Path $outputPath.FullName -Include '*.etl' -Recurse | Sort-Object -Property LastWriteTime | Select-Object -Last 1
                        if ($convertFile) {
                            $null = Convert-SdnEtwTraceToTxt -FileName $convertFile.FullName -Overwrite 'Yes'
                        }
                    }

                    try {
                        # compress the files into a single zip file
                        "Compressing results to {0}.zip" -f $outputPath.FullName | Trace-Output
                        Compress-Archive -Path "$($outputPath.FullName)\*" -Destination "$($outputPath.FullName).zip" -CompressionLevel Optimal -Force

                        # once we have copied the files to the new location we want to compress them to reduce disk space
                        # if confirmed we have a .zip file, then remove the staging folder
                        if (Test-Path -Path "$($outputPath.FullName).zip" -PathType Leaf) {
                            Clear-SdnWorkingDirectory -Path $outputPath.FullName -Force -Recurse
                        }

                        # if we opted to clean up the files, then proceed to do so now
                        if ($CleanUpFiles) {
                            "Cleaning up files" | Trace-Output -Level:Verbose
                            Clear-SdnWorkingDirectory -Path $logFiles.FullName -Force -Recurse
                        }
                    }
                    catch {
                        "Unable to compress files to {0}" -f "$($folder.FullName).zip" | Trace-Output -Level:Error
                    }
                }
            }
            else {
                "No log files found under {0} between {1} and {2} UTC." -f $folder.FullName, $fromDateUTC, $toDateUTC | Trace-Output -Level:Verbose
            }
        }
    }
}

function Get-SdnEventLog {
    <#
    .SYNOPSIS
        Collect the Windows Event Logs for different SDN Roles.
    .PARAMETER Role
        The specific SDN role to collect windows event logs from.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Determines the start time of what logs to collect. If omitted, defaults to the last 1 day.
    .PARAMETER ToDate
        Determines the end time of what logs to collect. Optional parameter that if ommitted, defaults to current time.
    .EXAMPLE
        PS> Get-SdnEventLog -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnEventLog -OutputDirectory "C:\Temp\CSS_SDN" -FromDate (Get-Date).AddHours(-12)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String[]]$Role = $Global:SdnDiagnostics.Config.Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddDays(-1),

        [Parameter(Mandatory = $false)]
        [DateTime]$ToDate = (Get-Date)
    )

    $fromDateUTC = $FromDate.ToUniversalTime()
    $toDateUTC = $ToDate.ToUniversalTime()

    try {
        foreach ($r in $Role) {
            $eventLogs = @()
            $eventLogProviders = @()

            [string]$outDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "EventLogs\$r"
            "Collect event logs between {0} and {1} UTC for {2} role" -f $fromDateUTC, $toDateUTC, $r | Trace-Output
            if (-NOT (Initialize-DataCollection -FilePath $outDir -MinimumMB 100)) {
                "Unable to initialize environment for data collection" | Trace-Output -Level:Error
                return
            }

            $roleConfig = Get-SdnModuleConfiguration -Role $r
            $eventLogProviders += $roleConfig.Properties.EventLogProviders

            # if we are running on a NetworkController, we need to get the event log providers from the NetworkController_FC or NetworkController_SF role
            # we will use the ClusterConfigType to determine which role to use
            if ($r -ieq 'NetworkController') {
                switch ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType) {
                    'FailoverCluster' {
                        $ncConfig = Get-SdnModuleConfiguration -Role 'NetworkController_FC'
                    }
                    'ServiceFabric' {
                        $ncConfig = Get-SdnModuleConfiguration -Role 'NetworkController_SF'
                    }
                }

                $eventLogProviders += $ncConfig.Properties.EventLogProviders
            }

            # check to see if the event log provider is valid
            # and that we have events to collect
            foreach ($provider in $eventLogProviders) {
                $eventLogsToAdd = Get-WinEvent -ListLog $provider -ErrorAction Ignore | Where-Object { $_.RecordCount }
                if ($eventLogsToAdd) {
                    $eventLogs += $eventLogsToAdd
                }
            }

            # process each of the event logs identified
            # and export them to csv and evtx files
            foreach ($eventLog in $eventLogs) {
                $events = Get-WinEvent -ErrorAction Ignore -FilterHashtable @{
                    LogName = $eventLog.LogName;
                    StartTime = $fromDateUTC;
                    EndTime = $toDateUTC
                }

                if ($events) {
                    $fileName = ("{0}\{1}" -f $outDir, $eventLog.LogName).Replace("/", "_")

                    "Export event log {0} to {1}" -f $eventLog.LogName, $fileName | Trace-Output -Level:Verbose
                    $events | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, ProviderID, TaskDisplayName, OpCodeDisplayName, Message `
                    | Export-Csv -Path "$fileName.csv" -NoTypeInformation -Force
                }

                wevtutil epl $eventLog.LogName "$fileName.evtx" /ow:$true
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Import-SdnCertificate {
    <#
    .SYNOPSIS
        Imports certificates (CER) and private keys from a Personal Information Exchange (PFX) file to the destination store.
    .PARAMETER FilePath
        Specifies the full path to the PFX or CER file.
    .PARAMETER CertStore
        Specifies the path of the store to which certificates will be imported. If paramater is not specified, defaults to Cert:\LocalMachine\Root.
    .PARAMETER CertPassword
        Specifies the password for the imported PFX file in the form of a secure string.
    .EXAMPLE
        PS> Import-SdnCertificate -FilePath c:\certs\cert.pfx -CertStore Cert:\LocalMachine\Root
    .EXAMPLE
        PS> Import-SdnCertificate -FilePath c:\certs\cert.pfx -CertStore Cert:\LocalMachine\Root -Password $secureString
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]$CertStore,

        [Parameter(Mandatory = $false)]
        [System.Security.SecureString]$CertPassword
    )

    $trustedRootStore = 'Cert:\LocalMachine\Root'
    $fileInfo = Get-Item -Path $FilePath

    $certObject = @{
        SelfSigned = $false
        CertInfo = $null
        CerFileInfo = $null
    }

    switch ($fileInfo.Extension) {
        '.pfx' {
            if ($CertPassword) {
                $certData = (Get-PfxData -FilePath $fileInfo.FullName -Password $CertPassword).EndEntityCertificates
            }
            else {
                $certData = Get-PfxCertificate -FilePath $fileInfo.FullName
            }
        }

        '.cer' {
            $certData = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certData.Import($fileInfo)
        }

        default {
            throw New-Object System.NotSupportedException("Unsupported certificate extension")
        }
    }

    $certExists = Get-ChildItem -Path $CertStore | Where-Object {$_.Thumbprint -ieq $certData.Thumbprint}
    if ($certExists) {
        "{0} already exists under {1}" -f $certExists.Thumbprint, $CertStore | Trace-Output -Level:Verbose
        $certObject.CertInfo = $certExists
    }
    else {
        "Importing {0} to {1}" -f $certData.Thumbprint, $CertStore | Trace-Output
        if ($certData.HasPrivateKey) {
            $importCert = Import-PfxCertificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -Password $CertPassword -Exportable -ErrorAction Stop
            Set-SdnCertificateAcl -Path $CertStore -Thumbprint $importCert.Thumbprint
        }
        else {
            $importCert = Import-Certificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -ErrorAction Stop
        }

        $certObject.CertInfo = $importCert
    }

    # determine if the certificates being used are self signed
    if (Confirm-IsCertSelfSigned -Certificate $certObject.CertInfo) {
        $certObject.SelfSigned = $true

        # check to see if we installed to root store with above operation
        # if it is not, then we want to check the root store to see if this certificate has already been installed
        # and finally if does not exist, then export the certificate from current store and import into trusted root store
        if ($CertStore -ine $trustedRootStore) {
            $selfSignedCerExists = Get-ChildItem -Path $trustedRootStore | Where-Object {$_.Thumbprint -ieq $certObject.CertInfo.Thumbprint}
            [System.String]$selfSignedCerPath = "{0}\{1}.cer" -f (Split-Path $fileInfo.FullName -Parent), ($certObject.CertInfo.Subject).Replace('=','_')
            $selfSignedCer = Export-Certificate -Cert $certObject.CertInfo -FilePath $selfSignedCerPath -ErrorAction Stop
            $certObject.CerFileInfo = $selfSignedCer

            if (-NOT ($selfSignedCerExists)) {
                # import the certificate to the trusted root store
                "Importing public key to {0}" -f $trustedRootStore | Trace-Output
                $null = Import-Certificate -FilePath $selfSignedCer.FullName -CertStoreLocation $trustedRootStore -ErrorAction Stop
            }
            else {
                "{0} already exists under {1}" -f $certObject.CertInfo.Thumbprint, $trustedRootStore | Trace-Output -Level:Verbose
            }
        }
    }

    return $certObject
}

function Invoke-SdnGetNetView {
    <#
    .SYNOPSIS
        Invokes Get-Netview function on the specified ComputerNames.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER BackgroundThreads
        Maximum number of background tasks, from 0 - 16. Defaults to 5.
    .PARAMETER SkipAdminCheck
        If present, skip the check for admin privileges before execution. Note that without admin privileges, the scope and
        usefulness of the collected data is limited.
    .PARAMETER SkipLogs
        If present, skip the EVT and WER logs gather phases.
    .PARAMETER SkipNetsh
        If present, skip all Netsh commands.
    .PARAMETER SkipNetshTrace
        If present, skip the Netsh Trace data gather phase.
    .PARAMETER SkipCounters
        If present, skip the Windows Performance Counters collection phase.
    .PARAMETER SkipWindowsRegistry
        If present, skip exporting Windows Registry keys.
    .PARAMETER SkipVm
        If present, skip the Virtual Machine (VM) data gather phases.
    .EXAMPLE
        PS> Invoke-SdnGetNetView -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 16)]
        [int]$BackgroundThreads = 5,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminCheck,

        [Parameter(Mandatory = $false)]
        [switch]$SkipLogs,

        [Parameter(Mandatory = $false)]
        [switch]$SkipNetsh,

        [Parameter(Mandatory = $false)]
        [switch]$SkipNetshTrace,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCounters,

        [Parameter(Mandatory = $false)]
        [switch]$SkipWindowsRegistry,

        [Parameter(Mandatory = $false)]
        [switch]$SkipVm
    )

    # check to see if Get-NetView module is loaded into the runspace
    Import-Module -Name 'Get-NetView' -Force -Global -ErrorAction Ignore
    $module = Get-Module -Name 'Get-NetView'
    if ($null -eq $module) {
        $msg = "Get-NetView module is not available. Please install the module and try again."
        $msg | Trace-Output -Level:Exception
        throw $msg
    }

    # throw a warning if the module is more than 1 years old
    if ($module.Version.Major -lt [datetime]::UtcNow.AddYears(-1).Year) {
        "$($module.Name) is running an outdated version: $($module.Version.ToString()). Recommend to update the module." | Trace-Output -Level:Warning
    }

    try {
        # initialize the data collection environment which will ensure the path exists and has enough space
        [string]$outDir = Join-Path -Path $OutputDirectory -ChildPath "Get-NetView"
        if (-NOT (Initialize-DataCollection -FilePath $outDir -MinimumMB 200)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        # execute Get-NetView with specified parameters and redirect all streams to null to prevent unnecessary noise on the screen
        Get-NetView @PSBoundParameters *>$null

        # remove the uncompressed files and folders to free up ~ 1.5GB of space
        $compressedArchive = Get-ChildItem -Path $outDir -Filter "*.zip"
        if ($compressedArchive) {
            Get-ChildItem -Path $outDir -Exclude *.zip | Remove-Item -Recurse -Confirm:$false
        }
        return $compressedArchive.FullName
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnSelfSignedCertificate {
    <#
    .SYNOPSIS
        Creates a new self-signed certificate for use with SDN fabric.
    .PARAMETER Subject
        Specifies the string that appears in the subject of the new certificate. This cmdlet prefixes CN= to any value that does not contain an equal sign.
    .PARAMETER CertStoreLocation
        Specifies the certificate store in which to store the new certificate. If paramater is not specified, defaults to Cert:\LocalMachine\My.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .EXAMPLE
        PS> New-SdnSelfSignedCertificate -Subject rest.sdn.contoso -CertStoreLocation Cert:\LocalMachine\My
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$Subject,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$CertStoreLocation = 'Cert:\LocalMachine\My',

        [Parameter(Mandatory = $true)]
        [System.DateTime]$NotAfter
    )

    try {
        "Generating certificate with subject {0} under {1}" -f $Subject, $CertStoreLocation | Trace-Output

        # create new self signed certificate with the following EnhancedKeyUsageList
        # 1.3.6.1.5.5.7.3.1 - Server Authentication OID
        # 1.3.6.1.5.5.7.3.2 - Client Authentication OID
        # 1.3.6.1.4.1.311.95.1.1.1 - Network Controller OID
        $selfSignedCert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject $Subject `
            -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 `
            -CertStoreLocation $CertStoreLocation -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.95.1.1.1") `
            -NotAfter $NotAfter

        if ($selfSignedCert) {
            "Successfully generated self signed certificate`n`tSubject: {0}`n`tThumbprint: {1}`n`tNotAfter: {2}" `
            -f $selfSignedCert.Subject, $selfSignedCert.Thumbprint, $selfSignedCert.NotAfter | Trace-Output

            Set-SdnCertificateAcl -Path $CertStoreLocation -Thumbprint $selfSignedCert.Thumbprint
        }

        return $selfSignedCert
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Repair-SdnDiagnosticsScheduledTask {
    <#
    .SYNOPSIS
        Repairs the SDN Diagnostics scheduled task.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('FcDiagnostics', 'SDN Diagnostics Task')]
        [string]$TaskName
    )

    try {
        $isLoggingEnabled = Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\NetworkController\Sdn\Diagnostics\Parameters" -Name 'IsLoggingEnabled'
        if (-NOT $isLoggingEnabled ) {
            "Logging is currently disabled. Logging must be enabled before the scheduled task can be repaired." | Trace-Output -Level:Warning
            return $null
        }

        $scheduledTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
        if ($scheduledTask) {
            # if the scheduled task is disabled, enable it and start it
            if ($scheduledTask.State -ieq "Disabled") {
                "Enabling scheduled task." | Trace-Output
                $scheduledTask | Enable-ScheduledTask -ErrorAction Stop

                "Starting scheduled task." | Trace-Output
                Get-ScheduledTask -TaskName $TaskName | Start-ScheduledTask -ErrorAction Stop
            }
            else {
                "Scheduled task is already enabled." | Trace-Output
            }

            return (Get-ScheduledTask -TaskName $TaskName)
        }
        else {
            "Scheduled task does not exist." | Trace-Output -Level:Warning
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Set-SdnCertificateAcl {
    <#
    .SYNOPSIS
        Configures NT AUTHORITY/NETWORK SERVICE to have appropriate permissions to the private key of the Network Controller certificates.
    .PARAMETER Path
        Specifies the certificate store in which to retrieve the certificate.
    .PARAMETER Subject
        Gets the thumbprint of a certificate with the specified store to ensure correct ACLs are defined.
    .PARAMETER Thumbprint
        Gets the thumbprint of a certificate with the specified store to ensure correct ACLs are defined.
    .EXAMPLE
        PS> Set-SdnCertificateAcl -Path CERT:\LocalMachine\My -Subject 'NCREST.Contoso.Local'
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript({
            if ($_ -notlike "cert:\*") {
                throw New-Object System.FormatException("Invalid path")
            }

            return $true
        })]
        [System.String]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Subject')]
        [System.String]$Subject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [System.String]$Thumbprint
    )

    try {
        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $certificate = Get-SdnCertificate -Path $Path -Subject $Subject
            }
            'Thumbprint' {
                $certificate = Get-SdnCertificate -Path $Path -Thumbprint $Thumbprint
            }
        }

        if ($null -eq $certificate) {
            throw New-Object System.NullReferenceException("Unable to locate the certificate based on $($PSCmdlet.ParameterSetName)")
        }
        else {
            "Located certificate with Thumbprint: {0} and Subject: {1}" -f $certificate.Thumbprint, $certificate.Subject | Trace-Output -Level:Verbose
        }

        if ($certificate.Count -ge 2) {
            throw New-Object System.Exception("Multiple certificates found matching $($PSCmdlet.ParameterSetName)")
        }

        if ($certificate.HasPrivateKey) {
            $privateKeyCertFile = Get-Item -Path "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\*" | Where-Object {$_.Name -ieq $($certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName)}
            $privateKeyAcl = Get-Acl -Path $privateKeyCertFile.FullName
            if ($privateKeyAcl.Access.IdentityReference -inotcontains "NT AUTHORITY\NETWORK SERVICE") {
                $networkServicePermission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow"
                "Configuring {0} on {1}" -f ($networkServicePermission -join ', ').ToString(), $privateKeyCertFile.FullName | Trace-Output

                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($networkServicePermission)
                [void]$privateKeyAcl.AddAccessRule($accessRule)
                $null = Set-Acl -Path $privateKeyCertFile.FullName -AclObject $privateKeyAcl
            }
            else {
                "Permissions already defined for NT AUTHORITY\NETWORK SERVICE for {0}. No ACL changes required." -f $certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName | Trace-Output -Level:Verbose
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Start-SdnEtwTraceCapture {
    <#
    .SYNOPSIS
        Start ETW Trace capture based on Role
    .PARAMETER Role
        The SDN Roles
    .PARAMETER Providers
        Allowed values are Default,Optional And All to control what are the providers needed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [System.String]$OutputDirectory = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"
    )

    # this is the default trace size that we will limit each etw trace session to
    $maxTraceSize = 1024

    try {
        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers

        # we want to calculate the max size on number of factors to ensure sufficient disk space is available
        $diskSpaceRequired = $maxTraceSize*($traceProvidersArray.Count)*1.5
        if (-NOT (Initialize-DataCollection -Role $Role -FilePath $OutputDirectory -MinimumMB $diskSpaceRequired)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        foreach ($traceProviders in $traceProvidersArray) {
            "Starting trace session {0}" -f $traceProviders.name | Trace-Output -Level:Verbose
            Start-EtwTraceSession -TraceName $traceProviders.name -TraceProviders $traceProviders.properties.providers -TraceFile "$OutputDirectory\$($traceProviders.name).etl" -MaxTraceSize $maxTraceSize
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Start-SdnNetshTrace {
    <#
    .SYNOPSIS
        Enables netsh tracing based on pre-configured trace providers.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Role
        The specific SDN role of the local or remote computer(s) that tracing is being enabled for.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1024.
    .PARAMETER Capture
        Optional. Specifies whether packet capture is enabled in addition to trace events. If unspecified, the default is No.
    .PARAMETER CaptureType
        Optional. Specifies if want to capture physical network or vmswitch. If unspecified, the default is Both.
    .PARAMETER Overwrite
        Optional. Specifies whether this instance of the trace conversion command overwrites files that were rendered from previous trace conversions. If unspecified, the default is Yes.
    .PARAMETER Correlation
        Optional. Specifies whether related events will be correlated and grouped together. If unspecified, the default is Disabled.
    .PARAMETER Report
        Optional. Specifies whether a complementing report will be generated in addition to the trace file report. If unspecified, the default is disabled.
    .EXAMPLE
        PS> Start-SdnNetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes -Role Server
    .EXAMPLE
        PS> Start-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController 'PREFIX-NC03').Server -Role Server -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String]$Role,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\NetworkTraces",

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [int]$MaxTraceSize = 1536,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No')]
        [System.String]$Capture = 'Yes',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Physical', 'VMSwitch', 'Both')]
        [System.String]$CaptureType = 'Physical',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No', 'Disabled')]
        [System.String]$Correlation = 'Disabled',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No', 'Disabled')]
        [System.String]$Report = 'Disabled',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "All",

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $scriptBlock = {
        param(
            [Parameter(Position = 0)][String]$Role,
            [Parameter(Position = 1)][String]$OutputDirectory,
            [Parameter(Position = 2)][int]$MaxTraceSize,
            [Parameter(Position = 3)][String]$Capture,
            [Parameter(Position = 4)][String]$CaptureType,
            [Parameter(Position = 5)][String]$Overwrite,
            [Parameter(Position = 6)][String]$Report,
            [Parameter(Position = 7)][String]$Correlation,
            [Parameter(Position = 8)][String]$Providers
        )

        Start-SdnNetshTrace -Role $Role -OutputDirectory $OutputDirectory `
        -MaxTraceSize $MaxTraceSize -Capture $Capture -CaptureType $CaptureType -Overwrite $Overwrite -Report $Report -Correlation $Correlation -Providers $Providers
    }

    $traceParams = @{
        OutputDirectory = $OutputDirectory
        MaxTraceSize = $MaxTraceSize
        Capture = $Capture
        CaptureType = $CaptureType
        Overwrite = $Overwrite
        Report = $Report
        Correlation = $Correlation
    }

    # if the user did not specify the capture type, in normal instances we default to physical
    # however for the server role, we want to define both for physical and vmswitch to capture the appropriate VLAN information
    if (-NOT $PSBoundParameters.ContainsKey('CaptureType')) {
        if ($Role -ieq 'Server') {
            $traceParams.CaptureType = 'Both'
        }
    }

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock $scriptBlock `
            -ArgumentList @($Role, $traceParams.OutputDirectory, $traceParams.MaxTraceSize, $traceParams.Capture, $traceParams.CaptureType, $traceParams.Overwrite, $traceParams.Report, $traceParams.Correlation, $Providers)
        }
        else {
            $traceProviderString = Get-TraceProviders -Role $Role -Providers $Providers -AsString
            if ($traceProviderString) {
                $traceParams.Add('TraceProviderString', $traceProviderString)
                "Trace providers configured: {0}" -f $traceProviderString | Trace-Output -Level:Verbose
            }
            elseif ($null -eq $traceProviderString) {
                "No default trace providers found for role {0}." -f $Role | Trace-Output
                if ($traceParams.Capture -eq 'No') {
                    $traceParams.Capture = 'Yes'
                    "Setting capture to {1}" -f $Role, $traceParams.Capture | Trace-Output
                }
            }

            if (-NOT ( Initialize-DataCollection -Role $Role -FilePath $OutputDirectory -MinimumMB ($MaxTraceSize*1.5) )) {
                "Unable to initialize environment for data collection" | Trace-Output -Level:Error
                return
            }

            Start-NetshTrace @traceParams
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Stop-SdnEtwTraceCapture {
    <#
    .SYNOPSIS
        Start ETW Trace capture based on Role
    .PARAMETER Role
        The SDN Roles
    .PARAMETER Providers
        Allowed values are Default,Optional And All to control what are the providers needed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Common', 'Gateway', 'NetworkController', 'Server', 'LoadBalancerMux')]
        [String]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"

    )

    try {
        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers

        foreach ($traceProviders in $traceProvidersArray) {
            Stop-EtwTraceSession -TraceName $traceProviders.name
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Stop-SdnNetshTrace {

    <#
    .SYNOPSIS
        Disables netsh tracing.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Stop-SdnNetshTrace }
        }
        else {
            Stop-NetshTrace
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Confirm-IsCertSelfSigned {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $Certificate
    )

    if ($Certificate.Issuer -eq $Certificate.Subject) {
        "Detected the certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output -Level:Verbose
        return $true
    }

    return $false
}
