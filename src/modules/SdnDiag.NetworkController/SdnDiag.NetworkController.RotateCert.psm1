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
        if ($null -ne $FabricDetails.LoadBalancerMux) {
            $southBoundNodes += $FabricDetails.LoadBalancerMux
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

function Copy-ServiceFabricManifestFromNetworkController {
    <#
    .SYNOPSIS
        Copy the Service Fabric Manifest Files from Network Controller.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER ManifestFolder
        The Manifest Folder path for Manifest files copy to.
    .PARAMETER ManifestFolderNew
        The New Manifest Folder path for updated Manifest files.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolderNew,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcNodeList.Count -eq 0) {
            Trace-Output "No NC Node found" -Level:Error
            return
        }
        Trace-Output "Copying Manifest files from $($NcNodeList.IpAddressOrFQDN)" -Level:Verbose

        New-Item -Path $ManifestFolder -ItemType Directory -Force | Out-Null
        New-Item -Path $ManifestFolderNew -ItemType Directory -Force | Out-Null

        $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$($NcNodeList[0].NodeName)\Fabric"
        Copy-FileFromRemoteComputer -Path "$fabricFolder\ClusterManifest.current.xml" -ComputerName $($NcNodeList[0].IpAddressOrFQDN) -Destination $ManifestFolder -Credential $Credential
        Copy-FileFromRemoteComputer -Path "$fabricFolder\Fabric.Data\InfrastructureManifest.xml" -ComputerName $($NcNodeList[0].IpAddressOrFQDN) -Destination $ManifestFolder -Credential $Credential

        $NcNodeList | ForEach-Object {
            $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$($_.NodeName)\Fabric"

            $version = Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -ScriptBlock {
                $fabricPkgFile = "$using:fabricFolder\Fabric.Package.current.xml"
                $xml = [xml](get-content $fabricPkgFile)
                $version = $xml.ServicePackage.DigestedConfigPackage.ConfigPackage.Version
                return $version
            } -Credential $Credential

            $fabricConfigDir = Join-Path -Path $fabricFolder -ChildPath $("Fabric.Config." + $version)
            $settingsFile = Join-Path -Path $fabricConfigDir -ChildPath "Settings.xml"
            New-Item -Path "$ManifestFolder\$($_.IpAddressOrFQDN)" -type Directory -Force | Out-Null
            New-Item -Path "$ManifestFolderNew\$($_.IpAddressOrFQDN)" -type Directory -Force | Out-Null

            Copy-FileFromRemoteComputer -Path $settingsFile -ComputerName $_.IpAddressOrFQDN -Destination "$ManifestFolder\$($_.IpAddressOrFQDN)" -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Copy-ServiceFabricManifestToNetworkController {
    <#
    .SYNOPSIS
        Copy the Service Fabric Manifest Files to Network Controller.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER ManifestFolder
        The Manifest Folder path for Manifest files copy from.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [String]
        $ManifestFolder,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($NcNodeList.Count -eq 0) {
            Trace-Output "No NC VMs found" -Level:Error
            return
        }
        Trace-Output "Copying Service Fabric Manifests to NC VMs: $($NcNodeList.IpAddressOrFQDN)"

        Trace-Output "Stopping Service Fabric Service"
        foreach ($nc in $NcNodeList.IpAddressOrFQDN) {
            Invoke-PSRemoteCommand -ComputerName $nc -ScriptBlock {
                Write-Host "[$(HostName)] Stopping Service Fabric Service"
                Stop-Service FabricHostSvc -Force
            } -Credential $Credential
        }


        $NcNodeList | ForEach-Object {
            $fabricFolder = "c:\programdata\Microsoft\Service Fabric\$($_.NodeName)\Fabric"

            $version = Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -ScriptBlock {
                $fabricPkgFile = "$using:fabricFolder\Fabric.Package.current.xml"
                $xml = [xml](get-content $fabricPkgFile)
                $version = $xml.ServicePackage.DigestedConfigPackage.ConfigPackage.Version
                return $version
            } -Credential $Credential

            $fabricConfigDir = Join-Path -Path $fabricFolder -ChildPath $("Fabric.Config." + $version)
            $settingsFile = Join-Path -Path $fabricConfigDir -ChildPath "Settings.xml"

            Invoke-PSRemoteCommand -ComputerName $_.IpAddressOrFQDN -ScriptBlock {
                Set-ItemProperty -Path "$using:fabricFolder\ClusterManifest.current.xml" -Name IsReadOnly -Value $false | Out-Null
                Set-ItemProperty -Path "$using:fabricFolder\Fabric.Data\InfrastructureManifest.xml" -Name IsReadOnly -Value $false | Out-Null
                Set-ItemProperty -Path $using:settingsFile -Name IsReadOnly -Value $false | Out-Null

            } -Credential $Credential

            Copy-FileToRemoteComputer -Path "$ManifestFolder\ClusterManifest.current.xml" -Destination "$fabricFolder\ClusterManifest.current.xml" -ComputerName $_.IpAddressOrFQDN -Credential $Credential
            Copy-FileToRemoteComputer -Path "$ManifestFolder\InfrastructureManifest.xml" -Destination "$fabricFolder\Fabric.Data\InfrastructureManifest.xml" -ComputerName $_.IpAddressOrFQDN -Credential $Credential
            Copy-FileToRemoteComputer -Path "$ManifestFolder\$($_.IpAddressOrFQDN)\settings.xml" -Destination $settingsFile -ComputerName $_.IpAddressOrFQDN -Credential $Credential
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
            FileInfo   = $pfxFile
            PfxData    = $pfxData
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

        if ($cert.pfxdata.EndEntityCertificates.Subject -ieq $cert.pfxdata.EndEntityCertificates.Issuer) {
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
                "Unable to locate self-signed certificate file for {0}. Node certificate may need to be manually installed to other Network Controllers manually." -f $controller | Trace-Output -Level:Exception
            }
        }
    }

    return $certificateCache
}

function Invoke-CertRotateCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Set-NetworkController', 'Set-NetworkControllerCluster', 'Set-NetworkControllerNode')]
        [System.String]$Command,

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

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    $retryAttempt = 0

    $params = @{
        'PassThru' = $true
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
            Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $using:Thumbprint
        }
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
            $ncNode = Get-SdnNetworkControllerNode -Name $NetworkController -Credential $Credential

            $params.Add('Name', $ncNode.Name)
            $params.Add('NodeCertificate', $cert)
        }
    }

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
                # Sleep 60s or longer before next retry if update in progress
                Start-Sleep -Seconds 60 * $retryAttempt
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

function Start-SdnExpiredCertificateRotation {
    <#
    .SYNOPSIS
        Start the Network Controller Certificate Update.
    .DESCRIPTION
        Start the Network Controller Certificate Update.
        This will use the latest issued certificate on each of the NC VMs to replace existing certificates. Ensure below before execute this command:
        - NC Rest Certificate and NC Node certificate created on each NC and trusted.
        - "Network Service" account have read access to the private file of the new certificates.
        - NC Rest Certificate need to be trusted by all SLB MUX VMs and SDN Hosts.

        For Self-Signed Certificate. This can also be created by 'New-NetworkControllerCertificate'. To get more details, run 'Get-Help New-NetworkControllerCertificate'

        About SDN Certificate Requirement:
        https://docs.microsoft.com/en-us/windows-server/networking/sdn/security/sdn-manage-certs

    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .EXAMPLE
        Start-SdnExpiredCertificateRotation -NetworkController nc01
    #>

    param (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $NcUpdateFolder = "$(Get-WorkingDirectory)\NcCertUpdate_{0}" -f (Get-FormattedDateTimeUTC)
    $ManifestFolder = "$NcUpdateFolder\manifest"
    $ManifestFolderNew = "$NcUpdateFolder\manifest_new"

    $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential
    Trace-Output "Network Controller Infrastrucutre Info detected:"
    Trace-Output "ClusterCredentialType: $($NcInfraInfo.ClusterCredentialType)"
    Trace-Output "NcRestName: $($NcInfraInfo.NcRestName)"

    $NcNodeList = $NcInfraInfo.NodeList

    if ($null -eq $NcNodeList -or $NcNodeList.Count -eq 0) {
        Trace-Output "Failed to get NC Node List from NetworkController: $(HostName)" -Level:Error
    }

    Trace-Output "NcNodeList: $($NcNodeList.IpAddressOrFQDN)"

    Trace-Output "Validate CertRotateConfig"
    if (!(Test-SdnCertificateRotationConfig -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential)) {
        Trace-Output "Invalid CertRotateConfig, please correct the configuration and try again" -Level:Error
        return
    }

    if ([String]::IsNullOrEmpty($NcInfraInfo.NcRestName)) {
        Trace-Output "Failed to get NcRestName using current secret certificate thumbprint. This might indicate the certificate not found on $(HOSTNAME). We won't be able to recover." -Level:Error
        throw New-Object System.NotSupportedException("Current NC Rest Cert not found, Certificate Rotation cannot be continue.")
    }

    $NcVms = $NcNodeList.IpAddressOrFQDN

    if (Test-Path $NcUpdateFolder) {
        $items = Get-ChildItem $NcUpdateFolder
        if ($items.Count -gt 0) {
            $confirmCleanup = Read-Host "The Folder $NcUpdateFolder not empty. Need to be cleared. Enter Y to confirm"
            if ($confirmCleanup -eq "Y") {
                $items | Remove-Item -Force -Recurse
            }
            else {
                return
            }
        }
    }

    foreach ($nc in $NcVms) {
        Invoke-Command -ComputerName $nc -ScriptBlock {
            Write-Host "[$(HostName)] Stopping Service Fabric Service"
            Stop-Service FabricHostSvc -Force
        }
    }

    Trace-Output "Step 1 Copy manifests and settings.xml from Network Controller"
    Copy-ServiceFabricManifestFromNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -Credential $Credential

    # Step 2 Update certificate thumbprint
    Trace-Output "Step 2 Update certificate thumbprint and secret in manifest"
    Update-NetworkControllerCertificateInManifest -NcNodeList $NcNodeList -ManifestFolder $ManifestFolder -ManifestFolderNew $ManifestFolderNew -CertRotateConfig $CertRotateConfig -Credential $Credential

    # Step 3 Copy the new files back to the NC vms
    Trace-Output "Step 3 Copy the new files back to the NC vms"
    Copy-ServiceFabricManifestToNetworkController -NcNodeList $NcNodeList -ManifestFolder $ManifestFolderNew -Credential $Credential

    # Step 5 Start FabricHostSvc and wait for SF system service to become healty
    Trace-Output "Step 4 Start FabricHostSvc and wait for SF system service to become healty"
    Trace-Output "Step 4.1 Update Network Controller Certificate ACL to allow 'Network Service' Access"
    Update-NetworkControllerCertificateAcl -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output "Step 4.2 Start Service Fabric Host Service and wait"
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output "ClusterHealthy: $clusterHealthy"
    if ($clusterHealthy -ne $true) {
        throw New-Object System.NotSupportedException("Cluster unheathy after manifest update, we cannot continue with current situation")
    }
    # Step 6 Invoke SF Cluster Upgrade
    Trace-Output "Step 5 Invoke SF Cluster Upgrade"
    Update-ServiceFabricCluster -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -ManifestFolderNew $ManifestFolderNew -Credential $Credential
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    Trace-Output "ClusterHealthy: $clusterHealthy"
    if ($clusterHealthy -ne $true) {
        throw New-Object System.NotSupportedException("Cluster unheathy after cluster update, we cannot continue with current situation")
    }

    # Step 7 Fix NC App
    Trace-Output "Step 6 Fix NC App"
    Trace-Output "Step 6.1 Updating Network Controller Global and Cluster Config"
    if ($NcInfraInfo.ClusterCredentialType -eq "X509") {
        Update-NetworkControllerConfig -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential
    }

    # Step 7 Restart
    Trace-Output "Step 7 Restarting Service Fabric Cluster after configuration change"
    $clusterHealthy = Wait-ServiceFabricClusterHealthy -NcNodeList $NcNodeList -CertRotateConfig $CertRotateConfig -Credential $Credential -Restart

    <#     Trace-Output "Step 7.2 Rotate Network Controller Certificate"
    #$null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint $NcRestCertThumbprint

    # Step 8 Update REST CERT credential
    Trace-Output "Step 8 Update REST CERT credential"
    # Step 8.1 Wait for NC App Healthy
    Trace-Output "Step 8.1 Wiating for Network Controller App Ready"
    #Wait-NetworkControllerAppHealthy -Interval 60
    Trace-Output "Step 8.2 Updating REST CERT Credential object calling REST API" #>
    #Update-NetworkControllerCredentialResource -NcUri "https://$($NcInfraInfo.NcRestName)" -NewRestCertThumbprint $NcRestCertThumbprint -Credential $NcRestCredential
}

function Update-NetworkControllerConfig {
    <#
    .SYNOPSIS
        Update the Network Controller Application Global Config with new certificate info. This to be run on Network Controller only.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $globalConfigUri = "GlobalConfiguration"
    $clusterConfigUri = "ClusterConfiguration"
    $globalConfigs = Get-SdnServiceFabricClusterConfig -Uri $globalConfigUri
    $clusterConfigs = Get-SdnServiceFabricClusterConfig -Uri $clusterConfigUri

    foreach ($ncNode in $NcNodeList) {
        $nodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
        if ($null -eq $nodeCertThumbprint) {
            throw New-Object System.NotSupportedException("NodeCertificateThumbprint not found for $($ncNode.NodeName)")
        }
        $thumbprintPropertyName = "{0}.ClusterCertThumbprint" -f $ncNode.NodeName
        # Global Config property name like Global.Version.NodeName.ClusterCertThumbprint
        $thumbprintProperty = $globalConfigs | Where-Object Name -Match $thumbprintPropertyName

        if ($null -ne $thumbprintProperty) {
            "GlobalConfiguration: Property $($thumbprintProperty.Name) will be updated from $($thumbprintProperty.Value) to $nodeCertThumbprint" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $globalConfigUri -Name $thumbprintProperty.Name -Value $nodeCertThumbprint
        }

        # Cluster Config property name like NodeName.ClusterCertThumbprint
        $thumbprintProperty = $clusterConfigs | Where-Object Name -ieq $thumbprintPropertyName

        # If NodeName.ClusterCertThumbprint exist (for Server 2022 +), Update
        if ($null -ne $thumbprintProperty) {
            "ClusterConfiguration: Property $($thumbprintProperty.Name) will be updated from $($thumbprintProperty.Value) to $nodeCertThumbprint" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $clusterConfigUri -Name $thumbprintProperty.Name -Value $nodeCertThumbprint
        }

        $certProperty = $clusterConfigs | Where-Object Name -ieq $ncNode.NodeName
        if ($null -ne $certProperty) {
            $nodeCert = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                return Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $using:nodeCertThumbprint
            }
            "ClusterConfiguration: Property $($certProperty.Name) will be updated From :`n$($certProperty.Value) `nTo : `n$nodeCert" | Trace-Output
            Set-SdnServiceFabricClusterConfig -Uri $clusterConfigUri -Name $certProperty.Name -Value $nodeCert.GetRawCertData()
        }
    }
}

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

    $headers = @{"Accept" = "application/json" }
    $content = "application/json; charset=UTF-8"
    $timeoutInMinutes = 10
    $array = @()

    $servers = Get-SdnServer -NcUri $NcUri -Credential $Credential
    foreach ($object in $servers) {
        "Processing X509 connections for {0}" -f $object | Trace-Output
        foreach ($connection in $servers.properties.connections | Where-Object { $_.credentialType -ieq 'X509Certificate' }) {
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
                if ($result.properties.provisioningState -ieq 'Updating') {
                    "Status: {0}" -f $result.properties.provisioningState | Trace-Output
                    Start-Sleep -Seconds 15
                }
                elseif ($result.properties.provisioningState -ieq 'Failed') {
                    $stopWatch.Stop()
                    throw New-Object System.Exception("Failed to update $($cred.resourceRef)")
                }
                elseif ($result.properties.provisioningState -ieq 'Succeeded') {
                    "Successfully updated {0}" -f $cred.resourceRef | Trace-Output
                    break
                }
                else {
                    $stopWatch.Stop()
                    throw New-Object System.Exception("Failed to update $($cred.resourceRef) with $($result.properties.provisioningState)")
                }
            }

            $array += $result
        }
    }

    return $array
}
function New-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Prepare the Network Controller Ceritifcate Rotation Configuration to determine which certificates to be used.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig
    .EXAMPLE
        PS> New-SdnCertificateRotationConfig -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$NetworkController = $(HostName),

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if (-NOT ($PSBoundParameters.ContainsKey('NetworkController'))) {
            $config = Get-SdnRoleConfiguration -Role 'NetworkController'
            $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
            if (-NOT ($confirmFeatures)) {
                "The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter to specify one" | Trace-Output -Level:Warning
                return # don't throw exception, since this is a controlled scenario and we do not need stack exception tracing
            }
        }

        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -NetworkController $NetworkController -Credential $Credential

        $CertificateRotationConfig = @{}
        $CertificateRotationConfig["ClusterCredentialType"] = $NcInfraInfo.ClusterCredentialType
        $getNewestCertScript = {
            param(
                [String]
                $certSubject
            )

            # Default to return Node Certificate
            if ([string]::IsNullOrEmpty($certSubject)) {
                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
                $certSubject = "CN=$NodeFQDN"
            }

            Write-Verbose "Looking for cert match $certSubject"
            $cert = Get-ChildItem -Path Cert:\LocalMachine\My | ? { $_.Subject -ieq $certSubject } | Sort-Object -Property NotBefore -Descending | Select-Object -First 1
            return $cert.Thumbprint
        }
        $CertificateRotationConfig["NcRestCert"] = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock $getNewestCertScript -ArgumentList "CN=$($NcInfraInfo.NcRestName)" -Credential $Credential

        if ($NcInfraInfo.ClusterCredentialType -eq "X509") {
            foreach ($ncNode in $($NcInfraInfo.NodeList)) {
                Trace-Output "Looking for Node Cert for Node: $($ncNode.NodeName), IpAddressOrFQDN: $($ncNode.IpAddressOrFQDN)" -Level:Verbose
                $ncNodeCert = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock $getNewestCertScript -Credential $Credential
                $CertificateRotationConfig[$ncNode.NodeName.ToLower()] = $ncNodeCert
            }
        }

        return $CertificateRotationConfig
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function New-SdnNetworkControllerNodeCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller node.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER CertPassword
        Specifies the password for the exported PFX file in the form of a secure string.
    .PARAMETER Credential
    .EXAMPLE
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(1),

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    try {
        if ($null -eq $FabricDetails) {
            $FabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = (Get-SdnNetworkControllerNode).Server
            }
        }

        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        $nodeCertSubject = (Get-SdnNetworkControllerNodeCertificate).Subject
        $certificate = New-SdnCertificate -Subject $nodeCertSubject -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$pfxFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $nodeCertSubject.ToString().ToLower().Replace('.','_').Replace("=",'_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $pfxFilePath | Trace-Output
        $exportedCertificate = Export-PfxCertificate -Cert $certificate -FilePath $pfxFilePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
        $null = Import-SdnCertificate -FilePath $exportedCertificate.FullName -CertStore 'Cert:\LocalMachine\Root' -CertPassword $CertPassword

        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
            -NetworkControllerNodeCert -Credential $Credential

        return ([PSCustomObject]@{
                Certificate = $certificate
                FileInfo    = $exportedCertificate
            })
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function New-SdnNetworkControllerRestCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER CertPassword
        Specifies the password for the imported PFX file in the form of a secure string.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$RestName,

        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(1),

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    try {
        if ($FabricDetails) {
            if ($FabricDetails.LoadBalancerMux -or $FabricDetails.Server) {
                $installToSouthboundDevices = $true
            }
            else {
                $installToSouthboundDevices = $false
            }
        }
        else {
            $installToSouthboundDevices = $false

            $FabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = (Get-SdnNetworkControllerNode).Server
            }
        }

        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        [System.String]$formattedSubject = "CN={0}" -f $RestName.Trim()
        $certificate = New-SdnCertificate -Subject $formattedSubject -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate using the $CertPassword provided by the operator
        # and save the file to directory. This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$pfxFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $RestName.ToLower().Replace('.','_').Replace('=','_').Trim()).pfx"
        "Exporting pfx certificate to {0}" -f $pfxFilePath | Trace-Output
        $exportedCertificate = Export-PfxCertificate -Cert $certificate -FilePath $pfxFilePath -Password $CertPassword -CryptoAlgorithmOption AES256_SHA256
        $null = Import-SdnCertificate -FilePath $exportedCertificate.FullName -CertStore 'Cert:\LocalMachine\Root' -CertPassword $CertPassword

        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -CertPassword $CertPassword -FabricDetails $FabricDetails `
            -NetworkControllerRestCertificate -InstallToSouthboundDevices:$installToSouthboundDevices -Credential $Credential

        return ([PSCustomObject]@{
                Certificate = $certificate
                FileInfo    = $exportedCertificate
            })
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Start-SdnCertificateRotation {
    <#
    .SYNOPSIS
        Performs a controller certificate rotate operation for Network Controller Northbound API, Southbound communications and Network Controller nodes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER CertPath
        Path directory where certificate(s) .pfx files are located for use with certificate rotation.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [System.String]$CertPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Switch]$GenerateCertificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [System.Security.SecureString]$CertPassword,

        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [hashtable]$CertRotateConfig,

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [switch]$Force
    )

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    $config = Get-SdnRoleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController.")
    }

    # add disclaimer that this feature is currently under preview
    if (!$Force) {
        "This feature is currently under preview. Please report any issues to https://github.com/microsoft/SdnDiagnostics/issues so we can accurately track any issues and help unblock your cert rotation." | Trace-Output -Level:Warning
        $confirm = Confirm-UserInput -Message "Do you want to proceed with certificate rotation? [Y/N]:"
        if (-NOT $confirm) {
            "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
            return
        }
    }

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        if ([String]::IsNullOrEmpty($CertPath)) {
            [System.String]$CertPath = "$(Get-WorkingDirectory)\Cert_{0}" -f (Get-FormattedDateTimeUTC)

            if (-NOT (Test-Path -Path $CertPath -PathType Container)) {
                $null = New-Item -Path $CertPath -ItemType Directory -Force
            }
        }

        [System.IO.FileSystemInfo]$CertPath = Get-Item -Path $CertPath -ErrorAction Stop

        # Get the Network Controller Info Offline (NC Cluster Down case)
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -Credential $Credential

        if ($NcInfraInfo.ClusterCredentialType -ieq 'X509') {
            $rotateNCNodeCerts = $true
        }

        # Get the current rest certificate to determine if it is expired scenario or not.
        $currentRestCert = Get-SdnNetworkControllerRestCertificate

        $restCertExpired = (Get-Date) -gt $($currentRestCert.NotAfter)
        $ncHealthy = $true

        if (!$restCertExpired) {
            try {
                $null = Get-NetworkController
            }
            catch {
                $ncHealthy = $false
            }
        }

        if ($restCertExpired -or !$ncHealthy) {
            $postRotateSBRestCert = $true
            if ($restCertExpired) {
                "Network Controller Rest Certificate {0} expired at {1}" -f $currentRestCert.Thumbprint, $currentRestCert.NotAfter | Trace-Output -Level:Warning
            }

            "Network Controller is currently not healthy" | Trace-Output -Level:Warning
            $sdnFabricDetails = [SdnFabricInfrastructure]@{
                NetworkController = $NcInfraInfo.NodeList.IpAddressOrFQDN
            }

            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ErrorAction Stop
        }
        else {
            # determine fabric information and current version settings for network controller
            $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $env:COMPUTERNAME -Credential $Credential -NcRestCredential $NcRestCredential
            $ncClusterSettings = Get-NetworkControllerCluster
            $ncSettings = @{
                NetworkControllerVersion        = (Get-NetworkController).Version
                NetworkControllerClusterVersion = $ncClusterSettings.Version
                ClusterAuthentication           = $ncClusterSettings.ClusterAuthentication
            }

            # before we proceed with anything else, we want to make sure that all the Network Controllers within the SDN fabric are running the current version
            Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop

            "Network Controller version: {0}" -f $ncSettings.NetworkControllerVersion | Trace-Output
            "Network Controller cluster version: {0}" -f $ncSettings.NetworkControllerClusterVersion | Trace-Output

            $healthState = Get-SdnServiceFabricClusterHealth -NetworkController $env:COMPUTERNAME
            if ($healthState.AggregatedHealthState -ine 'Ok') {
                "Service Fabric AggregatedHealthState is currently reporting {0}. Please address underlying health before proceeding with certificate rotation" `
                    -f $healthState.AggregatedHealthState | Trace-Output -Level:Exception

                if (!$Force) {
                    $confirm = Confirm-UserInput -Message "Do you want to proceed with certificate rotation? Enter N to abort and address the underlying health. Enter Y to force continue:"
                    if (-NOT $confirm) {
                        "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                        return
                    }
                }
            }
        }

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            $newSelfSignedCert = New-SdnNetworkControllerRestCertificate -RestName $NcInfraInfo.NcRestName.ToString() -NotAfter $NotAfter -Path $CertPath.FullName `
                -CertPassword $CertPassword -Credential $Credential -FabricDetails $sdnFabricDetails
            $selfSignedRestCertFile = $newSelfSignedCert.FileInfo

            if ($rotateNCNodeCerts) {
                $null = Invoke-PSRemoteCommand -ComputerName $sdnFabricDetails.NetworkController -Credential $Credential -ScriptBlock {
                    New-SdnNetworkControllerNodeCertificate -NotAfter $using:NotAfter -CertPassword $using:CertPassword `
                        -Credential $using:Credential -Path $using:CertPath.FullName -FabricDetails $sdnFabricDetails
                }
            }

            $CertRotateConfig = New-SdnCertificateRotationConfig -Credential $Credential
        }

        #####################################
        #
        # PFX Certificates (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'Pfx') {
            "== STAGE: Install PFX Certificates to Fabric ==" | Trace-Output
            $pfxCertificates = Copy-UserProvidedCertificateToFabric -CertPath $CertPath -CertPassword $CertPassword -FabricDetails $sdnFabricDetails `
                -NetworkControllerHealthy:$ncHealthy -Credential $Credential -RotateNodeCerts:$rotateNCNodeCerts

            $pfxCertificates | ForEach-Object {
                if ($_.CertificateType -ieq 'NetworkControllerRest' ) {
                    if ($_.SelfSigned -ieq $true) {
                        $selfSignedRestCertFile = $_.FileInfo
                    }
                }
            }

            $CertRotateConfig = New-SdnCertificateRotationConfig -Credential $Credential
        }

        #####################################
        #
        # Certificate Configuration
        #
        #####################################

        "== STAGE: DETERMINE CERTIFICATE CONFIG ==" | Trace-Output

        "Validating Certificate Configuration" | Trace-Output
        $certValidated = Test-SdnCertificateRotationConfig -NcNodeList $NcInfraInfo.NodeList -CertRotateConfig $CertRotateConfig -Credential $Credential

        if ($certValidated -ne $true) {
            throw New-Object System.NotSupportedException("Unable to validate certificate configuration")
        }

        $updatedRestCertificate = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -ieq $currentRestCert.Subject } `
        | Sort-Object -Property NotBefore -Descending | Select-Object -First 1

        "Network Controller Rest Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
            -f $currentRestCert.Subject, $currentRestCert.Thumbprint, $currentRestCert.NotAfter, $CertRotateConfig["NcRestCert"], $updatedRestCertificate.NotAfter `
        | Trace-Output -Level:Warning

        if ($rotateNCNodeCerts) {
            foreach ($node in $NcInfraInfo.NodeList) {
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $currentNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    Get-SdnNetworkControllerNodeCertificate
                }

                $newNodeCert = Invoke-PSRemoteCommand -ComputerName $node.IpAddressOrFQDN -Credential $Credential -ScriptBlock {
                    Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Thumbprint $using:nodeCertThumbprint
                }

                "Network Controller Node Certificate {0} will be updated from [Thumbprint:{1} NotAfter:{2}] to [Thumbprint:{3} NotAfter:{4}]" `
                    -f $currentNodeCert.Subject, $currentNodeCert.Thumbprint, $currentNodeCert.NotAfter, `
                    $newNodeCert.Thumbprint, $newNodeCert.NotAfter | Trace-Output -Level:Warning
            }
        }

        if (!$Force) {
            $confirm = Confirm-UserInput
            if (-NOT $confirm) {
                "User has opted to abort the operation. Terminating operation" | Trace-Output -Level:Warning
                return
            }
        }

        #####################################
        #
        # Rotate NC Certificate Expired
        #
        #####################################

        if ($restCertExpired -or !$ncHealthy) {
            # Use this for certificate if either rest cert expired or nc unhealthy, get-networkcontroller failed
            Start-SdnExpiredCertificateRotation -CertRotateConfig $CertRotateConfig -Credential $Credential -NcRestCredential $NcRestCredential
        }

        #####################################
        #
        # Rotate NC Northbound Certificate (REST)
        #
        #####################################

        "== STAGE: ROTATE NC REST CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkController' -Credential $Credential -Thumbprint $CertRotateConfig["NcRestCert"]

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate Cluster Certificate
        #
        #####################################

        "== STAGE: ROTATE NC CLUSTER CERTIFICATE ==" | Trace-Output

        $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerCluster' -Credential $Credential -Thumbprint $CertRotateConfig["NcRestCert"]

        "Waiting for 5 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
        Start-Sleep -Seconds 300

        #####################################
        #
        # Rotate NC Node Certificates
        #
        #####################################

        if ($rotateNCNodeCerts) {
            "== STAGE: ROTATE NC NODE CERTIFICATE ==" | Trace-Output

            foreach ($node in $NcInfraInfo.NodeList) {
                $nodeCertThumbprint = $certRotateConfig[$node.NodeName.ToLower()]
                $null = Invoke-CertRotateCommand -Command 'Set-NetworkControllerNode' -NetworkController $node.IpAddressOrFQDN -Credential $Credential -Thumbprint $nodeCertThumbprint

                "Waiting for 2 minutes before proceeding to the next step. Script will resume at {0}" -f (Get-Date).AddMinutes(5).ToUniversalTime().ToString() | Trace-Output
                Start-Sleep -Seconds 120
            }
        }

        #####################################
        #
        # Rotate NC Southbound Certificates
        #
        #####################################

        "== STAGE: ROTATE SOUTHBOUND CERTIFICATE CREDENTIALS ==" | Trace-Output

        $null = Update-NetworkControllerCredentialResource -NcUri "https://$($NcInfraInfo.NcRestName)" -Credential $NcRestCredential `
            -NewRestCertThumbprint $CertRotateConfig["NcRestCert"] -ErrorAction Stop

        "Certificate rotation completed successfully" | Trace-Output

        #####################################
        #
        # Certificate Seeding (Southbound Nodes)
        #
        #####################################

        # if nc was unhealthy and unable to determine southbound devices in the dataplane earlier
        # we now want to check to see if nc is healthy and if we need to install the rest cert (for self-signed) to southbound devices
        if ($postRotateSBRestCert) {
            if ($selfSignedRestCertFile) {
                $sdnFabricDetails = Get-SdnInfrastructureInfo -Credential $Credential -NcRestCredential $NcRestCredential -Force
                $southBoundNodes = @()
                if ($null -ne $sdnFabricDetails.LoadBalancerMux) {
                    $southBoundNodes += $sdnFabricDetails.LoadBalancerMux
                }
                if ($null -ne $sdnFabricDetails.Server) {
                    $southBoundNodes += $sdnFabricDetails.Server
                }

                if ($southBoundNodes) {
                    "== STAGE: REST SELF-SIGNED CERTIFICATE SEEDING (Southbound Nodes) ==" | Trace-Output

                    # ensure that we have the latest version of sdnDiagnostics module on the southbound devices
                    Install-SdnDiagnostics -ComputerName $southBoundNodes -Credential $Credential -ErrorAction Stop

                    "[REST CERT] Installing self-signed certificate to {0}" -f ($southBoundNodes -join ', ') | Trace-Output
                    [System.String]$remoteFilePath = Join-Path -Path $CertPath.FullName -ChildPath $selfSignedRestCertFile.Name
                    Copy-FileToRemoteComputer -ComputerName $southBoundNodes -Credential $Credential -Path $selfSignedRestCertFile.FullName -Destination $remoteFilePath
                    $null = Invoke-PSRemoteCommand -ComputerName $southBoundNodes -Credential $Credential -ScriptBlock {
                        Import-SdnCertificate -FilePath $using:remoteFilePath -CertStore 'Cert:\LocalMachine\Root'
                    } -ErrorAction Stop
                }
            }
        }

        "Certificate rotation has completed" | Trace-Output
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-SdnCertificateRotationConfig {
    <#
    .SYNOPSIS
        Validate the Cert Rotation Config provided is correct. Ensure certificates specified present on the machine.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {

        if ([string]::IsNullOrEmpty($CertRotateConfig["NcRestCert"])) {
            Trace-Output "NcRestCert not specified in CertRotateConfig" -Level:Exception
            return $false
        }

        $ncRestCert = $CertRotateConfig["NcRestCert"]
        foreach ($ncNode in $NcNodeList) {
            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                $nodeCert = $CertRotateConfig[$ncNode.NodeName.ToLower()]
                if ([string]::IsNullOrEmpty($nodeCert)) {
                    Trace-Output "The ClusterCredentialType is X509 but Node $($ncNode.NodeName) does not have certificate specified" -Level:Exception
                    return $false
                }
                else {
                    $certValid = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                        $nodeCertObj = Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $using:nodeCert
                        if ($null -eq $nodeCertObj) {
                            return $false
                        }
                        else {
                            if ($nodeCertObj.NotAfter -le (Get-Date)) {
                                return $false
                            }
                        }
                        return $true
                    }

                    if (!$certValid) {
                        Trace-Output "Node $($ncNode.NodeName) does not have validate Node certificate with thumbprint $nodeCert installed" -Level:Exception
                        return $false
                    }
                }
            }

            $certValid = Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                $ncRestCertObj = Get-SdnCertificate -Path "Cert:\LocalMachine\My" -Thumbprint $using:ncRestCert
                if ($null -eq $ncRestCertObj) {
                    return $false
                }
                else {
                    if ($ncRestCertObj.NotAfter -le (Get-Date)) {
                        return $false
                    }
                }
                return $true
            }

            if (!$certValid) {
                Trace-Output "Node $($ncNode.NodeName) does not have validate NcRest certificate with thumbprint $ncRestCert installed" -Level:Exception
                return $false
            }
        }
        return $true
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Update-NetworkControllerCertificateAcl {
    <#
    .SYNOPSIS
        Update the Network Controller Certificate to grant Network Service account read access to the private key.
    .PARAMETER NcNodeList
        The NcNodeList that retrieved via Get-SdnNetworkControllerInfoOffline.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include NC REST certificate thumbprint and node certificate thumbprint.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $NcNodeList,
        [Parameter(Mandatory = $true)]
        [hashtable]
        $CertRotateConfig,
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $NcRestCertThumbprint = $CertRotateConfig["NcRestCert"]

        foreach ($ncNode in $NcNodeList) {
            $ncNodeCertThumbprint = $CertRotateConfig[$ncNode.NodeName.ToLower()]
            Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $using:NcRestCertThumbprint
            } -Credential $Credential

            if ($CertRotateConfig["ClusterCredentialType"] -ieq "X509") {
                Invoke-PSRemoteCommand -ComputerName $ncNode.IpAddressOrFQDN -ScriptBlock {
                    Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $using:ncNodeCertThumbprint
                } -Credential $Credential
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

