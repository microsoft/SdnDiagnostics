# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module $PSScriptRoot\SdnDiag.LoadBalancerMux.Health.psm1
Import-Module $PSScriptRoot\SdnDiag.Common.psm1
Import-Module $PSScriptRoot\SdnDiag.Utilities.psm1

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.LoadBalancerMux.Config.psd1"
New-Variable -Name 'SdnDiagnostics_SLB' -Scope 'Script' -Force -Value @{
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

function Get-MuxDriverControl {
    if (-NOT (Get-Module -Name 'Microsoft.Cloudnet.Slb.Mux.MuxDriverControl')) {
        Import-Module "$env:SystemRoot\System32\Microsoft.Cloudnet.Slb.Mux.MuxDriverControl.dll" -Force
    }

    return ([Microsoft.Cloudnet.Slb.Mux.Driver.SlbDriverControl]::new())
}

function Get-SlbMuxConfigState {
    <#
    .SYNOPSIS
        Outputs a set of configuration state files for the load balancer role.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .EXAMPLE
        PS> Get-SlbMuxConfigState -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $currentErrorActionPreference = $ErrorActionPreference
    $ProgressPreference = 'SilentlyContinue'
    $ErrorActionPreference = 'Ignore'

    try {
        $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ConfigState"
        [System.IO.FileInfo]$regDir = Join-Path -Path $OutputDirectory.FullName -ChildPath "Registry"

        "Collect configuration state details for role {0}" -f $config.Name | Trace-Output

        if (-NOT (Initialize-DataCollection -Role $config.Name -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            "Unable to initialize environment for data collection" | Trace-Output -Level:Error
            return
        }

        Export-RegistryKeyConfigDetails -Path $config.properties.regKeyPaths -OutputDirectory $regDir.FullName
        Get-CommonConfigState -OutputDirectory $OutputDirectory.FullName

        # output slb configuration and states
        "Getting MUX Driver Control configuration settings" | Trace-Output -Level:Verbose
        Get-SdnMuxState | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxState' -FileType json
        Get-SdnMuxDistributedRouterIP | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxDistributedRouterIP' -FileType json
        Get-SdnMuxStatefulVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxStatefulVip' -FileType json
        Get-SdnMuxStatelessVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxStatelessVip' -FileType json
        Get-SdnMuxStats | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxStats' -FileType json
        Get-SdnMuxVip | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxVip' -FileType json
        Get-SdnMuxVipConfig | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-SdnMuxVipConfig' -FileType json
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }

    $ProgressPreference = 'Continue'
    $ErrorActionPreference = $currentErrorActionPreference
}

function Get-SdnMuxCertificate {
    <#
        .SYNOPSIS
        Returns the certificate used by the SDN Load Balancer Mux.
    #>

    [CmdletBinding()]
    param ()

    try {
        $muxCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux' -Name 'MuxCert'
        $subjectName = "CN={0}" -f $muxCert
        $certificate = Get-SdnCertificate -Subject $subjectName -Path 'Cert:\LocalMachine\My'
        return $certificate
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxDistributedRouterIP {
    <#
        .SYNOPSIS
            This cmdlet returns the Distributed Router IPs that are advertised on the MUX.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxDistributedRouterIP
        .EXAMPLE
            PS> Get-SdnMuxDistributedRouterIP -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl

        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()
        $control.GetDrips($null , [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxState {
    <#
        .SYNOPSIS
            This cmdlet retrieves the current state of the load balancer MUX.
        .DESCRIPTION
    #>

    try {
        return (Get-MuxDriverControl)
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxStatefulVip {
    <#
        .SYNOPSIS
            Gets details related to the stateful VIPs.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxStatefulVip
        .EXAMPLE
            PS> Get-SdnMuxStatefulVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $statefulVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control.GetStatefulVips($null, [ref]$statefulVips)

        if ($VirtualIP) {
            return ($statefulVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statefulVips
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxStatelessVip {
    <#
        .SYNOPSIS
            Gets details related to the stateless VIPs.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxStatelessVip
        .EXAMPLE
            PS> Get-SdnMuxStatelessVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $statelessVips = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointKey]]::new()

        $control.GetStatelessVips($null, [ref]$statelessVips)

        if ($VirtualIP) {
            return ($statelessVips | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $statelessVips
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxStats {
    <#
        .SYNOPSIS
            Get the statistics related to the Virtual IPs.
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .PARAMETER SkipReset
        .EXAMPLE
            PS> Get-SdnMuxStats
        .EXAMPLE
            PS> Get-SdnMuxStats -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$SkipReset = $true
    )

    try {
        $control = Get-MuxDriverControl
        return ($control.GetGlobalStats($SkipReset))
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxVip {
    <#
        .SYNOPSIS
            This cmdlet returns the VIP endpoint(s).
        .DESCRIPTION
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxVip
        .EXAMPLE
            PS> Get-SdnMuxVip -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $vipConfig = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipConfig]]::new()

        $control.GetVips($null, [ref]$vipConfig)

        if ($VirtualIP) {
            return ($vipConfig | Where-Object {$_.AddressStr -ieq $VirtualIP})
        }
        else {
            return $vipConfig
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-SdnMuxVipConfig {
    <#
        .SYNOPSIS
            Get configuration details such as the DIPs of the backend resources related to Virtual IP
        .PARAMETER VirtualIP
            The Virtual IP address (VIP) of the resource. If omitted, will return all VIPs programmed within the MUX driver.
        .EXAMPLE
            PS> Get-SdnMuxVipConfig
        .EXAMPLE
            PS> Get-SdnMuxVipConfig -VirtualIP 100.90.95.42
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$VirtualIP
    )

    try {
        $control = Get-MuxDriverControl
        $list = [System.Collections.Generic.List[Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig]]::new()

        if ($VirtualIP) {
            $statefulVips = Get-SdnMuxStatefulVip -VirtualIp $VirtualIP
        }
        else {
            $statefulVips = Get-SdnMuxStatefulVip
        }

        foreach ($vip in $statefulVips) {
            $vipConfig = New-Object -Type Microsoft.Cloudnet.Slb.Mux.Driver.VipEndpointConfig
            $control.GetVipConfig($vip, [ref]$vipConfig)

            [void]$list.Add($vipConfig)
        }

        return $list
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function New-SdnMuxCertificate {
    <#
    .SYNOPSIS
        Generate new self-signed certificate to be used by Load Balancer Mux and distributes to the Network Controller(s) within the environment.
    .PARAMETER NotAfter
        Specifies the date and time, as a DateTime object, that the certificate expires. To obtain a DateTime object, use the Get-Date cmdlet. The default value for this parameter is one year after the certificate was created.
    .PARAMETER Path
        Specifies the file path location where a .cer file is exported automatically.
    .PARAMETER FabricDetails
        The SDN Fabric details derived from Get-SdnInfrastructureInfo.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user
    .EXAMPLE
        New-SdnMuxCertificate -NotAfter (Get-Date).AddYears(1) -FabricDetails $Global:SdnDiagnostics.EnvironmentInfo
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [datetime]$NotAfter = (Get-Date).AddYears(3),

        [Parameter(Mandatory = $false)]
        [System.String]$Path = "$(Get-WorkingDirectory)\MuxCert_{0}" -f (Get-FormattedDateTimeUTC),

        [Parameter(Mandatory = $false)]
        [System.Object]$FabricDetails,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a LoadBalancerMux, run this on LoadBalancerMux.")
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }

    try {
        if (-NOT (Test-Path -Path $Path -PathType Container)) {
            "Creating directory {0}" -f $Path | Trace-Output
            $CertPath = New-Item -Path $Path -ItemType Directory -Force
        }
        else {
            $CertPath = Get-Item -Path $Path
        }

        $muxCert = Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\SlbMux' -Name 'MuxCert'
        $subjectName = "CN={0}" -f $muxCert
        $certificate = New-SdnCertificate -Subject $subjectName -NotAfter $NotAfter

        # after the certificate has been generated, we want to export the certificate and save the file to directory
        # This allows the rest of the function to pick up these files and perform the steps as normal
        [System.String]$cerFilePath = "$(Join-Path -Path $CertPath.FullName -ChildPath $subjectName.ToString().ToLower().Replace('.','_').Replace("=",'_').Trim()).cer"
        "Exporting certificate to {0}" -f $cerFilePath | Trace-Output
        $exportedCertificate = Export-Certificate -Cert $certificate -FilePath $cerFilePath -Type CERT
        Copy-CertificateToFabric -CertFile $exportedCertificate.FullName -FabricDetails $FabricDetails -LoadBalancerMuxNodeCert -Credential $Credential

        $certObject = [PSCustomObject]@{
            Certificate = $certificate
            FileInfo = $exportedCertificate
        }

        return $certObject
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Start-SdnMuxCertificateRotation {
    <#
    .SYNOPSIS
        Performs a certificate rotation operation for the Load Balancer Muxes.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action on the Load Balancer Mux and Network Controller nodes. The default is the current user.
    .PARAMETER NcRestCertificate
        Specifies the client certificate that is used for a secure web request to Network Controller REST API.
        Enter a variable that contains a certificate or a command or expression that gets the certificate.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to perform this action against the Network Controller REST API. The default is the current user.
    .PARAMETER CertPath
        Path directory where certificate(s) .pfx files are located for use with certificate rotation.
    .PARAMETER GenerateCertificate
        Switch to determine if certificate rotate function should generate self-signed certificates.
    .PARAMETER CertPassword
        SecureString password for accessing the .pfx files, or if using -GenerateCertificate, what the .pfx files will be encrypted with.
    .PARAMETER NotAfter
        Expiration date when using -GenerateCertificate. If ommited, defaults to 3 years.
    .PARAMETER CertRotateConfig
        The Config generated by New-SdnCertificateRotationConfig to include appropriate certificate thumbprints for mux nodes.
    .PARAMETER Force
        Switch to force the rotation without being prompted, when Service Fabric is unhealthy.
    #>

    [CmdletBinding(DefaultParameterSetName = 'GenerateCertificate')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $true, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $true, ParameterSetName = 'CertConfig')]
        [System.String]$NetworkController,

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

        [Parameter(Mandatory = $false, ParameterSetName = 'Pfx')]
        [Parameter(Mandatory = $false, ParameterSetName = 'GenerateCertificate')]
        [Parameter(Mandatory = $false, ParameterSetName = 'CertConfig')]
        [X509Certificate]$NcRestCertificate,

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

    # these are not yet supported and will take a bit more time to implement as it touches on core framework for rotate functionality
    # however majority of the environments impacted are using sdnexpress which leverage self-signed certificates.
    if ($CertRotateConfig -or $CertPath) {
        "This feature is not yet supported and is under development. Please use -GenerateCertificate or reference {0} for manual steps." `
        -f  'https://learn.microsoft.com/en-us/azure-stack/hci/manage/update-network-controller-certificates?tabs=manual-renewal' | Trace-Output -Level:Warning
        return
    }

    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
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

    $array = @()
    $ncRestParams = @{
        NcUri = $null
    }
    $putRestParams = @{
        Body = $null
        Content = "application/json; charset=UTF-8"
        Headers = @{"Accept"="application/json"}
        Method = 'Put'
        Uri = $null
        UseBasicParsing = $true
    }
    $confirmStateParams = @{
        TimeoutInSec = 600
        UseBasicParsing = $true
    }

    if ($PSBoundParameters.ContainsKey('NcRestCertificate')) {
        $restCredParam = @{ NcRestCertificate = $NcRestCertificate }
        $ncRestParams.Add('NcRestCertificate', $NcRestCertificate)
        $putRestParams.Add('Certificate', $NcRestCertificate)
    }
    else {
        $restCredParam = @{ NcRestCredential = $NcRestCredential }
        $ncRestParams.Add('NcRestCredential', $NcRestCredential)
        $putRestParams.Add('Credential', $NcRestCredential)
    }
    $confirmStateParams += $restCredParam

    try {
        "Starting certificate rotation" | Trace-Output
        "Retrieving current SDN environment details" | Trace-Output

        if ([String]::IsNullOrEmpty($CertPath)) {
            [System.String]$CertPath = "$(Get-WorkingDirectory)\MuxCert_{0}" -f (Get-FormattedDateTimeUTC)

            if (-NOT (Test-Path -Path $CertPath -PathType Container)) {
                $null = New-Item -Path $CertPath -ItemType Directory -Force
            }
        }

        [System.IO.FileSystemInfo]$CertPath = Get-Item -Path $CertPath -ErrorAction Stop
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential @restCredParam -ErrorAction Stop
        if ($Global:SdnDiagnostics.EnvironmentInfo.ClusterConfigType -ine 'ServiceFabric') {
            throw New-Object System.NotSupportedException("This function is only supported on Service Fabric clusters.")
        }

        $ncRestParams.NcUri = $sdnFabricDetails.NcUrl
        $loadBalancerMuxes = Get-SdnLoadBalancerMux @ncRestParams -ErrorAction Stop

        # before we proceed with anything else, we want to make sure that all the Network Controllers and MUXes within the SDN fabric are running the current version
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.NetworkController -ErrorAction Stop
        Install-SdnDiagnostics -ComputerName $sdnFabricDetails.LoadBalancerMux -ErrorAction Stop

        #####################################
        #
        # Create Certificate (Optional)
        #
        #####################################

        if ($PSCmdlet.ParameterSetName -ieq 'GenerateCertificate') {
            "== STAGE: CREATE SELF SIGNED CERTIFICATES ==" | Trace-Output

            # retrieve the corresponding virtualserver reference for each loadbalancermux
            # and invoke remote operation to the mux to generate the self-signed certificate that matches the managementAddress for x509 credentials
            foreach ($muxResource in $loadBalancerMuxes) {
                $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $muxResource.properties.virtualServer.resourceRef
                $virtualServerConnection = $virtualServer.properties.connections | Where-Object { $_.credentialType -ieq "X509Certificate" -or $_.credentialType -ieq "X509CertificateSubjectName" }
                $managementAddress = $virtualServerConnection.managementAddresses[0]

                $muxCert = Invoke-PSRemoteCommand -ComputerName $managementAddress -Credential $Credential -ScriptBlock {
                    param(
                        [Parameter(Position = 0)][DateTime]$param1,
                        [Parameter(Position = 1)][PSCredential]$param2,
                        [Parameter(Position = 2)][String]$param3,
                        [Parameter(Position = 3)][System.Object]$param4
                    )

                    New-SdnMuxCertificate -NotAfter $param1 -Credential $param2 -Path $param3 -FabricDetails $param4
                } -ArgumentList @($NotAfter, $Credential, $CertPath.FullName, $sdnFabricDetails)

                $array += [PSCustomObject]@{
                    ManagementAddress = $managementAddress
                    ResourceRef = $virtualServer.resourceRef
                    Certificate = $muxCert.Certificate
                }
            }
        }

        # loop through all the objects to perform PUT operation against the virtualServer resource
        # to update the base64 encoding for the certificate that NC should use when communicating with the virtualServer resource
        foreach ($obj in $array) {
            "Updating certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            $virtualServer = Get-SdnResource @ncRestParams -ResourceRef $obj.ResourceRef
            $encoding = [System.Convert]::ToBase64String($obj.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

            if ($virtualServer.properties.certificate) {
                $virtualServer.properties.certificate = $encoding
            }
            else {
                # in instances where the certificate property does not exist, we will need to add it
                # this typically will occur if converting from CA issued certificate to self-signed certificate
                $virtualServer.properties | Add-Member -MemberType NoteProperty -Name 'certificate' -Value $encoding -Force
            }
            $putRestParams.Body = ($virtualServer | ConvertTo-Json -Depth 100)

            $endpoint = Get-SdnApiEndpoint -NcUri $sdnFabricDetails.NcUrl -ResourceRef $virtualServer.resourceRef
            $putRestParams.Uri = $endpoint

            $null = Invoke-RestMethodWithRetry @putRestParams
            if (-NOT (Confirm-ProvisioningStateSucceeded -NcUri $putRestParams.Uri @confirmStateParams)) {
                throw New-Object System.Exception("ProvisioningState is not succeeded")
            }
            else {
                "Successfully updated the certificate information for {0}" -f $obj.ResourceRef | Trace-Output
            }

            # after we have generated the certificates and updated the servers to use the new certificate
            # we will want to go and locate certificates that may conflict with the new certificate
            "Checking certificates on {0} that match {1}" -f $obj.managementAddress, $obj.Certificate.Subject | Trace-Output
            $certsToExamine = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                param([Parameter(Mandatory = $true)]$param1)
                $certs = Get-SdnCertificate -Path 'Cert:\LocalMachine\My' -Subject $param1.Subject
                if ($certs.Count -ge 2) {
                    $certToRemove = $certs | Where-Object {$_.Thumbprint -ine $param1.Thumbprint}

                    return $certToRemove
                }
            } -ArgumentList $obj.Certificate

            if ($certsToExamine) {
                "`nMultiple certificates detected for Subject: {0}. Examine the certificates and cleanup if no longer needed." -f $obj.Certificate.Subject | Trace-Output -Level:Warning
                foreach ($cert in $certsToExamine) {
                    "`t[{0}] Thumbprint: {1}" -f $cert.PSComputerName, $cert.Thumbprint | Trace-Output -Level:Warning
                }

                Write-Host "" # insert empty line for better readability
            }

            # restart the slb mux service on the mux
            $null = Invoke-PSRemoteCommand -ComputerName $obj.managementAddress -Credential $Credential -ScriptBlock {
                Restart-Service -Name SlbMux -Force
            }
        }

        "Certificate rotation for Load Balancer Muxes has completed" | Trace-Output -Level:Success
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

