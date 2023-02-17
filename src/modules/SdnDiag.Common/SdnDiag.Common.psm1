# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module "$PSScriptRoot\..\SdnDiag.Common\SdnDiag.Common.Utilities.psm1"

enum SdnRoles {
    Gateway
    NetworkController
    Server
    LoadBalancerMux
}

function Get-SdnGeneralConfigurationState {
    <#
        .SYNOPSIS
            Retrieves a common set of configuration details that is collected on any role, regardless of the role.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    $ProgressPreference = 'SilentlyContinue'

    try {
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "General"

        "Collect general configuration state details" | Trace-Output
        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumMB 100)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # Gather general configuration details from all nodes
        "Gathering network and system properties" | Trace-Output -Level:Verbose
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n = "ProcessName"; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } } `
        | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetTCPConnection' -FileType csv
        Get-Service | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Service' -FileType txt -Format List
        Get-Process | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Process' -FileType txt -Format List
        Get-Volume | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-Volume' -FileType txt -Format Table
        Get-ComputerInfo | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-ComputerInfo' -FileType txt
        Get-NetIPInterface | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetIPInterface' -FileType txt -Format Table
        Get-NetNeighbor -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetNeighbor' -FileType txt -Format Table
        Get-NetRoute -AddressFamily IPv4 -IncludeAllCompartments | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetRoute' -FileType txt -Format Table
        ipconfig /allcompartments /all | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'ipconfig_allcompartments' -FileType txt

        "Gathering network adapter properties" | Trace-Output -Level:Verbose
        Get-NetAdapter | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name 'Get-NetAdapter' -FileType txt -Format Table
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'NetAdapter') -ItemType Directory -Force
        foreach ($adapter in Get-NetAdapter) {
            Get-NetAdapter -Name $adapter.Name | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapter' -FileType txt -Format List
            Get-NetAdapterAdvancedProperty -Name $adapter.Name `
            | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterAdvancedProperty' -FileType txt -Format List
        }

        # Gather DNS client settings
        "Gathering DNS client properties" | Trace-Output -Level:Verbose
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'DnsClient') -ItemType Directory -Force
        $dnsCommands = Get-Command -Verb Get -Module DnsClient
        foreach ($cmd in $dnsCommands.Name) {
            Invoke-Expression -Command $cmd -ErrorAction SilentlyContinue | Export-ObjectToFile -FilePath $outputDir.FullName -Name $cmd.ToString() -FileType txt -Format List
        }

        # gather the certificates configured on the system
        $certificatePaths = @('Cert:\LocalMachine\My', 'Cert:\LocalMachine\Root')
        foreach ($path in $certificatePaths) {
            $fileName = $path.Replace(':', '').Replace('\', '_')
            Get-SdnCertificate -Path $path | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name "Get-SdnCertificate_$($fileName)" -FileType csv
        }

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }

    $ProgressPreference = 'Continue'
}

function Get-SdnRole {
    <#
        .SYNOPSIS
        Retrieve the SDN Role for a given computername

        .PARAMETER ComputerName
        Type the NetBIOS name or a fully qualified domain name of a computer.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName
    )

    if ($null -eq $Global:SdnDiagnostics.InfrastructureInfo.NetworkController) {
        "Unable to enumerate data from InfrastructureInfo. Please run 'Get-SdnInfrastructureInfo' to populate infrastructure details." | Trace-Output -Level:Warning
        return
    }

    # we know Windows has some strict requirements around NetBIOS/DNS name of the computer
    # so we can safely make some assumptions that if period (.) exists, then assume the ComputerName being passed into function
    # is a FQDN in which case we want to split the string and assign the NetBIOS name
    if ($ComputerName.Contains('.')) {
        [System.String]$computerNameNetBIOS = $ComputerName.Split('.')[0]
        [System.String]$computerNameFQDN = $ComputerName
    }

    # likewise, if no period (.) specified as part of the ComputerName we can assume we were passed a NetBIOS name of the object
    # in which case we will try to resolve via DNS. If any failures when resolving the HostName from DNS, will catch and default to
    # current user dns domain in best effort
    else {
        [System.String]$computerNameNetBIOS = $ComputerName
        try {
            [System.String]$computerNameFQDN = [System.Net.Dns]::GetHostByName($ComputerName).HostName
        }
        catch {
            [System.String]$computerNameFQDN = "$($ComputerName).$($env:USERDNSDOMAIN)"
        }
    }

    # enumerate the objects for each of the available SDN roles to find a match
    # once match is found, return the role name as string back to calling function
    foreach ($role in ($Global:SdnDiagnostics.InfrastructureInfo.Keys | Where-Object { $_ -iin $Global:SdnDiagnostics.Config.Keys })) {
        foreach ($object in $Global:SdnDiagnostics.InfrastructureInfo[$role]) {
            if ($object -ieq $computerNameNetBIOS -or $object -ieq $computerNameFQDN) {
                return $role.ToString()
            }
        }
    }

    # if we made it to here, we were unable to locate the appropriate role the computername is associated with
    "Unable to determine SDN role for {0}" -f $ComputerName | Trace-Output -Level:Warning
    return $null
}

function Get-SdnRoleConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role
    )

    return $Global:SdnDiagnostics

    return ($Global:SdnDiagnostics.Config[$Role])
}

function Get-SdnCertificate {
    <#
        .SYNOPSIS
            Returns a list of the certificates within the given certificate store.
        .PARAMETER Path
            Defines the path within the certificate store. Path is expected to start with cert:\.
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
        [System.String]$Thumbprint
    )

    try {
        $certificateList = Get-ChildItem -Path $Path -Recurse | Where-Object { $_.PSISContainer -eq $false } -ErrorAction Stop

        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $filteredCert = $certificateList | Where-Object { $_.Subject -ieq $Subject }
            }
            'Thumbprint' {
                $filteredCert = $certificateList | Where-Object { $_.Thumbprint -ieq $Thumbprint }
            }
            default {
                return $certificateList
            }
        }

        if ($null -eq $filteredCert) {
            "Unable to locate certificate using {0}" -f $PSCmdlet.ParameterSetName | Trace-Output -Level:Warning
            return $null
        }

        if ($filteredCert.NotAfter -le (Get-Date)) {
            "Certificate [Thumbprint: {0} | Subject: {1}] is currently expired" -f $filteredCert.Thumbprint, $filteredCert.Subject | Trace-Output -Level:Exception
        }

        return $filteredCert
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnDiagnosticLog {
    <#
    .SYNOPSIS
        Collect the default enabled logs from SdnDiagnostics folder.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 4 hours.
    .PARAMETER ConvertETW
        Optional parameter that allows you to specify if .etl trace should be converted. By default, set to $true
    .EXAMPLE
        PS> Get-SdnDiagnosticLog -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnDiagnosticLog -OutputDirectory "C:\Temp\CSS_SDN" -FromDate (Get-Date).AddHours(-8)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4),

        [Parameter(Mandatory = $false)]
        [bool]$ConvertETW = $true
    )

    try {
        [System.IO.FileInfo]$logDir = $Global:SdnDiagnostics.Settings.DefaultLogDirectory
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "SdnDiagnosticLogs"

        "Collect diagnostic logs between {0} and {1} UTC" -f $FromDate.ToUniversalTime(), (Get-Date).ToUniversalTime() | Trace-Output

        $logFiles = Get-ChildItem -Path $logDir.FullName -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $FromDate }
        if ($null -eq $logFiles) {
            "No log files found under {0} between {1} and {2} UTC." -f $logDir.FullName, $FromDate.ToUniversalTime(), (Get-Date).ToUniversalTime() | Trace-Output -Level:Warning
            return
        }

        $minimumDiskSpace = [float](Get-FolderSize -FileName $logFiles.FullName -Total).GB * 3.5

        # we want to call the initialize datacollection after we have identify the amount of disk space we will need to create a copy of the logs
        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB $minimumDiskSpace)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        # copy the log files from the default log directory to the output directory
        "Copying {0} files to {1}" -f $logFiles.Count, $OutputDirectory.FullName | Trace-Output -Level:Verbose
        Copy-Item -Path $logFiles.FullName -Destination $OutputDirectory.FullName -Force

        # convert the most recent etl trace file into human readable format without requirement of additional parsing tools
        if ($ConvertETW) {
            $convertFile = Get-Item -Path "$($OutputDirectory.FullName)\*" -Include '*.etl' | Sort-Object -Property LastWriteTime | Select-Object -Last 1
            if ($convertFile) {
                $null = Convert-SdnEtwTraceToTxt -FileName $convertFile.FullName -Overwrite 'Yes'
            }
        }

        # once we have copied the files to the new location we want to compress them to reduce disk space
        # if confirmed we have a .zip file, then remove the staging folder
        "Compressing results to {0}" -f "$($OutputDirectory.FullName).zip" | Trace-Output -Level:Verbose
        Compress-Archive -Path "$($OutputDirectory.FullName)\*" -Destination $OutputDirectory.FullName -CompressionLevel Optimal -Force
        if (Test-Path -Path "$($OutputDirectory.FullName).zip" -PathType Leaf) {
            Remove-Item -Path $OutputDirectory.FullName -Force -Recurse
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 1 day.
    .EXAMPLE
        PS> Get-SdnEventLog -OutputDirectory "C:\Temp\CSS_SDN"
    .EXAMPLE
        PS> Get-SdnEventLog -OutputDirectory "C:\Temp\CSS_SDN" -FromDate (Get-Date).AddHours(-12)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddDays(-1)
    )
    try {
        $eventLogs = [System.Collections.ArrayList]::new()
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "EventLogs"

        "Collect event logs between {0} and {1} UTC" -f $FromDate.ToUniversalTime(), (Get-Date).ToUniversalTime() | Trace-Output

        $config = Get-SdnRoleConfiguration -Role $Role
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT $confirmFeatures) {
            throw New-Object System.Exception("Required feature is missing")
        }

        if (-NOT (Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB 1)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        $eventLogProviders = $config.properties.eventLogProviders
        "Collect the following events: {0}" -f ($eventLogProviders -join ',') | Trace-Output

        # build array of win events based on which role the function is being executed
        # we will build these and dump the results at the end
        foreach ($provider in $eventLogProviders) {
            "Looking for event matching {0}" -f $provider | Trace-Output -Level:Verbose
            $eventLogsToAdd = Get-WinEvent -ListLog $provider -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount }
            if ($eventLogsToAdd.Count -gt 1) {
                [void]$eventLogs.AddRange($eventLogsToAdd)
            }
            elseif ($eventLogsToAdd.Count -gt 0) {
                [void]$eventLogs.Add($eventLogsToAdd)
            }
            else {
                "No events found for {0}" -f $provider | Trace-Output -Level:Warning
            }
        }

        foreach ($eventLog in $eventLogs) {
            $fileName = ("{0}\{1}" -f $OutputDirectory.FullName, $eventLog.LogName).Replace("/", "_")

            "Export event log {0} to {1}" -f $eventLog.LogName, $fileName | Trace-Output -Level:Verbose
            $events = Get-WinEvent -LogName $eventLog.LogName -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -gt $FromDate }
            if ($events) {
                $events | Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, ProviderID, TaskDisplayName, OpCodeDisplayName, Message `
                | Export-Csv -Path "$fileName.csv" -NoTypeInformation -Force
            }

            wevtutil epl $eventLog.LogName "$fileName.evtx" /ow
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Import-SdnCertificate {
    <#
    .SYNOPSIS
        Imports certificates and private keys from a Personal Information Exchange (PFX) file to the destination store.
    .PARAMETER FilePath
        Specifies the full path to the PFX file of the secured file.
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
        SelfSigned  = $false
        CertInfo    = $null
        CerFileInfo = $null
    }

    if ($CertPassword) {
        $pfxData = (Get-PfxData -FilePath $fileInfo.FullName -Password $CertPassword).EndEntityCertificates
    }
    else {
        $pfxData = Get-PfxCertificate -FilePath $fileInfo.FullName
    }

    $certExists = Get-ChildItem -Path $CertStore | Where-Object { $_.Thumbprint -ieq $pfxData.Thumbprint }
    if ($certExists) {
        "{0} already exists under {1}" -f $certExists.Thumbprint, $CertStore | Trace-Output -Level:Verbose
        $certObject.CertInfo = $certExists
    }
    else {
        "Importing {0} to {1}" -f $pfxData.Thumbprint, $CertStore | Trace-Output
        if ($pfxData.HasPrivateKey) {
            $importCert = Import-PfxCertificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -Password $CertPassword -Exportable -ErrorAction Stop
            Set-SdnCertificateAcl -Path $CertStore -Thumbprint $importCert.Thumbprint
        }
        else {
            $importCert = Import-Certificate -FilePath $fileInfo.FullName -CertStoreLocation $CertStore -ErrorAction Stop
        }

        $certObject.CertInfo = $importCert
    }

    # determine if the certificates being used are self signed
    if ($certObject.CertInfo.Subject -ieq $certObject.CertInfo.Issuer) {
        "Detected the certificate subject and issuer are the same. Setting SelfSigned to true" | Trace-Output -Level:Verbose
        $certObject.SelfSigned = $true

        # check to see if we installed to root store with above operation
        # if it is not, then we want to check the root store to see if this certificate has already been installed
        # and finally if does not exist, then export the certificate from current store and import into trusted root store
        if ($CertStore -ine $trustedRootStore) {
            $selfSignedCerExists = Get-ChildItem -Path $trustedRootStore | Where-Object { $_.Thumbprint -ieq $certObject.CertInfo.Thumbprint }
            [System.String]$selfSignedCerPath = "{0}\{1}.cer" -f (Split-Path $fileInfo.FullName -Parent), ($certObject.CertInfo.Subject).Replace('=', '_')
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
        If present, skip the check for admin privileges before execution. Note that without admin privileges, the scope and usefulness of the collected data is limited.
    .PARAMETER SkipLogs
        If present, skip the EVT and WER logs gather phases.
    .PARAMETER SkipNetshTrace
        If present, skip the Netsh Trace data gather phases.
    .PARAMETER SkipCounters
        If present, skip the Windows Performance Counters (WPM) data gather phases.
    .PARAMETER SkipVM
        If present, skip the Virtual Machine (VM) data gather phases.
    .EXAMPLE
        PS> Invoke-SdnGetNetView -OutputDirectory "C:\Temp\CSS_SDN"
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [int]$BackgroundThreads = 5,

        [Parameter(Mandatory = $false)]
        [switch]$SkipAdminCheck,

        [Parameter(Mandatory = $false)]
        [switch]$SkipLogs,

        [Parameter(Mandatory = $false)]
        [switch]$SkipNetshTrace,

        [Parameter(Mandatory = $false)]
        [switch]$SkipCounters,

        [Parameter(Mandatory = $false)]
        [switch]$SkipVm
    )

    try {
        Copy-Item -Path "$PSScriptRoot\..\..\..\tools\Get-NetView" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Force -Recurse
        Import-Module -Name 'Get-NetView' -Force
        "Using Get-NetView version {0}" -f (Get-Module -Name 'Get-NetView' -ErrorAction SilentlyContinue).Version.ToString() | Trace-Output -Level:Verbose

        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "NetView"
        # validate the output directory exists, else create the appropriate path
        if (!(Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        # execute Get-NetView with specified parameters and redirect all streams to null to prevent unnecessary noise on the screen
        Get-NetView -OutputDirectory $OutputDirectory.FullName `
            -BackgroundThreads $BackgroundThreads `
            -SkipAdminCheck:$SkipAdminCheck.IsPresent `
            -SkipLogs:$SkipLogs.IsPresent `
            -SkipNetshTrace:$SkipNetshTrace.IsPresent `
            -SkipCounters:$SkipCounters.IsPresent `
            -SkipVm:$SkipVm.IsPresent *> $null

        # remove the uncompressed files and folders to free up ~ 1.5GB of space
        $compressedArchive = Get-ChildItem -Path $OutputDirectory.FullName -Filter "*.zip"
        if ($compressedArchive) {
            Get-ChildItem -Path $OutputDirectory.FullName -Exclude *.zip | Remove-Item -Recurse -Confirm:$false
        }

        return $compressedArchive.FullName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function New-SdnCertificate {
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
        PS> New-SdnCertificate -Subject rest.sdn.contoso -CertStoreLocation Cert:\LocalMachine\My
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
        $selfSignedCert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject $Subject `
            -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 `
            -CertStoreLocation $CertStoreLocation -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") `
            -NotAfter $NotAfter

        if ($selfSignedCert) {
            "Successfully generated self signed certificate`n`tSubject: {0}`n`tThumbprint: {1}`n`tNotAfter: {2}" `
                -f $selfSignedCert.Subject, $selfSignedCert.Thumbprint, $selfSignedCert.NotAfter | Trace-Output

            Set-SdnCertificateAcl -Path $CertStoreLocation -Thumbprint $selfSignedCert.Thumbprint
        }

        return $selfSignedCert
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
            $privateKeyCertFile = Get-Item -Path "$($env:ProgramData)\Microsoft\Crypto\RSA\MachineKeys\*" | Where-Object { $_.Name -ieq $($certificate.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName) }
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Clear-SdnWorkingDirectory {
    <#
    .SYNOPSIS
        Clears the contents of the directory specified
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Path
        Specifies a path of the items being removed. Wildcard characters are permitted. If ommitted, defaults to (Get-WorkingDirectory).
    .PARAMETER Recurse
        Indicates that this cmdlet deletes the items in the specified locations and in all child items of the locations.
    .PARAMETER Force
        Forces the cmdlet to remove items that cannot otherwise be changed, such as hidden or read-only files or read-only aliases or variables.
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -ComputerName PREFIX-NC01 -Path 'C:\Temp\SDN2'
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -ComputerName PREFIX-NC01,PREFIX-SLB01 -Credential (Get-Credential)
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -Force -Recurse
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -Path 'C:\Temp\SDN1','C:\Temp\SDN2' -Force -Recurse
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [System.String[]]$Path = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Switch]$Force,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Clear-SdnWorkingDirectory
            } -ArgumentList $Path, $Recurse, $Force
        }
        else {
            foreach ($object in $Path) {
                # enumerate through the allowed folder paths for cleanup to make sure the paths specified can be cleaned up
                $pathAllowed = $false
                foreach ($allowedFolderPath in $Global:SdnDiagnostics.Settings.FolderPathsAllowedForCleanup) {
                    if ($object -ilike $allowedFolderPath) {
                        $pathAllowed = $true
                    }
                }

                # once validated that the path can be removed then perform test to make sure path exists before attempting to remove
                if ($pathAllowed) {
                    if (Test-Path -Path $object) {
                        "Remove {0}" -f $object | Trace-Output -Level:Verbose
                        Remove-Item -Path $object -Exclude $Global:SdnDiagnostics.Settings.FilesExcludedFromCleanup -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction Continue
                    }
                }
                else {
                    "{0} is not defined as an allowed path for cleanup. Skipping" -f $object | Trace-Output -Level:Warning
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Install-SdnDiagnostics {
    <#
    .SYNOPSIS
        Install SdnDiagnostic Module to remote computers if not installed or version mismatch.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        [System.IO.FileInfo]$moduleRootDir = "C:\Program Files\WindowsPowerShell\Modules"
        $filteredComputerName = [System.Collections.ArrayList]::new()
        $installNodes = [System.Collections.ArrayList]::new()

        # if we have multiple modules installed on the current workstation,
        # abort the operation because side by side modules can cause some interop issues to the remote nodes
        $localModule = Get-Module -Name 'SdnDiagnostics'
        if ($localModule.Count -gt 1) {
            throw New-Object System.ArgumentOutOfRangeException("Detected more than one module version of SdnDiagnostics. Remove existing modules and restart your PowerShell session.")
        }

        # since we may not know where the module was imported from we cannot accurately assume the $localModule.ModuleBase is correct
        # manually generate the destination path we want the module to be installed on remote nodes
        if ($localModule.ModuleBase -ilike "*$($localModule.Version.ToString())") {
            [System.IO.FileInfo]$destinationPathDir = "{0}\{1}\{2}" -f $moduleRootDir.FullName, 'SdnDiagnostics', $localModule.Version.ToString()
        }
        else {
            [System.IO.FileInfo]$destinationPathDir = "{0}\{1}" -f $moduleRootDir.FullName, 'SdnDiagnostics'
        }

        "Current version of SdnDiagnostics is {0}" -f $localModule.Version.ToString() | Trace-Output

        # make sure that in instances where we might be on a node within the sdn dataplane,
        # that we do not remove the module locally
        foreach ($computer in $ComputerName) {
            if (Test-ComputerNameIsLocal -ComputerName $computer) {
                "Detected that {0} is local machine. Skipping update operation for {0}." -f $computer | Trace-Output -Level:Warning
                continue
            }

            [void]$filteredComputerName.Add($computer)
        }

        # due to how arrayLists are interpreted, need to check if count is 0 rather than look for $null
        if ($filteredComputerName.Count -eq 0) {
            return
        }

        # check to see if the current version is already present on the remote computers
        # else if we -Force defined, we can just move forward
        if ($Force) {
            "{0} will be installed on all computers" -f $localModule.Version.ToString() | Trace-Output
            $installNodes = $filteredComputerName
        }
        else {
            "Getting current installed version of SdnDiagnostics on {0}" -f ($filteredComputerName -join ', ') | Trace-Output
            $remoteModuleVersion = Invoke-PSRemoteCommand -ComputerName $filteredComputerName -Credential $Credential -ScriptBlock {
                try {
                    # Get the latest version of SdnDiagnostics Module installed
                    $version = (Get-Module -Name SdnDiagnostics -ListAvailable -ErrorAction SilentlyContinue | Sort-Object Version -Descending)[0].Version.ToString()
                }
                catch {
                    # in some instances, the module will not be available and as such we want to skip the noise and return
                    # a string back to the remote call command which we can do proper comparison against
                    $version = '0.0.0.0'
                }

                return $version
            }

            # enumerate the versions returned for each computer and compare with current module version to determine if we should perform an update
            foreach ($computer in ($remoteModuleVersion.PSComputerName | Sort-Object -Unique)) {
                $remoteComputerModuleVersions = $remoteModuleVersion | Where-Object { $_.PSComputerName -ieq $computer }
                "{0} is currently using version(s): {1}" -f $computer, ($remoteComputerModuleVersions.ToString() -join ' | ') | Trace-Output -Level:Verbose
                $updateRequired = $true

                foreach ($version in $remoteComputerModuleVersions) {
                    if ([version]$version -ge [version]$localModule.Version) {
                        $updateRequired = $false

                        # if we found a version that is greater or equal to current version, break out of current foreach loop for the versions
                        # and move to the next computer as update is not required
                        break
                    }
                    else {
                        $updateRequired = $true
                    }
                }

                if ($updateRequired) {
                    "{0} will be updated to {1}" -f $computer, $localModule.Version.ToString() | Trace-Output
                    [void]$installNodes.Add($computer)
                }
            }
        }

        if (-NOT $installNodes) {
            "All computers are up to date with version {0}. No update required" -f $localModule.Version.ToString() | Trace-Output
            return
        }

        # clean up the module directory on remote computers
        "Cleaning up SdnDiagnostics in remote Windows PowerShell Module directory" | Trace-Output
        Invoke-PSRemoteCommand -ComputerName $installNodes -Credential $Credential -ScriptBlock {
            $modulePath = 'C:\Program Files\WindowsPowerShell\Modules\SdnDiagnostics'
            if (Test-Path -Path $modulePath -PathType Container) {
                Remove-Item -Path $modulePath -Recurse -Force
            }
        }

        # copy the module base directory to the remote computers
        # currently hardcoded to machine's module path. Use the discussion at https://github.com/microsoft/SdnDiagnostics/discussions/68 to get requirements and improvement
        Copy-FileToRemoteComputer -Path $localModule.ModuleBase -ComputerName $installNodes -Destination $destinationPathDir.FullName -Credential $Credential -Recurse -Force

        # ensure that we destroy the current pssessions for the computer to prevent any caching issues
        # we want to target all the original computers, as may be possible that we running on a node within the sdn fabric
        # and have existing PSSession to itself from previous execution run
        Remove-PSRemotingSession -ComputerName $ComputerName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Invoke-SdnCommand {
    <#
    .SYNOPSIS
        Runs commands on local and remote computers.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name a remote computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock $ScriptBlock
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}


