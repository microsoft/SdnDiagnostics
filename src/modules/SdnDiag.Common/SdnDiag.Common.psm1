# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -ErrorAction SilentlyContinue
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -Recurse -ErrorAction SilentlyContinue
            $regKeyDirectories = $regKeyDirectories | Sort-Object -Unique

            [System.String]$filePath = "{0}\Registry_{1}.txt" -f $OutputDirectory.FullName, $($regKeyPath.Replace(':','').Replace('\','_'))
            foreach($obj in $RegKeyDirectories){
                "Scanning {0}" -f $obj.PsPath | Trace-Output -Level:Verbose
                try {
                    $properties = Get-ItemProperty -Path $obj.PSPath -ErrorAction Stop
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-GeneralConfigurationState {
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
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{n="ProcessName";e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} `
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
        foreach($adapter in Get-NetAdapter){
            Get-NetAdapter -Name $adapter.Name | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapter' -FileType txt -Format List
            Get-NetAdapterAdvancedProperty -Name $adapter.Name `
                | Export-ObjectToFile -FilePath $outputDir.FullName -Prefix $adapter.Name -Name 'Get-NetAdapterAdvancedProperty' -FileType txt -Format List
        }

        # Gather DNS client settings
        "Gathering DNS client properties" | Trace-Output -Level:Verbose
        $outputDir = New-Item -Path (Join-Path -Path $OutputDirectory.FullName -ChildPath 'DnsClient') -ItemType Directory -Force
        $dnsCommands = Get-Command -Verb Get -Module DnsClient
        foreach($cmd in $dnsCommands.Name){
            Invoke-Expression -Command $cmd -ErrorAction SilentlyContinue | Export-ObjectToFile -FilePath $outputDir.FullName -Name $cmd.ToString() -FileType txt -Format List
        }

        # gather the certificates configured on the system
        $certificatePaths = @('Cert:\LocalMachine\My','Cert:\LocalMachine\Root')
        foreach ($path in $certificatePaths) {
            $fileName = $path.Replace(':','').Replace('\','_')
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

    if ($null -eq $Global:SdnDiagnostics.EnvironmentInfo.NetworkController) {
        "Unable to enumerate data from EnvironmentInfo. Please run 'Get-SdnInfrastructureInfo' to populate infrastructure details." | Trace-Output -Level:Warning
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
    foreach ($role in ($Global:SdnDiagnostics.EnvironmentInfo.Keys | Where-Object {$_ -iin $Global:SdnDiagnostics.Config.Keys})) {
        foreach ($object in $Global:SdnDiagnostics.EnvironmentInfo[$role]) {
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

    return (Get-Content -Path "$PSScriptRoot\..\..\..\config\$Role\settings.json" | ConvertFrom-Json)
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
        $certificateList = Get-ChildItem -Path $Path -Recurse | Where-Object {$_.PSISContainer -eq $false} -ErrorAction Stop

        switch ($PSCmdlet.ParameterSetName) {
            'Subject' {
                $filteredCert = $certificateList | Where-Object {$_.Subject -ieq $Subject}
            }
            'Thumbprint' {
                $filteredCert = $certificateList | Where-Object {$_.Thumbprint -ieq $Thumbprint}
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
        if($null -eq $logFiles){
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
        SelfSigned = $false
        CertInfo = $null
        CerFileInfo = $null
    }

    if ($CertPassword) {
        $pfxData = (Get-PfxData -FilePath $fileInfo.FullName -Password $CertPassword).EndEntityCertificates
    }
    else {
        $pfxData = Get-PfxCertificate -FilePath $fileInfo.FullName
    }

    $certExists = Get-ChildItem -Path $CertStore | Where-Object {$_.Thumbprint -ieq $pfxData.Thumbprint}
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

