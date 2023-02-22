# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module ".\..\classes\SdnDiag.Classes.psm1"

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
        [ValidateSet('Gateway','NetworkController','Server','LoadBalancerMux')]
        [System.String]$Role
    )

    return $Global:SdnDiagnostics

    return ($Global:SdnDiagnostics.Config[$Role])
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
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateSet('Gateway','NetworkController','Server','LoadBalancerMux')]
        [System.String]$Role,

        [Parameter(Mandatory = $true, Position = 1)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false, Position = 2)]
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
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, Position = 0, ParameterSetName = 'Local')]
        [System.String[]]$Path = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Local')]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Local')]
        [Switch]$Force,

        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    function Clear-WorkingDirectory {
        [CmdletBinding()]
        param (
            [System.String[]]$Path,
            [bool]$Recurse,
            [bool]$Force
        )

        $filteredPaths = @()
        foreach($obj in $Path) {
            # enumerate through the allowed folder paths for cleanup to make sure the paths specified can be cleaned up
            foreach ($allowedFolderPath in $Global:SdnDiagnostics.Settings.FolderPathsAllowedForCleanup) {
                if ($obj -ilike $allowedFolderPath) {
                    $filteredPaths += $obj
                }
            }
        }

        "Cleaning up: {0}" -f ($filteredPaths -join ', ') | Trace-Output -Level:Verbose
        Remove-Item -Path $filteredPaths -Exclude $Global:SdnDiagnostics.Settings.FilesExcludedFromCleanup -Force:$Force -Recurse:$Recurse -ErrorAction Continue
    }

    $params = @{
        Path = $Path
        Recurse = $Recurse.IsPresent
        Force = $Force.IsPresent
    }

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Clear-SdnWorkingDirectory @using:params
            }
        }
        else {
            Clear-WorkingDirectory @params
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

function Format-NetshTraceProviderAsString {
    <#
        .SYNOPSIS
            Formats the netsh trace providers into a string that can be passed to a netsh command
        .PARAMETER Provider
            The ETW provider in GUID format
        .PARAMETER Level
            Optional. Specifies the level to enable for the corresponding provider.
        .PARAMETER Keywords
            Optional. Specifies the keywords to enable for the corresponding provider.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [guid]$Provider,

        [Parameter(Mandatory = $false)]
        [string]$Level,

        [Parameter(Mandatory = $false)]
        [string]$Keywords
    )

    try {
        [guid]$guid = [guid]::Empty
        if (!([guid]::TryParse($Provider, [ref]$guid))) {
            throw "The value specified in the Provider argument must be in GUID format"
        }
        [string]$formattedString = $null
        foreach ($param in $PSBoundParameters.GetEnumerator()) {
            if ($param.Value) {
                if ($param.Key -ieq "Provider") {
                    $formattedString += "$($param.Key)='$($param.Value.ToString("B"))' "
                }
                elseif ($param.Key -ieq "Level" -or $param.Key -ieq "Keywords") {
                    $formattedString += "$($param.Key)=$($param.Value) "
                }
            }
        }

        return $formattedString.Trim()
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
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
        [ValidateSet('Gateway','NetworkController','Server','LoadBalancerMux')]
        [System.String]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default",

        [Parameter(Mandatory = $false)]
        [Switch]$AsString
    )

    try {
        $config = Get-SdnRoleConfiguration -Role $Role
        $traceProvidersArray = [System.Collections.ArrayList]::new()
        foreach ($traceProviders in $config.properties.etwTraceProviders) {
            switch ($Providers) {
                "Default" {
                    if ($traceProviders.isOptional -ne $true) {
                        [void]$traceProvidersArray.Add($traceProviders)
                    }
                }
                "Optional" {
                    if ($traceProviders.isOptional -eq $true) {
                        [void]$traceProvidersArray.Add($traceProviders)
                    }
                }
                "All" {
                    [void]$traceProvidersArray.Add($traceProviders)
                }
            }
        }

        # we want to be able to return string value back so it can then be passed to netsh trace command
        # enumerate the properties that have values to build a formatted string that netsh expects
        if ($PSBoundParameters.ContainsKey('AsString') -and $traceProvidersArray) {
            [string]$formattedString = $null
            foreach ($traceProvider in $traceProvidersArray) {
                foreach ($provider in $traceProvider.Providers) {
                    $formattedString += "$(Format-NetshTraceProviderAsString -Provider $provider -Level $traceProvider.level -Keywords $traceProvider.keywords) "
                }
            }

            return $formattedString.Trim()
        }

        return $traceProvidersArray
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
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
        # ensure that the directory exists for file path
        if (!(Test-Path -Path (Split-Path -Path $TraceFile.FullName -Parent) -PathType Container)) {
            $null = New-Item -Path (Split-Path -Path $TraceFile.FullName -Parent) -ItemType Directory -Force
        }

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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
    .PARAMETER Report
        Optional. Specifies whether a complementing report will be generated in addition to the trace file report. If unspecified, the default is disabled.
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
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Enabled', 'Disabled')]
        [System.String]$Report = 'Disabled'
    )

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

    # enable the network trace
    if ($TraceProviderString) {
        $cmd = "netsh trace start capture={0} {1} tracefile={2} maxsize={3} overwrite={4} report={5}" `
            -f $Capture, $TraceProviderString, $traceFile, $MaxTraceSize, $Overwrite, $Report
    }
    else {
        $cmd = "netsh trace start capture={0} tracefile={1} maxsize={2} overwrite={3} report={4}" `
            -f $Capture, $traceFile, $MaxTraceSize, $Overwrite, $Report
    }

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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Stop-NetshTrace {
    <#
    .SYNOPSIS
        Disables netsh tracing.
    #>

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
                    Status   = 'Success'
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
        [ValidateSet('Gateway','NetworkController','Server','LoadBalancerMux')]
        [System.String]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"
    )

    try {
        $config = Get-SdnRoleConfiguration -Role $Role
        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (!$confirmFeatures) {
            throw New-Object System.Exception("Required feature is missing")
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if (!$confirmModules) {
            throw New-Object System.Exception("Required module is not loaded")
        }

        # create the OutputDirectory if does not already exist
        if (!(Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers

        foreach ($traceProviders in $traceProvidersArray) {
            "Starting trace session {0}" -f $traceProviders.name | Trace-Output -Level:Verbose
            Start-EtwTraceSession -TraceName $traceProviders.name -TraceProviders $traceProviders.providers -TraceFile "$OutputDirectory\$($traceProviders.name).etl" -MaxTraceSize 1024
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
    .PARAMETER Overwrite
        Optional. Specifies whether this instance of the trace conversion command overwrites files that were rendered from previous trace conversions. If unspecified, the default is Yes.
    .PARAMETER Report
        Optional. Specifies whether a complementing report will be generated in addition to the trace file report. If unspecified, the default is disabled.
    .EXAMPLE
        PS> Start-SdnNetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes -Role Server
    .EXAMPLE
        PS> Start-SdnNetshTrace -ComputerName (Get-SdnInfrastructureInfo -NetworkController 'PREFIX-NC03').Server -Role Server -Credential (Get-Credential)
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'Remote')]
        [ValidateSet('Gateway','NetworkController','Server','LoadBalancerMux')]
        [System.String]$Role,

        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'Remote')]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\NetworkTrace",

        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, Position = 2, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No')]
        [System.String]$Capture = 'Yes',

        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, Position = 3, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, Position = 4, ParameterSetName = 'Remote')]
        [ValidateSet('Enabled', 'Disabled')]
        [System.String]$Report = 'Disabled',

        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, Position = 5, ParameterSetName = 'Remote')]
        [int]$MaxTraceSize = 1536,

        [Parameter(Mandatory = $false, Position = 6, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, Position = 6, ParameterSetName = 'Remote')]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "All",

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $params = @{
            OutputDirectory = $OutputDirectory
            Capture = $Capture
            Overwrite = $Overwrite
            Report = $Report
            MaxTraceSize = $MaxTraceSize
        }

        if ($PSCmdlet.ParameterSetName -eq 'Local') {
            $traceProviderString = Get-TraceProviders -Role $Role -Providers $Providers -AsString
            if ($null -eq $traceProviderString -and $Capture -eq 'No') {
                $Capture = 'Yes'
                "No default trace providers found for role {0}. Setting capture to {1}" -f $Role, $Capture | Trace-Output
            }

            if (-NOT ( Initialize-DataCollection -Role $Role -FilePath $OutputDirectory -MinimumMB ($MaxTraceSize * 1.5) )) {
                "Unable to initialize environment for data collection" | Trace-Output -Level:Error
                return
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            $params.Add('Role',$Role)

            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Start-SdnNetshTrace @using:params
            }
        }
        else {
            if ($traceProviderString) {
                $params.Add('TraceProviderString', $traceProviderString)
            }

            Start-NetshTrace @params
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Exception
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
        [ValidateSet('Gateway','NetworkController','Server','LoadBalancerMux')]
        [System.String]$Role,

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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Exception
    }
}

function Confirm-RequiredFeaturesInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    try {

        if ($null -eq $Name) {
            return $true
        }
        else {
            foreach ($obj in $Name) {
                if (!(Get-WindowsFeature -Name $obj).Installed) {
                    return $false
                }
            }

            return $true
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        return $false
    }
}

function Confirm-RequiredModulesLoaded {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    try {

        if ($null -eq $Name) {
            return $true
        }
        else {
            foreach ($obj in $Name) {
                if (!(Get-Module -Name $obj)) {
                    Import-Module -Name $obj -Force -ErrorAction Stop
                }
            }

            return $true
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        return $false
    }
}

function Confirm-UserInput {
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [System.String]$Message = "Do you want to continue with this operation? [Y/N]: ",
        [System.String]$BackgroundColor = "Black",
        [System.String]$ForegroundColor = "Yellow"
    )

    $Message | Trace-Output -Level:Verbose
    Write-Host -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewline $Message
    $answer = Read-Host
    if ($answer) {
        $answer | Trace-Output -Level:Verbose
    }
    else {
        "User pressed enter key" | Trace-Output -Level:Verbose
    }

    return ($answer -ieq 'y')
}
function Convert-FileSystemPathToUNC {
    <#
    .SYNOPSIS
        Converts a local file path to a computer specific admin UNC path, such as C:\temp\myfile.txt to \\azs-srng01\c$\temp\myfile.txt
    #>

    param(
        [System.String]$ComputerName,
        [System.String]$Path
    )

    $newPath = $path.Replace([System.IO.Path]::GetPathRoot($Path), [System.IO.Path]::GetPathRoot($Path).Replace(':', '$'))
    return ("\\{0}\{1}" -f $ComputerName, $newPath)
}

function Copy-FileFromRemoteComputer {
    <#
    .SYNOPSIS
        Copies an item from one location to another using FromSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    try {
        foreach ($object in $ComputerName) {
            if (Test-ComputerNameIsLocal -ComputerName $object) {
                "Detected that {0} is local machine" -f $object | Trace-Output
                foreach ($subPath in $Path) {
                    if ($subPath -eq $Destination.FullName) {
                        "Path {0} and Destination {1} are the same. Skipping" -f $subPath, $Destination.FullName | Trace-Output -Level:Warning
                    }
                    else {
                        "Copying {0} to {1}" -f $subPath, $Destination.FullName | Trace-Output
                        Copy-Item -Path $subPath -Destination $Destination.FullName -Recurse -Force -ErrorAction:Continue
                    }
                }
            }
            else {
                # try SMB Copy first and fallback to WinRM
                try {
                    Copy-FileFromRemoteComputerSMB -Path $Path -ComputerName $object -Destination $Destination -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction Stop
                }
                catch {
                    "{0}. Attempting to copy files using WinRM" -f $_ | Trace-Output -Level:Warning

                    try {
                        Copy-FileFromRemoteComputerWinRM -Path $Path -ComputerName $object -Destination $Destination -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -Credential $Credential
                    }
                    catch {
                        # Catch the copy failed exception to not stop the copy for other computers which might success
                        "{0}. Unable to copy files" -f $_ | Trace-Output -Level:Exception
                        continue
                    }
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Copy-FileFromRemoteComputerSMB {
    <#
    .SYNOPSIS
        Copies an item from one location to another using FromSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the remote computer.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    begin {
        $params = @{
            'Path'        = $null
            'Destination' = $Destination.FullName
            'Force'       = $Force.IsPresent
            'Recurse'     = $Recurse.IsPresent
        }
        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
            $params.Add('Credential', $Credential)
        }

        # set this to suppress the information status bar from being displayed
        $Global:ProgressPreference = 'SilentlyContinue'
        $testNetConnection = Test-NetConnection -ComputerName $ComputerName -Port 445 -InformationLevel Quiet
        $Global:ProgressPreference = 'Continue'

        # if we cannot access the remote computer via SMB port, then we want to terminate
        if (-NOT ($testNetConnection)) {
            $msg = "Unable to establish TCP connection to {0}:445" -f $ComputerName
            throw New-Object System.Exception($msg)
        }
    }

    process {
        foreach ($subPath in $Path) {
            $remotePath = Convert-FileSystemPathToUNC -ComputerName $ComputerName -Path $subPath
            if (-NOT (Test-Path -Path $remotePath)) {
                "Unable to find {0}" -f $remotePath | Trace-Output -Level:Exception
            }
            else {
                $params.Path = $remotePath

                try {
                    "Copying {0} to {1}" -f $params.Path, $params.Destination | Trace-Output
                    Copy-Item @params
                }
                catch [System.IO.IOException] {
                    if ($_.Exception.Message -ilike "*used by another process*") {
                        "{0}\{1} is in use by another process" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Exception
                        continue
                    }

                    if ($_.Exception.Message -ilike "*already exists*") {
                        "{0}\{1} already exists" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Exception
                        continue
                    }

                    $_ | Trace-Output -Level:Exception
                }
            }
        }
    }
}


function Copy-FileFromRemoteComputerWinRM {
    <#
    .SYNOPSIS
        Copies an item from one location to another using FromSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the computer.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $session = New-PSRemotingSession -ComputerName $ComputerName -Credential $Credential
    if ($session) {
        foreach ($subPath in $Path) {
            "Copying {0} to {1} using WinRM Session {2}" -f $subPath, $Destination.FullName, $session.Name | Trace-Output
            Copy-Item -Path $subPath -Destination $Destination.FullName -FromSession $session -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
        }
    }
    else {
        $msg = "Unable to copy files from {0} as remote session could not be established" -f $ComputerName
        throw New-Object System.Exception($msg)
    }
}

function Copy-FileToRemoteComputer {
    <#
    .SYNOPSIS
        Copies an item from local path to a path at remote server
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    try {
        foreach ($object in $ComputerName) {
            if (Test-ComputerNameIsLocal -ComputerName $object) {
                "Detected that {0} is local machine" -f $object | Trace-Output
                foreach ($subPath in $Path) {
                    if ($subPath -eq $Destination.FullName) {
                        "Path {0} and Destination {1} are the same. Skipping" -f $subPath, $Destination.FullName | Trace-Output -Level:Warning
                    }
                    else {
                        "Copying {0} to {1}" -f $subPath, $Destination.FullName | Trace-Output
                        Copy-Item -Path $subPath -Destination $Destination.FullName -Recurse -Force
                    }
                }
            }
            else {
                # try SMB Copy first and fallback to WinRM
                try {
                    Copy-FileToRemoteComputerSMB -Path $Path -ComputerName $object -Destination $Destination -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction Stop
                }
                catch {
                    "{0}. Attempting to copy files using WinRM" -f $_ | Trace-Output -Level:Warning

                    try {
                        Copy-FileToRemoteComputerWinRM -Path $Path -ComputerName $object -Destination $Destination -Credential $Credential -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent)
                    }
                    catch {
                        # Catch the copy failed exception to not stop the copy for other computers which might success
                        "{0}. Unable to copy files" -f $_ | Trace-Output -Level:Exception
                        continue
                    }
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Copy-FileToRemoteComputerSMB {
    <#
    .SYNOPSIS
        Copies an item from local path to a path at remote server via SMB
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the remote computer.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.String]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    begin {
        $params = @{
            'Path'        = $null
            'Destination' = $null
            'Force'       = $Force.IsPresent
            'Recurse'     = $Recurse.IsPresent
        }
        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
            $params.Add('Credential', $Credential)
        }

        # set this to suppress the information status bar from being displayed
        $Global:ProgressPreference = 'SilentlyContinue'
        $testNetConnection = Test-NetConnection -ComputerName $ComputerName -Port 445 -InformationLevel Quiet
        $Global:ProgressPreference = 'Continue'

        if (-NOT ($testNetConnection)) {
            $msg = "Unable to establish TCP connection to {0}:445" -f $ComputerName
            throw New-Object System.Exception($msg)
        }

        $remotePath = Convert-FileSystemPathToUNC -ComputerName $ComputerName -Path $Destination
        $params.Destination = $remotePath
    }
    process {
        foreach ($subPath in $Path) {
            $params.Path = $subPath

            try {
                "Copying {0} to {1}" -f $params.Path, $params.Destination | Trace-Output
                Copy-Item @params
            }
            catch [System.IO.IOException] {
                if ($_.Exception.Message -ilike "*used by another process*") {
                    "{0}\{1} is in use by another process" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Exception
                    continue
                }

                if ($_.Exception.Message -ilike "*already exists*") {
                    "{0}\{1} already exists" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Exception
                    continue
                }

                $_ | Trace-Output -Level:Exception
            }
        }
    }
}

function Copy-FileToRemoteComputerWinRM {
    <#
    .SYNOPSIS
        Copies an item from one location to another using ToSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one remote computer.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $session = New-PSRemotingSession -ComputerName $ComputerName -Credential $Credential
    if ($session) {
        foreach ($subPath in $Path) {
            "Copying {0} to {1} using WinRM Session {2}" -f $subPath, $Destination.FullName, $session.Name | Trace-Output
            Copy-Item -Path $subPath -Destination $Destination.FullName -ToSession $session -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
        }
    }
    else {
        $msg = "Unable to copy files to {0} as remote session could not be established" -f $ComputerName
        throw New-Object System.Exception($msg)
    }
}

function Export-ObjectToFile {
    <#
    .SYNOPSIS
        Save an object to a file in a consistent format.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [Object[]]$Object,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $false)]
        [System.String]$Prefix,

        [Parameter(Mandatory = $true)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [ValidateSet("json", "csv", "txt")]
        [System.String]$FileType = "json",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Table", "List")]
        [System.String]$Format
    )

    begin {
        $arrayList = [System.Collections.ArrayList]::new()

        # if object is null, then exit
        if ($null -eq $Object) {
            return
        }
    }
    process {
        foreach ($obj in $Object) {
            [void]$arrayList.add($obj)
        }
    }
    end {
        try {
            # build the file directory and name that will be used to export the object out
            if ($Prefix) {
                [System.String]$formattedFileName = "{0}\{1}_{2}.{3}" -f $FilePath.FullName, $Prefix, $Name, $FileType
            }
            else {
                [System.String]$formattedFileName = "{0}\{1}.{2}" -f $FilePath.FullName, $Name, $FileType
            }

            [System.IO.FileInfo]$fileName = $formattedFileName

            # create the parent directory structure if does not already exist
            if (!(Test-Path -Path $fileName.Directory -PathType Container)) {
                "Creating directory {0}" -f $fileName.Directory | Trace-Output -Level:Verbose
                $null = New-Item -Path $fileName.Directory -ItemType Directory
            }

            "Creating file {0}" -f $fileName | Trace-Output -Level:Verbose
            switch ($FileType) {
                "json" {
                    $arrayList | ConvertTo-Json -Depth 10 | Out-File -FilePath $fileName
                }
                "csv" {
                    $arrayList | Export-Csv -NoTypeInformation -Path $fileName
                }
                "txt" {
                    switch ($Format) {
                        'Table' {
                            $arrayList | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -FilePath $fileName
                        }
                        'List' {
                            $arrayList | Format-List -Property * | Out-File -FilePath $fileName
                        }
                        default {
                            $arrayList | Out-File -FilePath $fileName
                        }
                    }
                }
            }
        }
        catch {
            "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        }
    }
}

function Format-ByteSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    return ([PSCustomObject]@{
            GB = "{0}" -f ($Bytes / 1GB)
            MB = "{0}" -f ($Bytes / 1MB)
        })
}

function Format-MacAddressNoDashes {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted without dashes
    .PARAMETER MacAddress
        MAC Address to canonicalize into standard format
    #>
    param (
        [System.String]$MacAddress
    )

    "Processing {0}" -f $MacAddress | Trace-Output -Level:Verbose

    if ($MacAddress.Split('-').Count -eq 6) {
        foreach ($obj in $MacAddress.Split('-')) {
            if ($obj.Length -ne 2) {
                throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Unable to split into expected pairs")
            }
        }
    }

    $MacAddress = $MacAddress.Replace('-', '').Trim().ToUpper()
    return ($MacAddress.ToString())
}

function Format-MacAddressWithDashes {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted with dashes
    .PARAMETER MacAddress
        MAC Address to canonicalize into standard format
    #>
    param (
        [System.String]$MacAddress
    )

    "Processing {0}" -f $MacAddress | Trace-Output -Level:Verbose

    if ($MacAddress.Split('-').Count -eq 6) {
        foreach ($obj in $MacAddress.Split('-')) {
            if ($obj.Length -ne 2) {
                throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Unable to split into expected pairs")
            }
        }

        return ($MacAddress.ToString().ToUpper())
    }

    if ($MacAddress.Length -ne 12) {
        throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Length is not equal to 12 ")
    }
    else {
        $MacAddress = $MacAddress.Insert(2, "-").Insert(5, "-").Insert(8, "-").Insert(11, "-").Insert(14, "-").Trim().ToUpper()
        return ($MacAddress.ToString())
    }
}

function Get-FolderSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [System.IO.FileInfo]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'File')]
        [System.IO.FileInfo[]]$FileName,

        [Parameter(Mandatory = $false, ParameterSetName = 'File')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Path')]
        [Switch]$Total
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        switch ($PSCmdlet.ParameterSetName) {
            'File' {
                $items = Get-Item -Path $FileName -Force
            }
            'Path' {
                $items = Get-ChildItem -Path $Path -Force
            }
        }

        foreach ($item in $items) {
            if ($item.PSIsContainer -eq $true) {
                $subFolderItems = Get-ChildItem $item.FullName -Recurse | Where-Object { $_.PSIsContainer -eq $false } | Measure-Object -Property Length -Sum | Select-Object Sum
                $folderSize = Format-ByteSize -Bytes $subFolderItems.sum

                [void]$arrayList.Add([PSCustomObject]@{
                        Name     = $item
                        SizeInGB = $folderSize.GB
                        SizeInMB = $folderSize.MB
                        Size     = $subFolderItems.sum
                        Type     = "Folder"
                        FullName = $item.FullName
                    })

            }
            else {
                $fileSize = Format-ByteSize -Bytes $item.Length
                [void]$arrayList.Add([PSCustomObject]@{
                        Name     = $item.Name
                        SizeInGB = $fileSize.GB
                        SizeInMB = $fileSize.MB
                        Size     = $item.Length
                        Type     = "File"
                        FullName = $item.FullName
                    })
            }
        }

        if ($Total) {
            $totalSize = $arrayList | Measure-Object -Property Size -Sum
            $totalSizeFormatted = Format-ByteSize -Bytes $totalSize.Sum

            return $totalSizeFormatted
        }

        return ($arrayList | Sort-Object Type, Size)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-FormattedDateTimeUTC {
    return ([DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
}

function Get-FunctionFromFile {
    <#
    .SYNOPSIS
        Enumerates a ps1 file to identify the functions defined within
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]$Verb
    )

    try {
        # get the raw content of the script
        $code = Get-Content -Path $FilePath.FullName -Raw

        # list all the functions in ps1 using language namespace parser
        $functionName = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null).EndBlock.Statements.FindAll([Func[Management.Automation.Language.Ast, bool]] { $args[0] -is [Management.Automation.Language.FunctionDefinitionAst] }, $false) `
        | Select-Object -ExpandProperty Name

        if ($functionName) {
            return ($functionName | Where-Object { $_ -like "$Verb-*" })
        }
        else {
            return $null
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-SdnCache {
    <#
        .SYNOPSIS
            Returns the cache results stored with the global SdnDiagnostics cache variable
    #>

    param (
        [System.String]$Name
    )

    return $Global:SdnDiagnostics.Cache[$Name]
}

function Get-TraceOutputFile {
    return [System.IO.FileInfo]$global:SdnDiagnostics.TraceFilePath
}
function Get-UserInput {
    <#
    .SYNOPSIS
        Used in scenarios where you need to prompt the user for input
    .PARAMETER Message
        The message that you want to display to the user
    .EXAMPLE
        $choice = Get-UserInput -Message "Do you want to proceed with operation? [Y/N]: "
        Switch($choice){
            'Y' {Do action}
            'N' {Do action}
            default {Do action}
        }
    #>

    param
    (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [string]$Message,
        [string]$BackgroundColor = "Black",
        [string]$ForegroundColor = "Yellow"
    )

    Write-Host -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewline $Message;
    return Read-Host
}

function Get-WorkingDirectory {
    return [System.IO.FileInfo]$global:SdnDiagnostics.Settings.WorkingDirectory
}

function Invoke-PSRemoteCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Object[]]$ArgumentList,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [System.String]$Activity,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$ExecutionTimeout = 600
    )

    $session = New-PSRemotingSession -ComputerName $ComputerName -Credential $Credential
    if ($session) {
        "ComputerName: {0}, ScriptBlock: {1}" -f ($session.ComputerName -join ', '), $ScriptBlock.ToString() | Trace-Output -Level:Verbose
        if ($ArgumentList) {
            "Arguments: {0}" -f ($ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
        }

        if ($AsJob) {
            $result = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -AsJob -JobName $([guid]::NewGuid().Guid) -ArgumentList $ArgumentList
            if ($PassThru) {
                if ($Activity) {
                    $result = Wait-PSJob -Name $result.Name -ExecutionTimeOut $ExecutionTimeout -Activity $Activity
                }
                else {
                    $result = Wait-PSJob -Name $result.Name -ExecutionTimeOut $ExecutionTimeout
                }
            }

            return $result
        }
        else {
            return (Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList)
        }
    }
}

function Invoke-RestMethodWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$Headers,

        [Parameter (Mandatory = $false)]
        [System.String]$ContentType,

        [Parameter(Mandatory = $false)]
        [System.Object] $Body,

        [Parameter(Mandatory = $false)]
        [Switch] $DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch] $UseBasicParsing,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSec = 600,

        [Parameter(Mandatory = $false)]
        [Switch]$Retry,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Int]$MaxRetry = 3,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Int]$RetryIntervalInSeconds = 30
    )

    $params = @{
        'Headers'     = $Headers;
        'ContentType' = $ContentType;
        'Method'      = $Method;
        'Uri'         = $Uri;
        'TimeoutSec'  = $TimeoutInSec
    }

    if ($null -ne $Body) {
        $params.Add('Body', $Body)
    }

    if ($DisableKeepAlive.IsPresent) {
        $params.Add('DisableKeepAlive', $true)
    }

    if ($UseBasicParsing.IsPresent) {
        $params.Add('UseBasicParsing', $true)
    }

    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }
    else {
        $params.Add('UseDefaultCredentials', $true)
    }

    $counter = 0
    while ($true) {
        $counter++

        try {
            "Performing {0} request to uri {1}" -f $Method, $Uri | Trace-Output -Level:Verbose
            if ($Body) {
                "Body:`n`t{0}" -f ($Body | ConvertTo-Json -Depth 10) | Trace-Output -Level:Verbose
            }

            $result = Invoke-RestMethod @params

            break
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq "NotFound") {
                "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Trace-Output -Level:Warning
                return $null
            }
            else {
                $_ | Trace-Output -Level:Exception
            }

            if (($counter -le $MaxRetry) -and $Retry) {
                "Retrying operation in {0} seconds. Retry count: {1}." - $RetryIntervalInSeconds, $counter | Trace-Output
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
            else {
                throw $_
            }
        }
    }

    return $result
}

function Invoke-WebRequestWithRetry {
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$Uri,

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'Get',

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$Headers,

        [Parameter (Mandatory = $false)]
        [System.String]$ContentType,

        [Parameter(Mandatory = $false)]
        [System.Object] $Body,

        [Parameter(Mandatory = $false)]
        [Switch] $DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch] $UseBasicParsing,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSec = 600,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Switch]$Retry,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Int]$MaxRetry = 3,

        [Parameter(Mandatory = $false, ParameterSetName = 'Retry')]
        [Int]$RetryIntervalInSeconds = 30
    )

    $params = @{
        'Headers'     = $Headers;
        'ContentType' = $ContentType;
        'Method'      = $Method;
        'Uri'         = $Uri;
        'TimeoutSec'  = $TimeoutInSec
    }

    if ($null -ne $Body) {
        $params.Add('Body', $Body)
    }

    if ($DisableKeepAlive.IsPresent) {
        $params.Add('DisableKeepAlive', $true)
    }

    if ($UseBasicParsing.IsPresent) {
        $params.Add('UseBasicParsing', $true)
    }

    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
        $params.Add('Credential', $Credential)
    }
    else {
        $params.Add('UseDefaultCredentials', $true)
    }

    $counter = 0
    while ($true) {
        $counter++

        try {
            "Performing {0} request to uri {1}" -f $Method, $Uri | Trace-Output -Level:Verbose
            if ($Body) {
                "Body:`n`t{0}" -f $Body | Trace-Output -Level:Verbose
            }

            $result = Invoke-WebRequest @params

            break
        }
        catch {
            if ($_.Exception.Response.StatusCode -eq "NotFound") {
                "{0} ({1})" -f $_.Exception.Message, $_.Exception.Response.ResponseUri.AbsoluteUri | Trace-Output -Level:Warning
                return $null
            }
            else {
                $_ | Trace-Output -Level:Exception
            }

            if (($counter -le $MaxRetry) -and $Retry) {
                "Retrying operation in {0} seconds. Retry count: {1}." - $RetryIntervalInSeconds, $counter | Trace-Output
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
            else {
                throw $_
            }
        }
    }

    "StatusCode: {0} StatusDescription: {1}" -f $result.StatusCode, $result.StatusDescription | Trace-Output -Level:Verbose
    return $result
}

function New-TraceOutputFile {

    try {
        # make sure that directory path exists, else create the folder structure required
        [System.IO.FileInfo]$workingDir = Get-WorkingDirectory
        if (!(Test-Path -Path $workingDir.FullName -PathType Container)) {
            $workingDir = New-Item -Path $workingDir.FullName -ItemType Directory -Force
        }

        # build the trace file path and set global variable
        [System.String]$fileName = "SdnDiagnostics_TraceOutput_{0}.csv" -f (Get-Date).ToString('yyyyMMdd')
        [System.IO.FileInfo]$filePath = Join-Path -Path $workingDir.FullName -ChildPath $fileName
        Set-TraceOutputFile -Path $filePath.FullName

        # configure the cache to not cleanup the trace file
        $Global:SdnDiagnostics.Settings.FilesExcludedFromCleanup = $filePath.Name

        "TraceFile: {0}" -f $filePath.FullName | Trace-Output -Level:Verbose
    }
    catch {
        $_.Exception | Write-Error
    }
}

function New-WorkingDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Path = $global:SdnDiagnostics.Settings.WorkingDirectory
    )

    try {

        # create the working directory and set the global cache
        if (!(Test-Path -Path $Path.FullName -PathType Container)) {
            $null = New-Item -Path $Path.FullName -ItemType Directory -Force
        }

        # create the trace file
        New-TraceOutputFile
    }
    catch {
        $_.Exception | Write-Error
    }
}

function Set-TraceOutputFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$Path
    )

    $global:SdnDiagnostics.TraceFilePath = $Path.FullName
}

function New-PSRemotingSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    try {
        # ensure that WinRM service is running on the local machine
        $serviceState = Get-Service -Name 'WinRm'
        if ($serviceState.Status -ine 'Running') {
            $msg = "WinRM Service is currently {0}. Ensure that service is running and try again." -f $serviceState.Status
            throw New-Object System.Exception($msg)
        }

        $remoteSessions = [System.Collections.ArrayList]::new()

        # return a list of current sessions on the computer
        # return only the sessions that are opened and available as this will allow new sessions to be opened
        # without having to wait for existing sessions to move from Busy -> Available
        $currentActiveSessions = Get-PSSession -Name "SdnDiag-*" | Where-Object { $_.State -ieq 'Opened' -and $_.Availability -ieq 'Available' }

        foreach ($obj in $ComputerName) {
            $session = $null

            # determine if an IP address was passed for the destination
            # if using IP address it needs to be added to the trusted hosts
            $isIpAddress = ($obj -as [IPAddress]) -as [Bool]
            if ($isIpAddress) {
                "{0} is an ip address" -f $obj | Trace-Output -Level:Verbose
                $trustedHosts = Get-Item -Path "WSMan:\localhost\client\TrustedHosts"
                if ($trustedHosts.Value -notlike "*$obj*" -and $trustedHosts.Value -ne "*") {
                    "Adding {0} to {1}" -f $obj, $trustedHosts.PSPath | Trace-Output
                    Set-Item -Path "WSMan:\localhost\client\TrustedHosts" -Value $obj -Concatenate
                }
            }

            # check to see if session is already opened
            # if no session already exists or Force is defined, then create a new remote session
            if ($currentActiveSessions.ComputerName -contains $obj -and !$Force) {
                $session = ($currentActiveSessions | Where-Object { $_.ComputerName -eq $obj })[0]
                "Located existing powershell session {0} for {1}" -f $session.Name, $obj | Trace-Output -Level:Verbose
            }
            else {
                try {
                    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                        "PSRemotingSession use provided credential {0}" -f $Credential.UserName | Trace-Output -Level:Verbose
                        $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $obj -Credential $Credential -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US) -ErrorAction Stop
                    }
                    else {
                        # if we need to create a new remote session, need to check to ensure that if using an IP Address that credentials are specified
                        # which is a requirement from a WinRM perspective. Will throw a warning and skip session creation for this computer.
                        if ($isIpAddress -and $Credential -eq [System.Management.Automation.PSCredential]::Empty) {
                            "Unable to create PSSession to {0}. The Credential parameter is required when using an IP Address." -f $obj | Trace-Output -Level:Warning
                            continue
                        }

                        "PSRemotingSession use default credential" | Trace-Output -Level:Verbose
                        $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $obj -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US) -ErrorAction Stop
                    }

                    "Created powershell session {0} to {1}" -f $session.Name, $obj | Trace-Output -Level:Verbose
                }
                catch {
                    "Unable to create powershell session to {0}`n`t{1}" -f $obj, $_.Exception | Trace-Output -Level:Warning
                    continue
                }
            }

            # add the session to the array
            if ($session) {
                [void]$remoteSessions.Add($session)
            }
        }

        return $remoteSessions

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Remove-PSRemotingSession {
    <#
    .SYNOPSIS
        Gracefully removes any existing PSSessions
    .PARAMETER ComputerName
        The computer name(s) that should have any existing PSSessions removed
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName
    )

    try {
        [int]$timeOut = 120
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object {$_.ComputerName -iin $ComputerName}
        while ($sessions) {
            if ($stopWatch.Elapsed.TotalSeconds -gt $timeOut) {
                throw New-Object System.TimeoutException("Unable to drain PSSessions")
            }

            foreach ($session in $sessions) {
                if ($session.Availability -ieq 'Busy') {
                    "{0} is currently {1}. Waiting for PSSession.. {2} seconds" -f $session.Name, $session.Availability, $stopWatch.Elapsed.TotalSeconds | Trace-Output
                    Start-Sleep -Seconds 5
                    continue
                }
                else {
                    "Removing PSSession {0}" -f $session.Name | Trace-Output -Level:Verbose
                    $session | Remove-PSSession -ErrorAction Continue
                }
            }

            $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object { $_.ComputerName -iin $ComputerName }
        }

        $stopWatch.Stop()
        "Successfully drained PSSessions for {0}" -f ($ComputerName -join ', ') | Trace-Output
    }
    catch {
        $stopWatch.Stop()
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-ComputerNameIsLocal {
    <##>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName
    )

    try {
        # detect if the ComputerName passed is an IP address
        # if so, need to enumerate the IP addresses on the system to compare with ComputerName to determine if there is a match
        $isIpAddress = ($ComputerName -as [IPAddress]) -as [Bool]
        if ($isIpAddress) {
            $ipAddresses = Get-NetIPAddress
            foreach ($ip in $ipAddresses) {
                if ([IPAddress]$ip.IpAddress -eq [IPAddress]$ComputerName) {
                    return $true
                }
            }
        }

        # check to determine if the ComputerName matches the NetBIOS name of the computer
        if ($env:COMPUTERNAME -ieq $ComputerName) {
            return $true
        }

        # check to determine if ComputerName matches the FQDN name of the computer
        if (([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName) -ieq $ComputerName) {
            return $true
        }

        return $false
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Test-Ping {
    <#
    .SYNOPSIS
        Sends ICMP echo request packets.
    .PARAMETER DestinationAddress
        Specifies the destination IP address to use.
    .PARAMETER SourceAddress
        Specifies the source IP address to use.
    .PARAMETER CompartmentId
        Specifies an ID of compartment to perform the ping from within.
    .PARAMETER BufferSize
        Specifies the size, in bytes, of the buffer sent with this command. The default value is 1472.
    .PARAMETER DontFragment
        This parameter sets the Don't Fragment flag in the IP header. You can use this parameter with the BufferSize parameter to test the Path MTU size.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [IPAddress]$DestinationAddress,

        [Parameter(Mandatory = $true)]
        [IPAddress]$SourceAddress,

        [Parameter(Mandatory = $false)]
        [int]$CompartmentId = (Get-NetCompartment | Where-Object { $_.CompartmentDescription -ieq 'Default Compartment' }).CompartmentId,

        [Parameter()]
        [int[]]$BufferSize = 1472,

        [Parameter(Mandatory = $false)]
        [switch]$DontFragment
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        foreach ($size in $BufferSize) {
            $Global:LASTEXITCODE = 0
            if ($DontFragment) {
                $ping = ping $DestinationAddress.IPAddressToString -c $CompartmentId -l $size -S $SourceAddress.IPAddressToString -n 2-f
            }
            else {
                $ping = ping $DestinationAddress.IPAddressToString -c $CompartmentId -l $size -S $SourceAddress.IPAddressToString -n 2
            }

            if ($LASTEXITCODE -ieq 0) {
                $status = 'Success'
            }
            else {
                $status = 'Failure'
            }

            $result = [PSCustomObject]@{
                SourceAddress      = $SourceAddress.IPAddressToString
                DestinationAddress = $DestinationAddress.IPAddressToString
                CompartmentId      = $CompartmentId
                BufferSize         = $size
                Status             = $status
                Result             = $ping
            }

            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Trace-Output {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]$Message,

        [Parameter(Mandatory = $false)]
        [TraceLevel]$Level
    )

    begin {
        if (!$PSBoundParameters.ContainsKey('Level')) {
            $Level = [TraceLevel]::Information
        }

        $traceFile = (Get-TraceOutputFile)
        if ([string]::IsNullOrEmpty($traceFile)) {
            New-WorkingDirectory

            $traceFile = (Get-TraceOutputFile)
        }
    }
    process {
        # create custom object for formatting purposes
        $traceEvent = [PSCustomObject]@{
            Computer     = $env:COMPUTERNAME.ToUpper().ToString()
            TimestampUtc = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH-mm-ss')
            FunctionName = (Get-PSCallStack)[1].Command
            Level        = $Level.ToString()
            Message      = $Message
        }

        # write the message to the console
        switch ($Level) {
            'Error' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Error
            }

            'Exception' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Host -ForegroundColor:Red
            }

            'Success' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Host -ForegroundColor:Green
            }

            'Verbose' {
                if ($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                    "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Verbose
                }
            }

            'Warning' {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Warning
            }

            default {
                "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message | Write-Host -ForegroundColor:Cyan
            }
        }

        # write the event to trace file to be used for debugging purposes
        $mutexInstance = Wait-OnMutex -MutexId 'SDN_TraceLogging' -ErrorAction Continue
        if ($mutexInstance) {
            $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile.FullName
        }
    }
    end {
        if ($mutexInstance) {
            $mutexInstance.ReleaseMutex()
        }
    }
}

function Wait-OnMutex {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$MutexId
    )

    try {
        $MutexInstance = New-Object System.Threading.Mutex($false, $MutexId)
        if ($MutexInstance.WaitOne(3000)) {
            return $MutexInstance
        }
        else {
            throw New-Object -TypeName System.TimeoutException("Failed to acquire Mutex")
        }
    }

    catch [System.Threading.AbandonedMutexException] {
        $MutexInstance = New-Object System.Threading.Mutex($false, $MutexId)
        return (Wait-OnMutex -MutexId $MutexId)
    }
    catch {
        $MutexInstance.ReleaseMutex()
        $_ | Write-Error
    }
}

function Wait-PSJob {
    <#
    .SYNOPSIS
        Monitors jobs to ensure they complete or terminate if any particular job is taking too long
    .PARAMETER Name
        The job name to monitor
    .PARAMETER Activity
        Description of the job that is being performed
    .PARAMETER ExecutionTimeOut
        Total period to wait for jobs to complete before stopping jobs and progressing forward in scripts. If omitted, defaults to 600 seconds
    .PARAMETER PollingInterval
        How often you want to query job status. If omitted, defaults to 1 seconds
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.String]$Name,

        [Parameter(Mandatory = $false)]
        [System.String]$Activity = (Get-PSCallStack)[1].Command,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    try {
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        "JobName: {0} PollingInterval: {1} seconds ExecutionTimeout: {2} seconds" -f $Name, $PollingInterval, $ExecutionTimeOut | Trace-Output -Level:Verbose

        # Loop while there are running jobs
        while ((Get-Job -Name $Name).State -ieq 'Running') {

            # get the job details and write progress
            $job = Get-Job -Name $Name
            $runningChildJobs = $job.ChildJobs | Where-Object { $_.State -ieq 'Running' }
            $jobCount = $job.ChildJobs.Count
            $runningJobCount = $runningChildJobs.Count
            $percent = [math]::Round((($jobcount - $runningJobCount) / $jobCount * 100), 2)

            $status = "Progress: {0}%. Waiting for {1}" -f $percent, ($runningChildJobs.Location -join ', ')
            Write-Progress -Activity $Activity -Status $status -PercentComplete $percent -Id $job.Id

            # check the stopwatch and break out of loop if we hit execution timeout limit
            if ($stopWatch.Elapsed.TotalSeconds -ge $ExecutionTimeOut) {
                Get-Job -Name $Name | Stop-Job -Confirm:$false
                throw New-Object System.TimeoutException("Unable to complete operation within the specified timeout period")
            }

            # pause the loop per polling interval value
            Start-Sleep -Seconds $PollingInterval
        }

        $stopWatch.Stop()
        $job = Get-Job -Name $Name

        # Ensure that we complete all jobs for write-progress to clear the progress bars
        Write-Progress -Activity $Activity -Id $job.Id -Completed

        # Output results of the job status to the operator
        if ($job.State -ne "Completed") {
            [System.String]$outputFolder = "{0}\PSRemoteJob_Failures\{1}" -f (Get-WorkingDirectory), $Name

            "[{0}] Operation {1}. Total Elapsed Time: {2}" -f $Name, $job.State, $stopwatch.Elapsed.TotalSeconds | Trace-Output -Level:Warning

            # Identify all failed child jobs and present to the operator
            $failedChildJobs = $job.ChildJobs | Where-Object { $_.State -ine 'Completed' }
            foreach ($failedChildJob in $failedChildJobs) {
                "[{0}] {1} for {2} is reporting state: {3}." -f $Name, $failedChildJob.Name, $failedChildJob.Location, $failedChildJob.State | Trace-Output -Level:Warning

                # do our best to capture the failing exception that was returned from the remote job invocation
                # due to ps remoting bug as outlined in https://github.com/PowerShell/PowerShell/issues/9585 we may not capture everything and may add additional details to screen
                $failedChildJob | Receive-Job -Keep -ErrorAction Continue *>&1 | Export-ObjectToFile -FilePath $outputFolder -Name $failedChildJob.Name -FileType 'txt'
            }
        }
        else {
            "[{0}] Operation {1}. Total Elapsed Time: {2}" -f $Name, $job.State, $stopwatch.Elapsed.TotalSeconds | Trace-Output -Level:Verbose
        }

        return (Get-Job -Name $Name | Receive-Job)
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Initialize-DataCollection {
    <#
    .SYNOPSIS
        Prepares the environment for data collection that logs will be saved to.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [System.String]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [System.Int32]$MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.Int32]$MinimumMB
    )

    # ensure that the appropriate windows feature is installed and ensure module is imported
    if ($Role) {
        $config = Get-SdnRoleConfiguration -Role $Role
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if (-NOT ($confirmFeatures)) {
            "Required feature is missing: {0}" -f ($config.windowsFeature -join ', ') | Trace-Output -Level:Exception
            return $false
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if (-NOT ($confirmModules)) {
            "Required module is not loaded: {0}" -f ($config.requiredModules -join ', ') | Trace-Output -Level:Exception
            return $false
        }
    }

    # create the directories if does not already exist
    if (-NOT (Test-Path -Path $FilePath.FullName -PathType Container)) {
        "Creating {0}" -f $FilePath.FullName | Trace-Output -Level:Verbose
        $null = New-Item -Path $FilePath.FullName -ItemType Directory -Force
    }

    # confirm sufficient disk space
    [System.Char]$driveLetter = (Split-Path -Path $FilePath.FullName -Qualifier).Replace(':', '')
    switch ($PSCmdlet.ParameterSetName) {
        'GB' {
            $diskSpace = Confirm-DiskSpace -DriveLetter $driveLetter -MinimumGB $MinimumGB
        }
        'MB' {
            $diskSpace = Confirm-DiskSpace -DriveLetter $driveLetter -MinimumMB $MinimumMB
        }
    }

    if (-NOT ($diskSpace)) {
        "Insufficient disk space detected." | Trace-Output -Level:Exception
        return $false
    }

    return $true
}

function Confirm-DiskSpace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [System.Char]$DriveLetter,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        $MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        $MinimumMB
    )

    try {
        $drive = Get-PSDrive $DriveLetter -ErrorAction Stop
        if ($null -eq $drive) {
            throw New-Object System.NullReferenceException("Unable to retrieve PSDrive information")
        }

        $freeSpace = Format-ByteSize -Bytes $drive.Free
        switch ($PSCmdlet.ParameterSetName) {
            'GB' {
                "Required: {0} GB | Available: {1} GB" -f ([float]$MinimumGB).ToString(), $freeSpace.GB | Trace-Output
                if ([float]$freeSpace.GB -gt [float]$MinimumGB) {
                    return $true
                }
            }

            'MB' {
                "Required: {0} MB | Available: {1} MB" -f ([float]$MinimumMB).ToString(), $freeSpace.MB | Trace-Output
                if ([float]$freeSpace.MB -gt [float]$MinimumMB) {
                    return $true
                }
            }
        }

        return $false
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
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
        if (!(Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        foreach ($regKeyPath in $Path) {
            "Enumerating the registry key paths for {0}" -f $regkeyPath | Trace-Output -Level:Verbose

            $regKeyDirectories = @()
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -ErrorAction SilentlyContinue
            $regKeyDirectories += Get-ChildItem -Path $regKeyPath -Recurse -ErrorAction SilentlyContinue
            $regKeyDirectories = $regKeyDirectories | Sort-Object -Unique

            [System.String]$filePath = "{0}\Registry_{1}.txt" -f $OutputDirectory.FullName, $($regKeyPath.Replace(':', '').Replace('\', '_'))
            foreach ($obj in $RegKeyDirectories) {
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
                if ($properties.Path -like "*.dll" -or $properties.Path -like "*.exe") {
                    "Getting file properties for {0}" -f $properties.Path | Trace-Output -Level:Verbose
                    [System.String]$fileName = "FileInfo_{0}" -f $($properties.Path.Replace(':', '').Replace('\', '_').Replace('.', '_'))
                    Get-Item -Path $properties.Path | Export-ObjectToFile -FilePath $OutputDirectory.FullName -Name $fileName -FileType txt -Format List
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
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
        [Parameter(Mandatory = $true, Position = 0)]
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
        Copy-Item -Path "$PSScriptRoot\..\..\..\packages\Get-NetView" -Destination "C:\Program Files\WindowsPowerShell\Modules" -Force -Recurse
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
