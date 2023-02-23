# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

using module ".\..\classes\SdnDiag.Classes.psm1"
. "$PSScriptRoot\..\scripts\SdnDiag.Utilities.ps1"

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

            # if the path does not exist, lets skip
            if (-NOT (Test-Path -Path $obj)) {
                continue
            }

            # enumerate through the allowed folder paths for cleanup to make sure the paths specified can be cleaned up
            foreach ($allowedFolderPath in $Global:SdnDiagnostics.Settings.FolderPathsAllowedForCleanup) {
                if ($obj -ilike $allowedFolderPath) {
                    $filteredPaths += $obj
                }
            }
        }

        if ($filteredPaths) {
            "Cleaning up: {0}" -f ($filteredPaths -join ', ') | Trace-Output -Level:Verbose
            Remove-Item -Path $filteredPaths -Exclude $Global:SdnDiagnostics.Settings.FilesExcludedFromCleanup -Force:$Force -Recurse:$Recurse -ErrorAction Continue
        }
    }

    $params = @{
        Path = $Path
        Recurse = $Recurse.IsPresent
        Force = $Force.IsPresent
    }

    "Parameters: {0}" -f $params | Trace-Output -Level:Verbose
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

            $config = Get-SdnRoleConfiguration -Role $Role
            if (-NOT ( Initialize-DataCollection -Configuration $config -FilePath $OutputDirectory -MinimumMB ($MaxTraceSize * 1.5) )) {
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
