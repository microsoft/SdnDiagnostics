# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

$configurationData = Import-PowerShellDataFile -Path "$PSScriptRoot\SdnDiag.Utilities.Config.psd1"
New-Variable -Name 'SdnDiagnostics_Utilities' -Scope 'Script' -Force -Value @{
    Cache = @{
        FilesExcludedFromCleanup = @()
        TraceFilePath = $null
        WorkingDirectory = $null
    }
    Config = $configurationData
}

##########################
#### CLASSES & ENUMS #####
##########################

enum TraceLevel {
    Error
    Exception
    Information
    Success
    Verbose
    Warning
}

enum SdnModules {
    Common
    Gateway
    LoadBalancerMux
    NetworkController
    NetworkController_FC
    NetworkController_SF
    Server
    Utilities
}

##########################
#### ARG COMPLETERS ######
##########################

##########################
####### FUNCTIONS ########
##########################

function Confirm-DiskSpace {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MB')]
        [System.String]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        $MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        $MinimumMB
    )

    # if the file path is a cluster storage, we want to check the CSVs
    if ($FilePath -ilike "*\ClusterStorage\*") {
        $csvs = Get-ClusterSharedVolume | Select-Object SharedVolumeInfo
        if ($null -ne $csvs) {
            foreach ($csv in $csvs) {

                # if the friendly volume name is empty, we want to skip
                if ([string]::IsNullOrEmpty($csv.SharedVolumeInfo.FriendlyVolumeName)) {
                    continue
                }

                # if the file path starts with the friendly volume name, we want to check the partition
                if ($FilePath.StartsWith($csv.SharedVolumeInfo.FriendlyVolumeName, [System.StringComparison]::OrdinalIgnoreCase)) {
                    if ($null -ne $csv.SharedVolumeInfo.Partition) {
                        $freeSpace = Format-ByteSize -Bytes $csv.SharedVolumeInfo.Partition.FreeSpace

                        break
                    }
                }
            }
        }
    }
    else {
        [System.Char]$driveLetter = (Split-Path -Path $FilePath -Qualifier).Replace(':','')

        $drive = Get-PSDrive $DriveLetter -ErrorAction Stop
        if ($null -eq $drive) {
            throw New-Object System.NullReferenceException("Unable to retrieve PSDrive information")
        }

        $freeSpace = Format-ByteSize -Bytes $drive.Free
    }

    if ($null -eq $freeSpace) {
        throw New-Object System.NullReferenceException("Unable to retrieve free space information")
    }

    switch ($PSCmdlet.ParameterSetName) {
        'GB' {
            "Required: {0} GB | Available: {1} GB" -f ([float]$MinimumGB).ToString(), $freeSpace.GB | Trace-Output -Level:Verbose
            if ([float]$freeSpace.GB -gt [float]$MinimumGB) {
                return $true
            }

            # if we do not have enough disk space, we want to provide what was required vs what was available
            "Required: {0} GB | Available: {1} GB" -f ([float]$MinimumGB).ToString(), $freeSpace.GB | Trace-Output -Level:Error
            return $false
        }

        'MB' {
            "Required: {0} MB | Available: {1} MB" -f ([float]$MinimumMB).ToString(), $freeSpace.MB | Trace-Output -Level:Verbose
            if ([float]$freeSpace.MB -gt [float]$MinimumMB) {
                return $true
            }

            # if we do not have enough disk space, we want to provide what was required vs what was available
            "Required: {0} MB | Available: {1} MB" -f ([float]$MinimumMB).ToString(), $freeSpace.MB | Trace-Output -Level:Error
            return $false
        }
    }
}

function Confirm-IpAddressInRange {
    <#
        .SYNOPSIS
            Uses .NET to compare the IpAddress specified to see if it falls within the StartAddress and EndAddress range specified.
        .PARAMETER IpAddress
            The IP Address that you want to validate.
        .PARAMETER StartAddress
            The lower end of the IP address range that you want to validate against.
        .PARAMETER EndAddress
            The upper end of the IP address range that you want to validate against.
        .EXAMPLE
            PS> Confirm-IpAddressInRange -IpAddress 192.168.0.10 -StartAddress 192.168.0.1 -EndAddress 192.168.0.255
    #>

    param(
        [System.String]$IpAddress,
        [System.String]$StartAddress,
        [System.String]$EndAddress
    )

    # if null ip address is specified, will default to $false that does not exist within range specified
    if([String]::IsNullOrEmpty($IpAddress)) {
        return $false
    }

    $ip = [System.Net.IPAddress]::Parse($IpAddress).GetAddressBytes()
    [array]::Reverse($ip)
    $ip = [System.BitConverter]::ToUInt32($ip, 0)

    $from = [System.Net.IPAddress]::Parse($StartAddress).GetAddressBytes()
    [array]::Reverse($from)
    $from = [System.BitConverter]::ToUInt32($from, 0)

    $to = [System.Net.IPAddress]::Parse($EndAddress).GetAddressBytes()
    [array]::Reverse($to)
    $to = [System.BitConverter]::ToUInt32($to, 0)

    $from -le $ip -and $ip -le $to
}

function Confirm-IsAdmin {
    # ensure that the module is running as local administrator
    $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-NOT $elevated) {
        throw New-Object System.Exception("This function requires elevated permissions. Run PowerShell as an Administrator and import the module again.")
    }
}

function Confirm-IsNetworkController {
    $config = Get-SdnModuleConfiguration -Role 'NetworkController'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a NetworkController, run this on NetworkController or use -NetworkController parameter (if available).")
    }
}

function Confirm-IsLoadBalancerMux {
    $config = Get-SdnModuleConfiguration -Role 'LoadBalancerMux'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a LoadBalancerMux. Run this on LoadBalancerMux.")
    }
}

function Confirm-IsServer {
    $config = Get-SdnModuleConfiguration -Role 'Server'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a Server. Run this on Server.")
    }
}

function Confirm-IsRasGateway {
    $config = Get-SdnModuleConfiguration -Role 'Gateway'
    $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
    if (-NOT ($confirmFeatures)) {
        throw New-Object System.NotSupportedException("The current machine is not a Gateway. Run this on Gateway.")
    }
}

function Confirm-ProvisioningStateSucceeded {
    <#
    .SYNOPSIS
        Used to verify the resource within the NC NB API is succeeded
    #>

    [CmdletBinding(DefaultParameterSetName = 'RestCredential')]
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri]$NcUri,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCredential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$NcRestCredential,

        [Parameter(Mandatory = $false, ParameterSetName = 'RestCertificate')]
        [X509Certificate]$NcRestCertificate,

        [Parameter(Mandatory = $false)]
        [Switch]$DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch]$UseBasicParsing,

        [Parameter(Mandatory = $false)]
        [Int]$TimeoutInSec = 120
    )

    $params = @{
        Uri              = $NcUri
        DisableKeepAlive = $DisableKeepAlive
        UseBasicParsing  = $UseBasicParsing
        Method           = 'Get'
        ErrorAction      = 'Stop'
    }

    switch ($PSCmdlet.ParameterSetName) {
        'RestCertificate' {
            $params.Add('Certificate', $NcRestCertificate)
        }
        'RestCredential' {
            $params.Add('Credential', $NcRestCredential)
        }
    }

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        if ($stopWatch.Elapsed.TotalSeconds -gt $TimeoutInSec) {
            $stopWatch.Stop()
            throw New-Object System.TimeoutException("ProvisioningState for $($result.resourceId) did not succeed within the alloted time")
        }

        $result = Invoke-RestMethodWithRetry @params
        switch ($result.properties.provisioningState) {
            'Updating' {
                "ProvisioningState for $($result.resourceId) is updating. Waiting for completion..." | Trace-Output
                Start-Sleep -Seconds 5
            }

            'Succeeded' {
                $stopWatch.Stop()

                "ProvisioningState for $($result.resourceId) succeeded." | Trace-Output
                return $true
            }

            'Failed' {
                $stopWatch.Stop()
                throw New-Object System.Exception("Failed to update $($result.resourceId). Examine Network Controller logs for more information.")
            }

            default {
                throw New-Object System.Exception("Unknown provisioning state $($result.properties.provisioningState)")
            }
        }
    }
}

function Confirm-RequiredFeaturesInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    try {

        if($null -eq $Name){
            return $true
        }
        else {
            foreach($obj in $Name){
                if(!(Get-WindowsFeature -Name $obj).Installed){
                    return $false
                }
            }

            return $true
        }
    }
    catch {
        $_ | Trace-Exception
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

        if($null -eq $Name){
            return $true
        }
        else {
            foreach($obj in $Name){
                if(!(Get-Module -Name $obj)){
                    Import-Module -Name $obj -Force -ErrorAction Stop
                }
            }

            return $true
        }
    }
    catch {
        $_ | Trace-Exception
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

    $newPath = $path.Replace([System.IO.Path]::GetPathRoot($Path),[System.IO.Path]::GetPathRoot($Path).Replace(':','$'))
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
                        "{0}. Unable to copy files" -f $_ | Trace-Output -Level:Error
                        continue
                    }
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
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
            'Path'          = $null
            'Destination'   = $Destination.FullName
            'Force'         = $Force.IsPresent
            'Recurse'       = $Recurse.IsPresent
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
                "Unable to find {0}" -f $remotePath | Trace-Output -Level:Error
            }
            else {
                $params.Path = $remotePath

                try {
                    "Copying {0} to {1}" -f $params.Path, $params.Destination | Trace-Output
                    Copy-Item @params
                }
                catch [System.IO.IOException] {
                    if ($_.Exception.Message -ilike "*used by another process*") {
                        "{0}\{1} is in use by another process" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Error
                        continue
                    }

                    if ($_.Exception.Message -ilike "*already exists*") {
                        "{0}\{1} already exists" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Error
                        continue
                    }

                    throw $_
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
                        "{0}. Unable to copy files" -f $_ | Trace-Output -Level:Error
                        continue
                    }
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
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
            'Path'          = $null
            'Destination'   = $null
            'Force'         = $Force.IsPresent
            'Recurse'       = $Recurse.IsPresent
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

        [System.IO.FileInfo]$remotePath = Convert-FileSystemPathToUNC -ComputerName $ComputerName -Path $Destination.FullName
        $params.Destination = $remotePath.FullName
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
                    "{0}\{1} is in use by another process" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Error
                    continue
                }

                if ($_.Exception.Message -ilike "*already exists*") {
                    "{0}\{1} already exists" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Error
                    continue
                }

                throw $_
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
        # copy the files to the destination using WinRM
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
        [ValidateSet("json","csv","txt")]
        [System.String]$FileType = "json",

        [Parameter(Mandatory = $false)]
        [ValidateSet("Table","List")]
        [System.String]$Format,

        [Parameter(Mandatory = $false)]
        [System.String]$Depth = 2
    )

    begin {
        $arrayList = [System.Collections.ArrayList]::new()
        # build the file directory and name that will be used to export the object out
        if($Prefix){
            [System.String]$formattedFileName = "{0}\{1}_{2}.{3}" -f $FilePath.FullName, $Prefix, $Name, $FileType
        }
        else {
            [System.String]$formattedFileName = "{0}\{1}.{2}" -f $FilePath.FullName, $Name, $FileType
        }
        [System.IO.FileInfo]$fileName = $formattedFileName

        # create the parent directory structure if does not already exist
        if(!(Test-Path -Path $fileName.Directory -PathType Container)){
            try {
                $null = New-Item -Path $fileName.Directory -ItemType Directory -ErrorAction Stop
            }
            catch {
                $_ | Trace-Exception
                throw New-Object System.Exception("Failed to create directory $($fileName.Directory)")
            }
        }
    }
    process {
        $arrayList.AddRange($Object)
    }
    end {
        if ($arrayList.Count -eq 0) {
            return
        }

        try {
            "Creating file {0}" -f $fileName | Trace-Output -Level:Verbose
            switch($FileType){
                "json" {
                    $arrayList | ConvertTo-Json -Depth $Depth | Out-File -FilePath $fileName -Force
                }
                "csv" {
                    $arrayList | Export-Csv -NoTypeInformation -Path $fileName -Force
                }
                "txt" {
                    $FormatEnumerationLimit = 500
                    switch($Format){
                        'Table' {
                            $arrayList | Format-Table -AutoSize -Wrap | Out-String -Width 4096 | Out-File -FilePath $fileName -Force
                        }
                        'List' {
                            $arrayList | Format-List -Property * | Out-File -FilePath $fileName -Force
                        }
                        default {
                            $arrayList | Out-File -FilePath $fileName -Force
                        }
                    }
                }
            }
        }
        catch {
            $_ | Trace-Exception
            $_ | Write-Error
        }
    }
}

function Format-ByteSize {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [double]$Bytes
    )

    $gb = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $Bytes / 1GB)
    $mb = [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, "{0}", $Bytes / 1MB)

    return ([PSCustomObject]@{
        GB = $gb
        MB = $mb
    })
}

function Format-MacAddress {
    <#
    .SYNOPSIS
        Returns a consistent MAC address back formatted with or without dashes
    .PARAMETER MacAddress
        MAC Address to canonicalize into standard format
    .PARAMETER Dashes
        Optional. If specified, the MAC address will be formatted with dashes
    #>
    param (
        [System.String]$MacAddress,
        [Switch]$Dashes
    )

    if ($Dashes) {
        return (Format-MacAddressWithDashes -MacAddress $MacAddress)
    }
    else {
        return (Format-MacAddressNoDashes -MacAddress $MacAddress)
    }
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

    if($MacAddress.Split('-').Count -eq 6){
        foreach($obj in $MacAddress.Split('-')){
            if($obj.Length -ne 2){
                throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Unable to split into expected pairs")
            }
        }
    }

    $MacAddress = $MacAddress.Replace('-','').Trim().ToUpper()
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

    if($MacAddress.Split('-').Count -eq 6){
        foreach($obj in $MacAddress.Split('-')){
            if($obj.Length -ne 2){
                throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Unable to split into expected pairs")
            }
        }

        return ($MacAddress.ToString().ToUpper())
    }

    if($MacAddress.Length -ne 12){
        throw New-Object System.ArgumentOutOfRangeException("Invalid MAC Address. Length is not equal to 12 ")
    }
    else {
        $MacAddress = $MacAddress.Insert(2,"-").Insert(5,"-").Insert(8,"-").Insert(11,"-").Insert(14,"-").Trim().ToUpper()
        return ($MacAddress.ToString())
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
        [Parameter(Mandatory=$true)]
        [guid]$Provider,

        [Parameter(Mandatory=$false)]
        [string]$Level,

        [Parameter(Mandatory=$false)]
        [string]$Keywords
    )

    try {
        [guid]$guid = [guid]::Empty
        if(!([guid]::TryParse($Provider,[ref]$guid))){
            throw "The value specified in the Provider argument must be in GUID format"
        }
        [string]$formattedString = $null
        foreach($param in $PSBoundParameters.GetEnumerator()){
            if($param.Value){
                if($param.Key -ieq "Provider"){
                    $formattedString += "$($param.Key)='$($param.Value.ToString("B"))' "
                }
                elseif($param.Key -ieq "Level" -or $param.Key -ieq "Keywords") {
                    $formattedString += "$($param.Key)=$($param.Value) "
                }
            }
        }

        return $formattedString.Trim()
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Get-ComputerNameFQDNandNetBIOS {
    <#
    .SYNOPSIS
        Returns back the NetBIOS and FQDN name of the computer
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline)]
        [System.String]$ComputerName
    )

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

    return [PSCustomObject]@{
        ComputerNameNetBIOS = $computerNameNetBIOS
        ComputerNameFQDN    = $computerNameFQDN
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
        $_ | Trace-Exception
        $_ | Write-Error
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
        $functionName = [Management.Automation.Language.Parser]::ParseInput($code, [ref]$null, [ref]$null).EndBlock.Statements.FindAll([Func[Management.Automation.Language.Ast,bool]]{$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]}, $false) `
            | Select-Object -ExpandProperty Name

        if($functionName){
            return ($functionName | Where-Object {$_ -like "$Verb-*"})
        }
        else {
            return $null
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
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
    return [System.String]$Script:SdnDiagnostics_Utilities.Cache.TraceFilePath
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

    # check to see if the working directory has been configured into cache
    # otherwise set the cache based on what we have defined within our configuration file
    if ([String]::IsNullOrEmpty($Script:SdnDiagnostics_Utilities.Cache.WorkingDirectory)) {
        $Script:SdnDiagnostics_Utilities.Cache.WorkingDirectory = $Script:SdnDiagnostics_Utilities.Config.WorkingDirectory
    }

    return [System.String]$Script:SdnDiagnostics_Utilities.Cache.WorkingDirectory
}

function Get-WSManCredSSPState {
    if (Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation') {
        if (Test-Path -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentials') {
            $allowFreshCredentials = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowFreshCredentials' | Select-Object -ExpandProperty 'AllowFreshCredentials'
            if ($allowFreshCredentials -eq 1) {
                return $true
            }
        }
    }

    return $false
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
        [SdnModules]$Role,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.IO.DirectoryInfo]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'GB')]
        [System.Int32]$MinimumGB,

        [Parameter(Mandatory = $true, ParameterSetName = 'MB')]
        [System.Int32]$MinimumMB
    )

    # ensure that the appropriate windows feature is installed and ensure module is imported
    if ($Role) {
        $config = Get-SdnModuleConfiguration -Role $Role.ToString()
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.WindowsFeature
        if (-NOT ($confirmFeatures)) {
            "Required feature is missing: {0}" -f ($config.WindowsFeature -join ', ') | Trace-Output -Level:Error
            return $false
        }

        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if (-NOT ($confirmModules)) {
            "Required module is not loaded: {0}" -f ($config.requiredModules -join ', ')| Trace-Output -Level:Error
            return $false
        }
    }

    # create the directories if does not already exist
    if (-NOT (Test-Path -Path $FilePath.FullName -PathType Container)) {
        "Creating {0}" -f $FilePath.FullName | Trace-Output -Level:Verbose
        $null = New-Item -Path $FilePath.FullName -ItemType Directory -Force
    }

    # confirm sufficient disk space
    switch ($PSCmdlet.ParameterSetName) {
        'GB' {
            $diskSpace = Confirm-DiskSpace -FilePath $FilePath.FullName -MinimumGB $MinimumGB
        }
        'MB' {
            $diskSpace = Confirm-DiskSpace -FilePath $FilePath.FullName -MinimumMB $MinimumMB
        }
    }

    if (-NOT ($diskSpace)) {
        "Insufficient disk space detected." | Trace-Output -Level:Error
        return $false
    }

    return $true
}

function Invoke-PSRemoteCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [bool]$ImportModuleOnRemoteSession,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Object[]]$ArgumentList = $null,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [System.String]$Activity,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$ExecutionTimeout = 600
    )

    $params = @{
        ScriptBlock = $ScriptBlock
    }

    $psSessionParams = @{
        ComputerName = $ComputerName
        Credential = $Credential
    }

    if ($PSBoundParameters.ContainsKey('ImportModuleOnRemoteSession')) {
        $psSessionParams.Add('ImportModuleOnRemoteSession', $ImportModuleOnRemoteSession)
    }

    $session = New-PSRemotingSession @psSessionParams
    if ($session) {
        $params.Add('Session', $session)
        "ComputerName: {0}, ScriptBlock: {1}" -f ($session.ComputerName -join ', '), $ScriptBlock.ToString() | Trace-Output -Level:Verbose
        if ($ArgumentList) {
            $params.Add('ArgumentList', $ArgumentList)
            "ArgumentList: {0}" -f ($ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
        }

        if ($AsJob) {
            $params += @{
                AsJob = $true
                JobName = "SdnDiag-{0}" -f $(Get-Random)
            }

            $result = Invoke-Command @params
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
            return (Invoke-Command @params)
        }
    }
}

function Invoke-RestMethodWithRetry {

    [CmdletBinding(DefaultParameterSetName = 'Credential')]
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
        [System.Object]$Body,

        [Parameter(Mandatory = $false)]
        [Switch] $DisableKeepAlive,

        [Parameter(Mandatory = $false)]
        [Switch] $UseBasicParsing,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [X509Certificate]$Certificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSec = 600,

        [Parameter(Mandatory = $false)]
        [Switch]$Retry,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRetry = 3,

        [Parameter(Mandatory = $false)]
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

    if ($DisableKeepAlive) {
        $params.Add('DisableKeepAlive', $true)
    }

    if ($UseBasicParsing) {
        $params.Add('UseBasicParsing', $true)
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Certificate' {
            $params.Add('Certificate', $Certificate)
        }
        'Credential' {
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
                $params.Add('Credential', $Credential)
            }
            else {
                $params.Add('UseDefaultCredentials', $true)
            }
        }
    }

    $counter = 0
    while ($true) {
        $counter++

        try {
            "Performing {0} request to uri {1}" -f $Method, $Uri | Trace-Output -Level:Verbose
            if ($Body) {
                if ($Body -is [Hashtable]) {
                    "Body:`n`t{0}" -f ($Body | ConvertTo-Json -Depth 10) | Trace-Output -Level:Verbose
                }
                else {
                    "Body:`n`t{0}" -f ($Body) | Trace-Output -Level:Verbose
                }
            }

            $result = Invoke-RestMethod @params

            break
        }
        catch {
            if (($counter -le $MaxRetry) -and $Retry) {
                "Retrying operation in {0} seconds. Retry count: {1}." - $RetryIntervalInSeconds, $counter | Trace-Output
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
            else {
                $_ | Trace-Exception
                throw $_
            }
        }
    }

    return $result
}

function Invoke-WebRequestWithRetry {

    [CmdletBinding(DefaultParameterSetName = 'Credential')]
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

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [X509Certificate]$Certificate,

        [Parameter(Mandatory = $false, ParameterSetName = 'Credential')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutInSec = 600,

        [Parameter(Mandatory = $false)]
        [Switch]$Retry,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRetry = 3,

        [Parameter(Mandatory = $false)]
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

    if ($DisableKeepAlive) {
        $params.Add('DisableKeepAlive', $true)
    }

    if ($UseBasicParsing) {
        $params.Add('UseBasicParsing', $true)
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Certificate' {
            $params.Add('Certificate', $Certificate)
        }
        'Credential' {
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
                $params.Add('Credential', $Credential)
            }
            else {
                $params.Add('UseDefaultCredentials', $true)
            }
        }
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
            if (($counter -le $MaxRetry) -and $Retry) {
                "Retrying operation in {0} seconds. Retry count: {1}." - $RetryIntervalInSeconds, $counter | Trace-Output
                Start-Sleep -Seconds $RetryIntervalInSeconds
            }
            else {
                $_ | Trace-Exception
                throw $_
            }
        }
    }

    "StatusCode: {0} StatusDescription: {1}" -f $result.StatusCode, $result.StatusDescription | Trace-Output -Level:Verbose
    return $result
}

function New-PSRemotingSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool]$ImportModuleOnRemoteSession = $Global:SdnDiagnostics.Config.ImportModuleOnRemoteSession,

        [Parameter(Mandatory = $false)]
        [System.String]$ModuleName = $Global:SdnDiagnostics.Config.ModuleName,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    begin {
        $importRemoteModule = {
            param([string]$arg0, $arg1)
            try {
                Import-Module $arg0 -ErrorAction Stop
                $Global:SdnDiagnostics.Config = $arg1
            }
            catch {
                throw $_
            }
        }

        $confirmRemoteModuleImported = {
            param([string]$arg0)
            $moduleExists = Get-Module -Name $arg0 -ListAvailable -ErrorAction Ignore
            if ($moduleExists) {
                return $true
            }

            return $false
        }

        $remoteSessions = @()

        # return a list of current sessions on the computer
        # return only the sessions that are opened and available as this will allow new sessions to be opened
        # without having to wait for existing sessions to move from Busy -> Available
        $currentActiveSessions = Get-PSSession -Name "SdnDiag-*" | Where-Object { $_.State -ieq 'Opened' -and $_.Availability -ieq 'Available' }
    }
    process {
        $ComputerName | ForEach-Object {
            $objectName = $PSItem

            # check to see if session is already opened
            if ($currentActiveSessions.ComputerName -contains $objectName -and !$Force) {
                $session = ($currentActiveSessions | Where-Object { $_.ComputerName -eq $objectName })[0]
                "Located existing powershell session {0} for {1}" -f $session.Name, $objectName | Trace-Output -Level:Verbose

                # if we have to import the module on the remote session, we need to check if the module is already imported
                # if not, we will import the module on the remote session
                if ($ImportModuleOnRemoteSession) {
                    $moduleImported = Invoke-Command -Session $session -ScriptBlock $confirmRemoteModuleImported -ArgumentList @($ModuleName) -ErrorAction Stop
                    if (-NOT $moduleImported) {
                        "Importing module {0} on remote session {1}" -f $ModuleName, $session.Name | Trace-Output -Level:Verbose
                        Invoke-Command -Session $session -ScriptBlock $importRemoteModule -ArgumentList @($ModuleName, $Global:SdnDiagnostics.Config) -ErrorAction Stop
                    }
                }

                # add the session to the array and skip further processing
                $remoteSessions += $session
                return # stop processing
            }

            # determine if an IP address was passed for the destination
            # if using IP address it needs to be added to the trusted hosts
            $isIpAddress = ($objectName -as [IPAddress]) -as [Bool]
            if ($isIpAddress) {
                try {
                    Confirm-IsAdmin

                    "{0} is an ip address" -f $objectName | Trace-Output -Level:Verbose
                    $trustedHosts = Get-Item -Path "WSMan:\localhost\client\TrustedHosts"
                    if ($trustedHosts.Value -notlike "*$objectName*" -and $trustedHosts.Value -ne "*") {
                        "Adding {0} to {1}" -f $objectName, $trustedHosts.PSPath | Trace-Output
                        Set-Item -Path "WSMan:\localhost\client\TrustedHosts" -Value $objectName -Concatenate
                    }
                }
                catch {
                    $_ | Trace-Output -Level:Error
                    return # stop processing
                }
            }

            try {
                if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                    "PSRemotingSession use user-defined credential" | Trace-Output -Level:Verbose
                    $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $objectName -Credential $Credential -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US -IdleTimeout 86400000) -ErrorAction Stop
                }
                else {
                    # if the credential is not defined, we want to check if we
                    if ($PSSenderInfo -and !(Get-WSManCredSSPState)) {
                        throw New-Object System.NotSupportedException("Unable to create PSSession to $objectName. This operation is not supported in a remote session without supplying -Credential.")
                    }

                    # if we need to create a new remote session, need to check to ensure that if using an IP Address that credentials are specified
                    # which is a requirement from a WinRM perspective. Will throw a warning and skip session creation for this computer.
                    if ($isIpAddress -and $Credential -eq [System.Management.Automation.PSCredential]::Empty) {
                        throw New-Object System.NotSupportedException("Unable to create PSSession to $objectName. The Credential parameter is required when using an IP Address.")
                    }

                    "PSRemotingSession use default credential" | Trace-Output -Level:Verbose
                    $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $objectName -SessionOption (New-PSSessionOption -Culture 'en-US' -UICulture 'en-US' -IdleTimeout 86400000) -ErrorAction Stop
                }

                "Created powershell session {0} to {1}" -f $session.Name, $objectName | Trace-Output -Level:Verbose
                if ($ImportModuleOnRemoteSession) {
                    "Importing module {0} on remote session {1}" -f $ModuleName, $session.Name | Trace-Output -Level:Verbose
                    Invoke-Command -Session $session -ScriptBlock $importRemoteModule -ArgumentList @($ModuleName, $Global:SdnDiagnostics.Config) -ErrorAction Stop
                }

                # add the session to the array
                $remoteSessions += $session
            }
            catch {
                "Unable to create powershell session to {0}`n`t{1}" -f $objectName, $_.Exception.Message | Trace-Output -Level:Error
                return # stop processing
            }
        }
    }
    end {
        return ($remoteSessions | Sort-Object -Unique)
    }
}

function New-TraceOutputFile {

    try {
        # make sure that directory path exists, else create the folder structure required
        $workingDir = Get-WorkingDirectory
        if (-NOT (Test-Path -Path $workingDir -PathType Container)) {
            $null = New-Item -Path $workingDir -ItemType Directory -Force
        }

        # build the trace file path and set global variable
        [System.String]$fileName = "SdnDiagnostics_TraceOutput_{0}.csv" -f (Get-Date).ToString('yyyyMMdd')
        [System.IO.FileInfo]$filePath = Join-Path -Path $workingDir -ChildPath $fileName
        Set-TraceOutputFile -Path $filePath.FullName

        # configure the cache to not cleanup the trace file
        $SdnDiagnostics_Utilities.Cache.FilesExcludedFromCleanup += $filePath.Name
        "TraceFile: {0}" -f $filePath.FullName | Trace-Output -Level:Verbose
    }
    catch {
        $_.Exception | Write-Error
    }
}

function New-WorkingDirectory {
    [CmdletBinding()]
    param ()

    try {
        [System.String]$path = (Get-WorkingDirectory)

        if(-NOT (Test-Path -Path $path -PathType Container)){
            $null = New-Item -Path $path -ItemType Directory -Force
        }

        # create the trace file
        New-TraceOutputFile
    }
    catch {
        $_.Exception | Write-Error
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
        [Parameter(Mandatory = $false)]
        [System.String[]]$ComputerName
    )

    try {
        [int]$timeOut = 120
        $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object { $_.ComputerName -iin $ComputerName }
        }
        else {
            $sessions = Get-PSSession -Name "SdnDiag-*"
        }

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
                    "Removing PSSession {0} for {1}" -f $session.Name, $session.ComputerName | Trace-Output -Level:Verbose

                    try {
                        $session | Remove-PSSession -ErrorAction Stop
                    }
                    catch {
                        "Unable to remove PSSession {0} for {1}. Error: {2}" -f $session.Name, $session.ComputerName, $_.Exception.Message | Trace-Output -Level:Warning
                        continue
                    }
                }
            }

            if ($PSBoundParameters.ContainsKey('ComputerName')) {
                $sessions = Get-PSSession -Name "SdnDiag-*" | Where-Object { $_.ComputerName -iin $ComputerName }
            }
            else {
                $sessions = Get-PSSession -Name "SdnDiag-*"
            }
        }

        $stopWatch.Stop()
    }
    catch {
        $stopWatch.Stop()
        $_ | Trace-Exception
    }
}

function Remove-SdnDiagnosticJob {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String[]]$State = @("Completed","Failed"),

        [Parameter(Mandatory = $false)]
        [System.String]$Name
    )

    if (-NOT ([string]::IsNullOrEmpty($Name))) {
        $filteredJobs = Get-Job -Name $Name
    }
    else {
        $filteredJobs = Get-Job -Name "SdnDiag-*" | Where-Object {$_.State -iin $State}
    }

    if ($filteredJobs ) {
        $filteredJobs | Remove-Job -Force -ErrorAction SilentlyContinue
    }
}

function Set-TraceOutputFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Path
    )

    $Script:SdnDiagnostics_Utilities.Cache.TraceFilePath = $Path
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
        if($isIpAddress){
            $ipAddresses = Get-NetIPAddress
            foreach($ip in $ipAddresses){
                if([IPAddress]$ip.IpAddress -eq [IPAddress]$ComputerName){
                    return $true
                }
            }
        }

        # check to determine if the ComputerName matches the NetBIOS name of the computer
        if($env:COMPUTERNAME -ieq $ComputerName){
            return $true
        }

        # check to determine if ComputerName matches the FQDN name of the computer
        if(([System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName) -ieq $ComputerName){
            return $true
        }

        return $false
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
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
        [int]$CompartmentId = (Get-NetCompartment | Where-Object {$_.CompartmentDescription -ieq 'Default Compartment'}).CompartmentId,

        [Parameter()]
        [int[]]$BufferSize = 1472,

        [Parameter(Mandatory = $false)]
        [switch]$DontFragment
    )

    try {
        $arrayList = [System.Collections.ArrayList]::new()

        foreach($size in $BufferSize){
            $Global:LASTEXITCODE = 0
            if($DontFragment){
                $ping = ping $DestinationAddress.IPAddressToString -c $CompartmentId -l $size -S $SourceAddress.IPAddressToString -n 2-f
            }
            else {
                $ping = ping $DestinationAddress.IPAddressToString -c $CompartmentId -l $size -S $SourceAddress.IPAddressToString -n 2
            }

            if($LASTEXITCODE -ieq 0){
                $status = 'Success'
            }
            else {
                $status = 'Failure'
            }

            $result = [PSCustomObject]@{
                SourceAddress = $SourceAddress.IPAddressToString
                DestinationAddress = $DestinationAddress.IPAddressToString
                CompartmentId = $CompartmentId
                BufferSize = $size
                Status = $status
                Result = $ping
            }

            [void]$arrayList.Add($result)
        }

        return $arrayList
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

function Trace-Exception {
    <#
    .SYNOPSIS
        Extracts information out of exceptions to write to the log file.
        Pipe exceptions to this command in a catch block.

    .PARAMETER Exception
        Any exception inherited from [System.Exception]

    .EXAMPLE
        try
        {
            1 / 0 #divide by 0 exception
        }
        catch
        {
            $_ | Trace-Exception
        }
    #>
    param(
        [parameter(Mandatory = $True, ValueFromPipeline = $true)]
        $Exception
    )

    Trace-Output -Exception $Exception -FunctionName (Get-PSCallStack)[1].Command -Level 'Exception'
}

function Trace-Output {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Message')]
        [System.String]$Message,

        [Parameter(Mandatory = $false, ParameterSetName = 'Message')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Exception')]
        [TraceLevel]$Level = 'Information',

        [Parameter(Mandatory = $false, ParameterSetName = 'Message')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Exception')]
        [System.String]$FunctionName = (Get-PSCallStack)[0].Command,

        [parameter(Mandatory = $true, ParameterSetName = 'Exception')]
        $Exception
    )

    begin {
        $traceFile = (Get-TraceOutputFile)
        if ([string]::IsNullOrEmpty($traceFile)) {
            New-WorkingDirectory

            $traceFile = (Get-TraceOutputFile)
        }
    }
    process {
        # create custom object for formatting purposes
        $traceEvent = [PSCustomObject]@{
            Computer = $env:COMPUTERNAME.ToUpper().ToString()
            TimestampUtc = [DateTime]::UtcNow.ToString('yyyy-MM-dd HH-mm-ss')
            FunctionName = $FunctionName
            Level = $Level.ToString()
            Message = $null
        }

        switch ($PSCmdlet.ParameterSetName) {
            'Message' {
                $traceEvent.Message = $Message
            }
            'Exception' {
                if ($Exception -is [System.Management.Automation.ErrorRecord]) {
                    $traceEvent.Message = "{0}`n{1}" -f $Exception.Exception, $Exception.ScriptStackTrace
                }
                # this is for when we capture a terminating exception generated by throw, in which
                # it will not include the ScriptStackTrace or Exception details like the ErrorRecord
                else {
                    $traceEvent.Message = $Exception.ToString()
                }
            }
        }

        $formattedMessage = "[{0}] {1}" -f $traceEvent.Computer, $traceEvent.Message

        # write the message to the console
        switch($Level){
            'Error' {
                $formattedMessage | Write-Host -ForegroundColor:Red
            }

            'Exception' {
                # do nothing here, as the exception should be written to the console by the caller using Write-Error
                # as this will preserve the proper call stack tracing
            }

            'Success' {
                $formattedMessage  | Write-Host -ForegroundColor:Green
            }

            'Verbose' {
                if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                    $formattedMessage | Write-Verbose
                }
            }

            'Warning' {
                $formattedMessage | Write-Warning
            }

            default {
                $formattedMessage | Write-Host -ForegroundColor:Cyan
            }
        }

        # write the event to trace file to be used for debugging purposes
        $mutexInstance = Wait-OnMutex -MutexId 'SDN_TraceLogging' -ErrorAction Continue
        if ($mutexInstance) {
            $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile
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
                $stopWatch.Stop()

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
        $_ | Trace-Exception
        $_ | Write-Error
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
            foreach ($allowedFolderPath in $Script:SdnDiagnostics_Utilities.Config.FolderPathsAllowedForCleanup) {
                if ($obj -ilike $allowedFolderPath) {
                    $filteredPaths += $obj
                }
            }
        }

        if ($filteredPaths) {
            "Cleaning up: {0}" -f ($filteredPaths -join ', ') | Trace-Output -Level:Verbose
            Remove-Item -Path $filteredPaths -Exclude $Script:SdnDiagnostics_Utilities.Cache.FilesExcludedFromCleanup -Force:$Force -Recurse:$Recurse -ErrorAction Continue
        }
    }

    $params = @{
        Path = $Path
        Recurse = $Recurse.IsPresent
        Force = $Force.IsPresent
    }

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param([Parameter(Position = 1)]$Path, [Parameter(Position = 2)]$Recurse, [Parameter(Position = 3)]$Force)
                Clear-SdnWorkingDirectory -Path $Path -Recurse:$Recurse -Force:$Force
            } -ArgumentList @($params.Path, $params.Recurse, $params.Force)
        }
        else {
            Clear-WorkingDirectory @params
        }
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

    function Copy-SdnFileFromComputer {

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

    Copy-FileFromRemoteComputer @PSBoundParameters
}

function Copy-SdnFileToComputer {
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

    Copy-FileToRemoteComputer @PSBoundParameters
}

function Get-SdnModuleConfiguration {
    <#
    .SYNOPSIS
        Returns the configuration data related to the sub modules within SdnDiagnostics.
    .PARAMETER Role
        The SDN role that you want to return configuration data for.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnModules]$Role
    )

    if ($Role.ToString().Contains('_')) {
        [string]$Role = $Role -replace '_', '.'
    }

    $path = "SdnDiag.{0}.Config.psd1" -f $Role
    $moduleConfig = Get-Item -Path (Join-Path -Path $PSScriptRoot -ChildPath $path) -ErrorAction SilentlyContinue
    if ($moduleConfig) {
        $moduleConfigData = Import-PowerShellDataFile -Path $moduleConfig.FullName
    }

    return $moduleConfigData
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
    .PARAMETER Path
        Specifies the path to the module where it should be installed. If not specified, the default path will be used.
    .PARAMETER Force
        Forces a cleanup and re-install of the module on the remote computer.
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
        [System.String]$Path = $Script:SdnDiagnostics_Utilities.Config.DefaultModuleDirectory,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    begin {
        $moduleName = $Global:SdnDiagnostics.Config.ModuleName

        # if we have multiple modules installed on the current workstation,
        # abort the operation because side by side modules can cause some interop issues to the remote nodes
        $localModule = Get-Module -Name 'SdnDiagnostics'
        if ($localModule.Count -gt 1) {
            throw "Detected more than one module version of SdnDiagnostics. Remove all versions of module from runspace and re-import the module."
        }

        $getModuleVersionSB = {
            param ([string]$arg0)
            try {
                # Get the latest version of SdnDiagnostics Module installed
                $version = (Get-Module -Name $arg0 -ListAvailable -ErrorAction Ignore | Sort-Object Version -Descending)[0].Version.ToString()
            }
            catch {
                # in some instances, the module will not be available and as such we want to skip the noise and return
                # a string back to the remote call command which we can do proper comparison against
                $version = '0.0.0.0'
            }
            return $version
        }

        # typically PowerShell modules will be installed in the following directory configuration:
        #    $env:ProgramFiles\WindowsPowerShell\Modules\SdnDiagnostics\{version}
        #    $env:USERPROFILE\Documents\WindowsPowerShell\Modules\SdnDiagnostics\{version}
        # so we default to Leaf of the path being SdnDiagnostics as PSGet will handle the versioning so we only ever do import in the following format:
        #    Import-Module SdnDiagnostics (if using default PowerShell module path)
        #    Import-Module C:\{path}\SdnDiagnostics (if using custom PowerShell module path)
        # so we need to ensure that we are copying the module to the correct path on the remote computer
        [System.String]$destinationPathDir = Join-Path $Path -ChildPath $localModule.Version.ToString()
    }
    process {
        $ComputerName | ForEach-Object {
            $computer = $_

            # if we have configured automatic seeding of module to remote nodes, we will want to skip this operation
            if ($Global:SdnDiagnostics.Config.DisableModuleSeeding) {
                "Automatic seeding of module to remote nodes is disabled. Skipping update operation for {0}." -f $computer | Trace-Output -Level:Verbose
                return
            }

            try {
                # check to see if the computer is local, if so, we will skip the operation
                if (Test-ComputerNameIsLocal -ComputerName $computer) {
                    "Detected that {0} is local machine. Skipping update operation for {0}." -f $computer | Trace-Output -Level:Verbose
                    return
                }

                if (!$Force) {
                    "Getting current installed version of SdnDiagnostics on {0}" -f $computer | Trace-Output -Level:Verbose

                    # use Invoke-Command here, as we do not want to create a cached session for the remote computers
                    # as it will impact scenarios where we need to import the module on the remote computer for remote sessions
                    try {
                        $remoteModuleVersion = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock $getModuleVersionSB -ArgumentList @($moduleName) -ErrorAction Stop
                    }
                    catch {
                        # if we are unable to connect to the remote computer, we will skip the operation
                        $_ | Trace-Exception
                        "Unable to connect to {0}. Skipping update operation for {0}." -f $computer | Trace-Output -Level:Verbose
                        return
                    }

                    if ($remoteModuleVersion) {
                        # if the remote module version is greater or equal to the local module version, then we do not need to update
                        "{0} is currently using version: {1}" -f $computer, $remoteModuleVersion | Trace-Output -Level:Verbose
                        if ([version]$remoteModuleVersion -ge [version]$localModule.Version) {
                            "No update is required for {0}" -f $computer | Trace-Output -Level:Verbose
                            return
                        }
                    }
                }

                "SdnDiagnostics {0} will be installed to {1}" -f $localModule.Version.ToString(), $computer | Trace-Output
                Copy-FileToRemoteComputer -Path $localModule.ModuleBase -ComputerName $computer -Destination $destinationPathDir -Credential $Credential -Recurse -Force

                # ensure that we destroy the current pssessions for the computer to prevent any caching issues
                # we will want to remove any existing PSSessions for the remote computers
                Remove-PSRemotingSession -ComputerName $computer
            }
            catch {
                $_ | Trace-Exception
                $_ | Write-Error
            }
        }
    }
    end {
        # do nothing here
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
        $_ | Trace-Exception
        $_ | Write-Error
    }
}

