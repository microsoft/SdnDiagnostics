function Trace-Output {
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String]$Message,

        [Parameter(Mandatory = $false)]
        [TraceLevel]$Level
    )

    if(!$PSBoundParameters.ContainsKey('Level')) {
        $Level = [TraceLevel]::Information
    }  

    # Verify we've made the working directory and trace file
    if([string]::IsNullOrEmpty((Get-TraceOutputFile))){
        $workingDir = Get-WorkingDirectory

        if($null -eq $workingDir){
            New-WorkingDirectory
        }
    }

    $traceFile = (Get-TraceOutputFile)
    $callingFunction = (Get-PSCallStack)[1].Command

    # create custom object for formatting purposes
    $traceEvent = [PSCustomObject]@{
        TimestampUtc = [DateTime]::UtcNow.ToString()
        FunctionName = $callingFunction
        Level = $Level.ToString()
        Message = $Message
    }

    # write the message to the console
    switch($Level){
        'Error' {
            $traceEvent.Message | Write-Host -ForegroundColor:Red
        }

        'Success' {
            $traceEvent.Message | Write-Host -ForegroundColor:Green
        }

        'Verbose' {
            if($VerbosePreference -ne [System.Management.Automation.ActionPreference]::SilentlyContinue) {
                $traceEvent.Message | Write-Verbose
            }
        }

        'Warning' {
            $traceEvent.Message | Write-Host -ForegroundColor:Yellow
        }
        
        default {
            $traceEvent.Message | Write-Host -ForegroundColor:Cyan
        }
    }

    # write the event to trace file to be used for debugging purposes
    $traceEvent | Export-Csv -Append -NoTypeInformation -Path $traceFile.FullName
}

function New-WorkingDirectory {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Path = (Get-Content -Path "$PSScriptRoot\..\..\config\app\settings.json" | ConvertFrom-Json).workingDirectory
    )

    try {

        # create the working directory and set the global cache
        if(!(Test-Path -Path $Path -PathType Container)){
            $null = New-Item -Path $Path -ItemType Directory -Force
        }

        $global:SdnDiagnostics.WorkingDirectory = $Path.FullName

        # create the trace file
        New-TraceOutputFile
    }
    catch {
        $_.Exception | Write-Error
    }
}

function Get-WorkingDirectory {
    return [System.IO.FileInfo]$global:SdnDiagnostics.WorkingDirectory
}

function Get-TraceOutputFile {
    return [System.IO.FileInfo]$global:SdnDiagnostics.TraceFilePath
}

function Set-TraceOutputFile {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Path
    )

    $global:SdnDiagnostics.TraceFilePath = $Path.FullName
}

function New-TraceOutputFile {

    try {
        # make sure that directory path exists, else create the folder structure required
        [System.IO.FileInfo]$workingDir = Get-WorkingDirectory
        if(!(Test-Path -Path $workingDir.FullName -PathType Container)){
            $workingDir = New-Item -Path $workingDir.FullName -ItemType Directory -Force
        }

        # build the trace file path and set global variable
        [System.String]$fileName = "SdnDiagnostics_TraceOutput_{0}.csv" -f (Get-Date).ToString('yyyyMMdd')
        [System.IO.FileInfo]$filePath = Join-Path -Path $workingDir.FullName -ChildPath $fileName
        Set-TraceOutputFile -Path $filePath.FullName

        "TraceFile: {0}" -f $filePath.FullName | Trace-Output -Level:Verbose
    }
    catch {
        $_.Exception | Write-Error
    }
}

function Confirm-UserInput {
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [System.String]$Message = "Do you want to continue with this operation? (y/n)",
        [System.String]$BackgroundColor = "Black",
        [System.String]$ForegroundColor = "Yellow"
    )

    $Message | Trace-Output -Level:Verbose
    Write-Host -ForegroundColor:$ForegroundColor -BackgroundColor:$BackgroundColor -NoNewline $Message  
    $answer = Read-Host

    return ($answer -ieq 'y')
}

function New-PSRemotingSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {

        if((Get-Service -Name WinRM).Status -ine 'Running'){
            $service = Start-Service -Name WinRM -PassThru
            if($service.Status -ine 'Running'){
                $msg = "Unable to start WinRM service`n`t{0}" -f $_
                throw New-Object System.Exception($msg)
            }
        }

        $remoteSessions = [System.Collections.ArrayList]::new()

        # return a list of current sessions on the computer
        # return only the sessions that are opened and available as this will allow new sessions to be opened
        # without having to wait for existing sessions to move from Busy -> Available
        $currentActiveSessions = Get-PSSession | Where-Object {$_.State -ieq 'Opened' -and $_.Availability -ieq 'Available'}

        $remoteSessions = [System.Collections.ArrayList]::new()
        foreach($obj in $ComputerName){

            $session = $null

            # determine if an IP address was passed for the destination
            # if using IP address it needs to be added to the trusted hosts
            $isIpAddress = ($obj -as [IPAddress]) -as [Bool]
            if($isIpAddress){
                $trustedHosts = Get-Item -Path "WSMan:\localhost\client\TrustedHosts"
                if($trustedHosts.Value -notlike "*$obj*" -and $trustedHosts.Value -ne "*") {
                    "Adding {0} to {1}" -f $obj, $trustedHosts.PSPath | Trace-Output
                    Set-Item -Path "WSMan:\localhost\client\TrustedHosts" -Value $obj -Concatenate
                }
            }

            # check to see if session is already opened
            # if no session already exists or Force is defined, then create a new remote session
            if($currentActiveSessions.ComputerName -contains $obj -and !$Force){
                $session = ($currentActiveSessions | Where-Object {$_.ComputerName -eq $obj})[0]
                "Located existing powershell session {0}" -f $session.Name | Trace-Output -Level:Verbose
            }
            else {
                try {
                    if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
                        "PSRemotingSession use provided credential {0}" -f $Credential.UserName | Trace-Output -Level:Verbose
                        $session = New-PSSession -ComputerName $obj -Credential $Credential -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US) -ErrorAction Stop
                    }
                    else {
                        "PSRemotingSession use default credential" | Trace-Output -Level:Verbose
                        $session = New-PSSession -ComputerName $obj -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US) -ErrorAction Stop
                    }

                    "Created powershell session {0} to {1}" -f $session.Name, $obj | Trace-Output -Level:Verbose
                }
                catch {
                    "Unable to create powershell session to {0}`n`t{1}" -f $obj, $_.Exception | Trace-Output -Level:Warning
                    continue
                }
            }

            # add the session to the array
            if($session){
                [void]$remoteSessions.Add($session)
            }
        }

        return $remoteSessions

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Invoke-PSRemoteCommand {
    <#
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
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$ExecutionTimeout = 600
    )

    try {
        $session = New-PSRemotingSession -ComputerName $ComputerName -Credential $Credential
        if($session){
            "ComputerName: {0}, ScriptBlock: {1}" -f ($session.ComputerName -join ', '), $ScriptBlock.ToString() | Trace-Output -Level:Verbose
            
            if($AsJob){
                $result = Invoke-Command -Session $session -HideComputerName -ScriptBlock $ScriptBlock -AsJob -JobName $([guid]::NewGuid().Guid)
                if($PassThru){
                    $result = Wait-PSRemoteJob -Name $result.Name -ExecutionTimeOut $ExecutionTimeout
                }
            }
            else {
                $result = Invoke-Command -Session $session -HideComputerName -ScriptBlock $ScriptBlock
            }


            return $result
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Wait-PSRemoteJob {
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

        [Parameter(Mandatory= $false)]
        [System.String]$Activity = (Get-PSCallStack)[1].Command,

        [Parameter(Mandatory = $false)]
        [int]$ExecutionTimeOut = 600,

        [Parameter(Mandatory = $false)]
        [int]$PollingInterval = 1
    )

    try {
        $stopWatch =  [System.Diagnostics.Stopwatch]::StartNew()
        "JobName: {0} PollingInterval: {1} seconds ExecutionTimeout: {2} seconds" -f $Name, $PollingInterval, $ExecutionTimeOut | Trace-Output -Level:Verbose

        # Loop while there are running jobs
        while((Get-Job -Name $Name).State -ieq 'Running'){

            # get the job details and write progress
            $job = Get-Job -Name $Name
            $runningChildJobs = $job.ChildJobs | Where-Object {$_.State -ieq 'Running'}
            $jobCount = $job.ChildJobs.Count
            $runningJobCount = $runningChildJobs.Count
            $percent = [math]::Round((($jobcount-$runningJobCount)/$jobCount * 100),2)

            $status = "Progress: {0}%. Waiting for {1}" -f $percent, ($runningChildJobs.Location -join ', ')
            Write-Progress -Activity $Activity -Status $status -PercentComplete $percent -Id $job.Id

            # check the stopwatch and break out of loop if we hit execution timeout limit
            if($stopWatch.Elapsed.TotalSeconds -ge $ExecutionTimeOut){
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
        if($job.State -ne "Completed"){
            "JobName: {0} Operation {1}. Total Elapsed Time: {2}" -f $Name, $job.State, $stopwatch.Elapsed.TotalSeconds | Trace-Output -Level:Warning
            
            # Identify all failed child jobs and present to the operator
            $failedChildJobs = $job.ChildJobs | Where-Object {$_.State -ine 'Completed'}
            foreach ($failedChildJob in $failedChildJobs){
                "JobName {0}: Job for {1} failed with State: {2} | Status: {3}" -f $Name, $failedChildJob.Location, $failedChildJob.State, $failedChildJob.StatusMessage | Trace-Output -Level:Warning
            }

            "JobName {0}: State: {1} StatusMessage: {2}" -f $Name, $job.State, $job.StatusMessage | Trace-Output -Level:Error
        }
        else {
            "JobName: {0} Operation {1}. Total Elapsed Time: {2}" -f $Name, $job.State, $stopwatch.Elapsed.TotalSeconds | Trace-Output -Level:Verbose
        }

        return (Get-Job -Name $Name | Receive-Job) 
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Get-FormattedDateTimeUTC {
    return ((Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss'))
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

function Export-ObjectToFile {
    <#
    .SYNOPSIS
        Save an object to a file in a consistent format.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
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
        [System.String]$Format
    )

    begin {
        $arrayList = [System.Collections.ArrayList]::new()
    }
    process {
        foreach ($obj in $Object) {
            [void]$arrayList.add($obj)
        }
    }
    end {
        try {
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
                "Creating directory {0}" -f $fileName.Directory | Trace-Output -Level:Verbose
                $null = New-Item -Path $fileName.Directory -ItemType Directory
            }

            "Creating file {0}" -f $fileName | Trace-Output -Level:Verbose
            switch($FileType){
                "json" {
                    $arrayList | ConvertTo-Json -Depth 10 | Out-File -FilePath $fileName
                }
                "csv" {
                    $arrayList | Export-Csv -NoTypeInformation -Path $fileName
                }
                "txt" {
                    switch($Format){
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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Copy-FileFromPSRemoteSession {
    <#
    .SYNOPSIS
        Copies an item from one location to another using FromSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. To specify the local computer, type the computer name, localhost, or a dot (.). When the computer is in a different domain than the user, the fully qualified domain name is required.
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
        foreach($object in $ComputerName){
            if(Test-ComputerNameIsLocal -ComputerName $object){
                "Detected that {0} is local machine. Skipping" -f $object | Trace-Output -Level:Warning
                continue
            }

            $session = New-PSRemotingSession -ComputerName $object -Credential $Credential
            if($session){

                [System.IO.FileInfo]$outputDirectory = Join-Path -Path $Destination.FullName -ChildPath $object
                if(!(Test-Path -Path $outputDirectory.FullName -PathType Container)){
                    $null = New-Item -Path $outputDirectory.FullName -ItemType Directory -Force
                }
   
                "Copying files from {0} to {1} using {2}" -f $session.ComputerName, $outputDirectory.FullName, $session.Name | Trace-Output
                Copy-Item -Path $Path -Destination $outputDirectory.FullName -FromSession $session -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
            }
            else {
                "Unable to copy files from {0} as no remote session could be established" -f $object | Trace-Output -Level:Warning
                continue
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Copy-FileToPSRemoteSession {
    <#
    .SYNOPSIS
        Copies an item from one location to another using ToSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers. To specify the local computer, type the computer name, localhost, or a dot (.). When the computer is in a different domain than the user, the fully qualified domain name is required.
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
        foreach($object in $ComputerName){
            if(Test-ComputerNameIsLocal -ComputerName $object){
                "Detected that {0} is local machine. Skipping copy operation." -f $object | Trace-Output -Level:Warning
                continue
            }

            $session = New-PSRemotingSession -ComputerName $object -Credential $Credential
            if($session){
                "Copying files to {0} on {1} using {2}" -f $Destination.FullName, $session.ComputerName, $session.Name | Trace-Output
                Copy-Item -Path $Path -Destination $Destination.FullName -ToSession $session -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
            }
            else {
                "Unable to copy files to {0} as no remote session could be established" -f $object | Trace-Output -Level:Warning
                continue
            }
        }
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
        $stopWatch =  [System.Diagnostics.Stopwatch]::StartNew()

        $sessions = Get-PSSession -ComputerName $ComputerName
        while($sessions){
            if($stopWatch.Elapsed.TotalSeconds -gt $timeOut){
                throw New-Object System.TimeoutException("Unable to drain PSSessions")
            }

            foreach($session in $sessions){
                if($session.Availability -ieq 'Busy'){
                    "{0} is currently {1}. Waiting for PSSession.. {2} seconds" -f $session.Name, $session.Availability, $stopWatch.Elapsed.TotalSeconds | Trace-Output
                    Start-Sleep -Seconds 5
                    continue
                }
                else {
                    "Removing PSSession {0}" -f $session.Name | Trace-Output -Level:Verbose
                    $session | Remove-PSSession -ErrorAction Continue
                }
            }

            $sessions = Get-PSSession -ComputerName $ComputerName
        }

        $stopWatch.Stop()
        "Successfully drained PSSessions for {0}" -f ($ComputerName -join ', ') | Trace-Output
    }
    catch {
        $stopWatch.Stop()
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}