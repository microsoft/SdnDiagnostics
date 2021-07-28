function Enable-GatewayTracing {
    <#
    .SYNOPSIS
        Enables netsh tracing for the RAS components. Files will be saved to C:\Windows\Tracing by default
    #>

    try {
        # ensure that the appropriate windows feature is installed and ensure module is imported
        $config = Get-SdnRoleConfiguration -Role:Gateway
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }

        # remove any previous or stale logs
        $files = Get-ChildItem -Path $config.properties.commonPaths.rasGatewayTraces -Include '*.log','*.etl'
        if($files){
            "Cleaning up files from previous collections" | Trace-Output
            $files | Remove-Item -Force
        }

        # enable tracing
        netsh ras set tracing * enabled
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Disable-SdnGatewayTracing {
    <#
    .SYNOPSIS
        Disable netsh tracing for the RAS components
    #>

    try {
        # disable tracing
        netsh ras set tracing * disabled
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Enable-NetshTrace {
    <#
    .SYNOPSIS
        Enables netsh tracing. Supports pre-configured trace providers or custom provider strings.
    .PARAMETER ComputerName
        The computer name to perform the operation against
    .PARAMETER TraceProvider
        The trace providers in string format that you want to trace on
    .PARAMETER TraceFile
        The trace file that will be written. If omitted, the trace files will be generated under (Get-AzsSupportWorkingDirectory)\$($env:COMPUTERNAME)_netshTrace.etl on the computers defined
    .PARAMETER MaxTraceSize
        Optional. Specifies the maximum size in MB for saved trace files. If unspecified, the default is 1024.
    .PARAMETER Capture
        Optional. Specifies whether packet capture is enabled in addition to trace events. If unspecified, the default entry for capture is $true.
    .PARAMETER Overwrite
        Optional. Specifies whether this instance of the trace conversion command overwrites files that were rendered from previous trace conversions. If unspecified, the parameter defaults to $true.
    .PARAMETER Report
        Optional. Specifies whether a complementing report will be generated in addition to the trace file report. If unspecified, the default entry for report is disabled.
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [string]$TraceProvider = $null,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
			if($_ -notmatch "(\.etl)"){
				throw "The file specified in the TraceFile argument must be etl extension"
			}
            return $true
        })]
        [System.IO.FileInfo]$TraceFile,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024,

        [Parameter(Mandatory = $false)]
        [boolean]$Capture,

        [Parameter(Mandatory = $false)]
        [boolean]$Overwrite,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Enabled','Disabled')]
        [string]$Report = 'Disabled'
    )

    try {
        # ensure that we at least are attempting to configure NDIS tracing or ETW provider tracing, else the netsh
        # command will return a generic exception that is not useful to the operator
        if(!$Capture -and !$TraceProvider){
            throw New-Object System.Exception("You must at least specify Capture or TraceProvider parameter")
        }

        # netsh expects the command to be in yes or no format for several of it's parameters
        if($Capture){
            [string]$Capture = 'Yes'
        }
        else {
            [string]$Capture = 'No'
        }

        if($Overwrite){
            [string]$Overwrite = 'Yes'
        }
        else {
            [string]$Overwrite = 'No'
        }

        # ensure that the directory exists for file path
        if(!(Test-Path -Path (Split-Path -Path $TraceFile.FullName -Parent) -PathType Container)){
            $null = New-Item -Path (Split-Path -Path $TraceFile.FullName -Parent) -ItemType Directory -Force
        }

        # enable the network trace
        if($using:TraceProvider){
            $cmd = "netsh trace start capture=$Capture $TraceProvider tracefile=$FilePath maxsize=$MaxTraceSize overwrite=$Overwrite report=$Report"
        }
        else {
            $cmd = "netsh trace start capture=$Capture tracefile=$FilePath maxsize=$MaxTraceSize overwrite=$Overwrite report=$Report"
        }

        $result = Invoke-Expression -Command $cmd
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Disable-NetshTrace {
    <#
    .SYNOPSIS
        Disables netsh tracing.
    .PARAMETER ComputerName
        The computer name to perform the operation against
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName
    )

    try {
        $result = Invoke-Expression -Command "netsh trace stop"
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Start-SdnEtwTraceSession {
    <#
    .SYNOPSIS
        Enables netsh tracing. Supports pre-configured trace providers or custom provider strings.
    .PARAMETER ComputerName
        The computer name to perform the operation against
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
        [Parameter(Mandatory = $false)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [string]$TraceName,

        [Parameter(Mandatory = $false)]
        [string[]]$TraceProviders = $null,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
			if($_ -notmatch "(\.etl)"){
				throw "The file specified in the TraceFile argument must be etl extension"
			}
            return $true
        })]
        [System.IO.FileInfo]$TraceFile,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024
    )

    try {

        if(!$TraceProviders){
            throw New-Object System.Exception("You must at least one TraceProvider")
        }

        # ensure that the directory exists for file path
        if(!(Test-Path -Path (Split-Path -Path $TraceFile.FullName -Parent) -PathType Container)){
            $null = New-Item -Path (Split-Path -Path $TraceFile.FullName -Parent) -ItemType Directory -Force
        }

        Start-EtwTraceSession -Name $TraceName -MaximumFileSize $MaxTraceSize -LocalFilePath $TraceFile | Out-Null

        foreach ($provider in $TraceProviders) {
            "Adding provider {0}" -f $provider | Trace-Output -Level:Verbose
            Add-EtwTraceProvider -SessionName $TraceName -Guid $provider -Level 0xff | Out-Null
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }   
}

function Stop-SdnEtwTraceSession {
    <#
    .SYNOPSIS
        Enables netsh tracing. Supports pre-configured trace providers or custom provider strings.
    .PARAMETER ComputerName
        The computer name to perform the operation against
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
       Stop-EtwTraceSession -Name $TraceName
       
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }   
}

function Start-SdnTraceCapture{
    <#
    .SYNOPSIS
        Start ETW Trace capture based on Role
    .PARAMETER Role
        The SDN Roles 
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory
    )

    try{
        $config = Get-SdnRoleConfiguration -Role $Role

        # ensure that the appropriate windows feature is installed and ensure module is imported
        $confirmFeatures = Confirm-RequiredFeaturesInstalled -Name $config.windowsFeature
        if(!$confirmFeatures){
            throw New-Object System.Exception("Required feature is missing")
        }
    
        $confirmModules = Confirm-RequiredModulesLoaded -Name $config.requiredModules
        if(!$confirmModules){
            throw New-Object System.Exception("Required module is not loaded")
        }
    
        # create the OutputDirectory if does not already exist
        if(!(Test-Path -Path $OutputDirectory.FullName -PathType Container)){
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }
    
        foreach ($traceSession in $config.properties.etwTraceSessions) {
            "Starting trace session {0}" -f $traceSession.name | Trace-Output -Level:Verbose
            Start-SdnEtwTraceSession -TraceName $traceSession.name -TraceProviders $traceSession.providers -TraceFile "$OutputDirectory\$($traceSession.name).etl"  -MaxTraceSize 1024
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
   

function Stop-SdnTraceCapture{
    <#
    .SYNOPSIS
        Start ETW Trace capture based on Role
    .PARAMETER Role
        The SDN Roles 
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role
    )

    try{
        $config = Get-SdnRoleConfiguration -Role $Role
    
        foreach ($traceSession in $config.properties.etwTraceSessions) {
            Stop-SdnEtwTraceSession -TraceName $traceSession.name
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}