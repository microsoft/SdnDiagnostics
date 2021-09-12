# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
    .PARAMETER TraceProviderString
        The trace providers in string format that you want to trace on.
    .PARAMETER TraceFile
        The trace file that will be written. Requires full path name and trace file with etl extension.
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
        [Parameter(Mandatory = $false)]
        [System.String]$TraceProviderString,

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
        [ValidateSet('Yes', 'No')]
        [System.String]$Capture = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Enabled','Disabled')]
        [string]$Report = 'Disabled'
    )

    try {
        # ensure that we at least are attempting to configure NDIS tracing or ETW provider tracing, else the netsh
        # command will return a generic exception that is not useful to the operator
        if($Capture -ieq 'No' -and !$TraceProvider){
            throw New-Object System.Exception("You must at least specify Capture or TraceProvider parameter")
        }

        # ensure that the directory exists for file path
        if(!(Test-Path -Path (Split-Path -Path $TraceFile.FullName -Parent) -PathType Container)){
            $null = New-Item -Path (Split-Path -Path $TraceFile.FullName -Parent) -ItemType Directory -Force
        }

        # enable the network trace
        if($TraceProvider){
            $cmd = "netsh trace start capture=$Capture $TraceProvider tracefile=$FilePath maxsize=$MaxTraceSize overwrite=$Overwrite report=$Report"
        }
        else {
            $cmd = "netsh trace start capture=$Capture tracefile=$FilePath maxsize=$MaxTraceSize overwrite=$Overwrite report=$Report"
        }

        $start = Invoke-Expression -Command $cmd
        if($start -ilike "*Running*"){
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = $start[3].split(' ')[-1].Trim()
                    FileName = $start[4].split(' ')[-1].Trim()
                    Append = $start[5].split(' ')[-1].Trim()
                    Circular = $start[6].split(' ')[-1].Trim()
                    MaxSize = $start[7].split(' ')[-1].Trim()
                    Report = $start[8].split(' ')[-1].Trim()
                }
            )
        }
        else {
            # typically, the first line returned in scenarios where there was an error thrown will contain the error details
            throw New-Object System.Exception($start[0])
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Disable-NetshTrace {
    <#
    .SYNOPSIS
        Disables netsh tracing.
    #>
    
    try {
        $stop = Invoke-Expression -Command "netsh trace stop"
        if($stop -ilike "*Tracing session was successfully stopped.*"){
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Stopped'
                    Details = $stop
                }
            )
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Convert-EtwTraceToTxt {
    <#
    .SYNOPSIS
        Used to convert existing etw provider traces into text readable format
    .PARAMETER FileName
        ETL trace file path and name to convert 
    .PARAMETER Destination
        Output file name and directory. If ommitted, will use the FileName path and base name.
    .PARAMETER Overwrite
        Overwrites existing files. If ommitted, defaults to no.
    .PARAMETER Report
        Generates an HTML report. If ommitted, defaults to no.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$FileName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination,

        [Parameter(Mandatory = $false)]
        [ValidateSet('No','Yes')]
        [System.String]$Overwrite = 'No',

        [Parameter(Mandatory = $false)]
        [ValidateSet('No','Yes')]
        [System.String]$Report = 'No'
    )

    try {
        if(!$Destination){
            [System.IO.FileInfo]$Destination = $FileName.FullName
        }

        if(!(Test-Path -Path $Destination.FullName -PathType Container)){
            $null = New-Item -Path $Destination.FullName -ItemType Directory -Force
        }

        [System.String]$outputFile = "{0}.txt" -f (Join-Path -Path $Destination.FullName -ChildPath $FileName.BaseName)
        [System.String]$cmd = "netsh trace convert input={0} output={1} overwrite={2} report={3}" -f $FileName.FullName, $outputFile, $Overwrite, $Report
        $convert = Invoke-Expression -Command $cmd

        # output returned is string objects, so need to manually do some mapping to correlate the properties
        # that can be then returned as psobject to the call
        if($convert[5] -ilike "*done*"){
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Success'
                    Input = $convert[1].Split(' ')[-1].Trim()
                    Output = $convert[2].Split(' ')[-1].Trim()
                    Format = 'txt'
                }
            )
        }
        else {
            # typically, the first line returned in scenarios where there was an error thrown will contain the error details
            throw New-Object System.Exception($convert[0])
        }

        return $object
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

function Start-SdnEtwTraceSession {
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
        # ensure that the directory exists for file path
        if(!(Test-Path -Path (Split-Path -Path $TraceFile.FullName -Parent) -PathType Container)){
            $null = New-Item -Path (Split-Path -Path $TraceFile.FullName -Parent) -ItemType Directory -Force
        }

        $logmanCmd = "logman create trace $TraceName -ow -o $TraceFile -nb 16 16 -bs 1024 -mode Circular -f bincirc -max $MaxTraceSize -ets"
        $result = Invoke-Expression -Command $logmanCmd

        # Session create failure error need to be reported to user to be aware, this means we have one trace session missing. 
        # Provider add failure might be ignored and exposed via verbose trace/log file only to debug. 
        if("$result".Contains("Error")){
            "Create session {0} failed with error {1}" -f $TraceName, "$result" | Trace-Output -Level:Warning
        }else{
            "Created session {0} with result {1}" -f $TraceName,"$result" | Trace-Output -Level:Verbose
        }
       
        foreach ($provider in $TraceProviders) {
            $logmanCmd = 'logman update trace $TraceName -p "$provider" 0xffffffffffffffff 0xff -ets'
            $result = Invoke-Expression -Command $logmanCmd
            "Added provider {0} with result {1}" -f $provider,"$result" | Trace-Output -Level:Verbose
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }   
}

function Stop-SdnEtwTraceSession {
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
        if("$result".Contains("Error")){
            "Stop session {0} failed with error {1}" -f $TraceName, "$result" | Trace-Output -Level:Warning
        }
        else {
            "Stop session {0} with result {1}" -f $TraceName,"$result" | Trace-Output -Level:Verbose
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }   
}


function Get-SdnTraceProviders {
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
        [SdnRoles]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"
    )

    try {
        $config = Get-SdnRoleConfiguration -Role $Role
        $traceProvidersArray  =  [System.Collections.ArrayList]::new()
        foreach ($traceProviders in $config.properties.etwTraceProviders) {
            switch($Providers){
                "Default" {
                    if($traceProviders.isOptional -ne $true){
                        [void]$traceProvidersArray.Add($traceProviders)
                    }
                }
                "Optional" {
                    if($traceProviders.isOptional -eq $true){
                        [void]$traceProvidersArray.Add($traceProviders)
                    }
                }
                "All" {
                    [void]$traceProvidersArray.Add($traceProviders)
                }
            }
        }
        return $traceProvidersArray
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
   
function Start-SdnTraceCapture {
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
        [SdnRoles]$Role,

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

        $traceProvidersArray = Get-SdnTraceProviders -Role $Role -Providers $Providers
    
        foreach ($traceProviders in $traceProvidersArray) {
            "Starting trace session {0}" -f $traceProviders.name | Trace-Output -Level:Verbose
            Start-SdnEtwTraceSession -TraceName $traceProviders.name -TraceProviders $traceProviders.providers -TraceFile "$OutputDirectory\$($traceProviders.name).etl"  -MaxTraceSize 1024
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
   

function Stop-SdnTraceCapture {
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
        [SdnRoles]$Role,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "Default"

    )

    try {
        $traceProvidersArray = Get-SdnTraceProviders -Role $Role -Providers $Providers
    
        foreach ($traceProviders in $traceProvidersArray) {
            Stop-SdnEtwTraceSession -TraceName $traceProviders.name
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}