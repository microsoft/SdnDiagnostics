# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Enable-SdnGatewayTracing {
    <#
    .SYNOPSIS
        Enables netsh tracing for the RAS components. Files will be saved to C:\Windows\Tracing by default
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [int]$MaxTraceSize = 1024
    )]

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
            "Cleaning up files from previous collections" | Trace-Output -Level:Verbose
            $files | Remove-Item -Force
        }

        # enable ras tracing
        netsh ras set tracing * enabled

        # enable netsh tracing with capture
        $traceProviderString = Get-TraceProviders -Role:Gateway -Providers Default -AsString
        Start-NetshTrace -TraceFile $OutputDirectory.FullName -TraceProviderString $traceProviderString -MaxTraceSize $MaxTraceSize -Report 'Disabled' -Capture 'Yes' -Overwrite 'Yes'
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

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory
    )]

    try {
        # disable ras tracing and copy logs to the output directory
        netsh ras set tracing * disabled
        $files = Get-ChildItem -Path $config.properties.commonPaths.rasGatewayTraces -Include '*.log','*.etl'
        if($files){
            $files | Move-Item -Destination $OutputDirectory.FullName -Force
        }

        # disable the netsh trace
        Stop-NetshTrace
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
        [Parameter(Mandatory = $true)]
        [ValidateScript({
			if($_ -notmatch "(\.etl)"){
				throw "The file specified in the TraceFile argument must be etl extension"
			}
            return $true
        })]
        [System.IO.FileInfo]$TraceFile,

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
        [ValidateSet('Enabled','Disabled')]
        [System.String]$Report = 'Disabled'
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
            $cmd = "netsh trace start capture={0} {1} tracefile={2} maxsize={3} overwrite={4} report={5}" `
                -f $Capture, $TraceFile.FullName, $TraceProviderString, $MaxTraceSize, $Overwrite, $Report
        }
        else {
            $cmd = "netsh trace start capture={0} tracefile={1} maxsize={2} overwrite={3} report={4}" `
                -f $Capture, $TraceFile.FullName, $MaxTraceSize, $Overwrite, $Report
        }

        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose

        $expression = Invoke-Expression -Command $cmd
        if($expression -ilike "*Running*"){
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = $expression[3].split(' ')[-1].Trim()
                    Details = $expression
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

function Stop-NetshTrace {
    <#
    .SYNOPSIS
        Disables netsh tracing.
    #>
    
    try {
        $expression = Invoke-Expression -Command "netsh trace stop"
        if($expression -ilike "*Tracing session was successfully stopped.*"){
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Stopped'
                    Details = $expression
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
        [System.String]$cmd = "netsh trace convert input={0} output={1} overwrite={2} report={3}" `
            -f $FileName.FullName, $outputFile, $Overwrite, $Report
        
        "Netsh trace cmd:`n`t{0}" -f $cmd | Trace-Output -Level:Verbose    
        $expression = Invoke-Expression -Command $cmd

        # output returned is string objects, so need to manually do some mapping to correlate the properties
        # that can be then returned as psobject to the call
        if($expression[5] -ilike "*done*"){
            $object = New-Object -TypeName PSCustomObject -Property (
                [Ordered]@{
                    Status = 'Success'
                    Details = $expression
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
   
function Start-EtwTraceCapture {
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
   

function Stop-EtwTraceCapture {
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
        $traceProvidersArray = Get-TraceProviders -Role $Role -Providers $Providers
    
        foreach ($traceProviders in $traceProvidersArray) {
            Stop-EtwTraceSession -TraceName $traceProviders.name
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}