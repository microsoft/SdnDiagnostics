# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

Import-Module "$PSScriptRoot\..\SdnDiag.Utilities"

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
        [SdnRoles]$Role,

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
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -TraceProviderString 'provider="{EB171376-3B90-4169-BD76-2FB821C4F6FB}" level=0xff' -Capture No
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -TraceProviderString 'provider="{EB171376-3B90-4169-BD76-2FB821C4F6FB}" level=0xff' -Capture Yes
    .EXAMPLE
        PS> Start-NetshTrace -OutputDirectory "C:\Temp\CSS_SDN" -Capture Yes -MaxTraceSize 2048 -Report Disabled
    .EXAMPLE
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

    try {
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
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
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

    try {
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
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
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
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Remote')]
        [SdnRoles]$Role,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.IO.FileInfo]$OutputDirectory = "$(Get-WorkingDirectory)\NetworkTraces",

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [int]$MaxTraceSize = 1536,

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No')]
        [System.String]$Capture = 'Yes',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Yes', 'No')]
        [System.String]$Overwrite = 'Yes',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet('Enabled', 'Disabled')]
        [System.String]$Report = 'Disabled',

        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [ValidateSet("Default", "Optional", "All")]
        [string]$Providers = "All"
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Local') {
            $traceProviderString = Get-TraceProviders -Role $Role -Providers $Providers -AsString
            if ($null -eq $traceProviderString -and $Capture -eq 'No') {
                $Capture = 'Yes'
                "No default trace providers found for role {0}. Setting capture to {1}" -f $Role, $Capture | Trace-Output
            }

            if (-NOT ( Initialize-DataCollection -Role $Role -FilePath $OutputDirectory.FullName -MinimumMB ($MaxTraceSize * 1.5) )) {
                "Unable to initialize environment for data collection" | Trace-Output -Level:Error
                return
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Start-SdnNetshTrace -Role $using:Role -OutputDirectory $using:OutputDirectory.FullName `
                    -Capture $using:Capture -Overwrite $using:Overwrite -Report $using:Report -MaxTraceSize $using:MaxTraceSize -Providers $using:Providers
            }
        }
        else {
            Start-NetshTrace -OutputDirectory $OutputDirectory.FullName -TraceProviderString $traceProviderString `
                -Capture $Capture -Overwrite $Overwrite -Report $Report -MaxTraceSize $MaxTraceSize
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
