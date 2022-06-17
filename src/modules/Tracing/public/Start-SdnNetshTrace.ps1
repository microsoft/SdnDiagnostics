function Start-SdnNetshTrace {
    <#
        .SYNOPSIS

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

            if (-NOT ( Initialize-DataCollection -Role $Role -FilePath $OutputDirectory.FullName -MinimumMB ($MaxTraceSize*1.5) )) {
                "Unable to initialize environment for data collection" | Trace-Output -Level:Error
                return
            }
        }

        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential  -ScriptBlock {
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
