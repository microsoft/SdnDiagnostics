# place holder for the core windows sdn data collection script

function Start-SdnDataCollection {

    <#
        .SYNOPSIS
        Automated network diagnostics and data collection/tracing script.

        .PARAMETER DataCollectionType 
        Optional parameter that allows the user to define if they want to collect either Configuration, Logs or None. Default is Logs
            Configuration - Gathers basic configuration details related to SDN infrastructure
            Logs - Gathers diagnostics logs and event traces, in addition to configuration details

        .PARAMETER Scenario
        Required parameter that allows you to specify the datapath scenario you want to enable
            SLB - Adds the appropriate SLB nodes as part of the data collection 
            Gateway - Add the appropriate Gateway nodes as part of the data collection
            None - No scenario

        .PARAMETER EnableNetworkTraces
        Optional switch parameter that allows you to collect network traces as part of the data collection process

        .PARAMETER OutputDirectory

        .PARAMETER RemoteSharePath
        Optional parameter that allows you to output results to a remote network share

        .PARAMETER RemoteShareCredentials
        Optional parameter used in conjuction with RemoteSharePath that provides appropriate credentials to access the RemoteSharePath location

        .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 120 hours.
            (Get-Date).AddHours(-4)

        .PARAMETER MaxTraceSize
        Optional parameter that allows you to define maximum size allowed for network trace. Default is 2048 MB
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Configuration','Logs','None')]
        [System.String]$DataCollectionType = 'Logs',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Starting SDN Data Collection" | Trace-Output
    if($null -eq $OutputDirectory){
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
    }

    [System.IO.FileInfo]$outputDir = (Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC))
    "Results will be saved to {0}" -f $outputDir.FullName | Trace-Output

    "Generating output of the NC API resources" | Trace-Output
    Get-SdnApiResources -NcUri $NcUri.AbsoluteUri -OutputDirectory $OutputDirectory.FullName -Credential $Credential
}