# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnDataCollection {

    <#
    .SYNOPSIS
        Automated network diagnostics and data collection/tracing script.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.    
    .PARAMETER DataCollectionType 
        Optional parameter that allows the user to define if they want to collect either Configuration, Logs or None. Default is Logs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Configuration', 'Logs', 'None')]
        [System.String]$DataCollectionType = 'Logs',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Starting SDN Data Collection" | Trace-Output
    if ($null -eq $OutputDirectory) {
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
    }

    [System.IO.FileInfo]$outputDir = (Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC))
    "Results will be saved to {0}" -f $outputDir.FullName | Trace-Output

    "Generating output of the NC API resources" | Trace-Output
    Get-SdnApiResource -NcUri $NcUri.AbsoluteUri -OutputDirectory $outputDir.FullName -Credential $Credential
}
