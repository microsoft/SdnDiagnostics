# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnServiceFabricLog {
    <#
    .SYNOPSIS
        Collect the default enabled logs from Service Fabric folder
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.
    .PARAMETER FromDate
        Optional parameter that allows you to control how many hours worth of logs to retrieve from the system for the roles identified. Default is 4 hours.
    .EXAMPLE
        PS> Get-SdnServiceFabricLog -OutputDirectory "C:\Temp\CSS_SDN\SFLogs"
    .EXAMPLE
        PS> Get-SdnServiceFabricLog -OutputDirectory "C:\Temp\CSS_SDN\SFLogs" -FromDate (Get-Date).AddHours(-1)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [parameter(Mandatory = $false)]
        [DateTime]$FromDate = (Get-Date).AddHours(-4)
    )

    try {
        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [System.IO.FileInfo]$sfLogDir = $config.properties.commonPaths.serviceFabricLogDirectory
        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath "ServiceFabricLogs"

        "Collect Service Fabric logs between {0} and {1} UTC" -f $FromDate.ToUniversalTime(), (Get-Date).ToUniversalTime() | Trace-Output

        if (!(Initialize-DataCollection -FilePath $OutputDirectory.FullName -MinimumGB 5)) {
            throw New-Object System.Exception("Unable to initialize environment for data collection")
        }

        $serviceFabricLogs = Get-ChildItem -Path $sfLogDir.FullName | Where-Object { $_.LastWriteTime -ge $FromDate }
        foreach ($file in $serviceFabricLogs) {
            Copy-Item -Path $file.FullName -Destination $OutputDirectory.FullName -Force
        }

        # once we have copied the files to the new location we want to compress them to reduce disk space
        # if confirmed we have a .zip file, then remove the staging folder
        Compress-Archive -Path "$($OutputDirectory.FullName)\*" -Destination $OutputDirectory.FullName -CompressionLevel Optimal -Force
        if (Test-Path -Path "$($OutputDirectory.FullName).zip" -PathType Leaf) {
            Remove-Item -Path $OutputDirectory.FullName -Force -Recurse
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
