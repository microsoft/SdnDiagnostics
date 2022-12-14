# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-SdnResourceDump {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Invoke-SdnResourceDump
    .EXAMPLE
        PS> Invoke-SdnResourceDump -NcUri "https://nc.contoso.com"
    .EXAMPLE
        PS> Invoke-SdnResourceDump -NcUri "https://nc.contoso.com" -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'SdnApiResources'
        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $apiVersion = (Get-SdnDiscovery -NcUri $NcUri.AbsoluteUri -Credential $Credential).currentRestVersion
        if ($null -ieq $apiVersion) {
            $apiVersion = 'v1'
        }

        $config = Get-SdnRoleConfiguration -Role:NetworkController
        [int]$apiVersionInt = $ApiVersion.Replace('v','').Replace('V','')
        foreach ($resource in $config.properties.apiResources) {
            [int]$minVersionInt = $resource.minVersion.Replace('v','').Replace('V','')

            if ($minVersionInt -le $apiVersionInt) {
                $sdnResource = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $resource.uri -Credential $Credential
                if ($sdnResource) {
                    $sdnResource | Export-ObjectToFile -FilePath $outputDir.FullName -Name $resource.name -FileType json
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
