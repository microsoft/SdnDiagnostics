# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Get-SdnApiResource {
    <#
    .SYNOPSIS
        Returns a list of gateways from network controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnApiResource
    .EXAMPLE
        PS> Get-SdnApiResource -NcUri "https://nc.contoso.com"
    .EXAMPLE
        PS> Get-SdnApiResource -NcUri "https://nc.contoso.com" -Credential (Get-Credential)
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

        $config = Get-SdnRoleConfiguration -Role:NetworkController
        foreach ($resource in $config.properties.apiResources) {
            try {
                $sdnResource = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $resource -Credential $Credential
                if ($sdnResource) {
                    $sdnResource | Export-ObjectToFile -FilePath $outputDir.FullName -Name $resource.Replace('/', '_') -FileType json
                }
            }
            catch {
                $_.Exception | Trace-Output -Level:Warning
            }
        }

        Get-SdnDiscovery -NcUri $NcUri.AbsoluteUri -Credential $Credential | Export-ObjectToFile -FilePath $outputDir.FullName -Name 'discovery' -FileType json
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
