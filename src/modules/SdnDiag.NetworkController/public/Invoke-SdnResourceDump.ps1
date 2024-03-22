function Invoke-SdnResourceDump {
    <#
    .SYNOPSIS
        Performs API request to all available northbound endpoints for NC and dumps out the resources to json file.
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
        "Generating resource dump for Network Controller NB API endpoints" | Trace-Output
        [System.IO.FileInfo]$outputDir = Join-Path -Path $OutputDirectory.FullName -ChildPath 'SdnApiResources'
        if (!(Test-Path -Path $outputDir.FullName -PathType Container)) {
            $null = New-Item -Path $outputDir.FullName -ItemType Directory -Force
        }

        $apiVersion = (Get-SdnDiscovery -NcUri $NcUri.AbsoluteUri -Credential $Credential).currentRestVersion
        if ($null -ieq $apiVersion) {
            $apiVersion = 'v1'
        }

        # objects returned from the apiResourse property are a hashtable, so need to work in key/value pairs
        $config = Get-SdnModuleConfiguration -Role:NetworkController
        [int]$apiVersionInt = $ApiVersion.Replace('v','').Replace('V','')
        foreach ($key in $config.properties.apiResources.Keys) {
            $value = $config.Properties.apiResources[$key]

            # skip any resources that are not designed to be exported
            if ($value.includeInResourceDump -ieq $false) {
                continue
            }

            [int]$minVersionInt = $value.minVersion.Replace('v','').Replace('V','')
            if ($minVersionInt -le $apiVersionInt) {
                $sdnResource = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceRef $value.uri -Credential $Credential
                if ($sdnResource) {
                    $sdnResource | Export-ObjectToFile -FilePath $outputDir.FullName -Name $key -FileType json -Depth 10
                }
            }
        }
    }
    catch {
        $_ | Trace-Exception
    }
}
