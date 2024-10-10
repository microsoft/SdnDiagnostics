function Get-SdnAuditLogSetting {
    <#
    .SYNOPSIS
        Retrieves the audit log settings for the Network Controller
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $object = [PSCustomObject]@{
        Enabled = $false
        OutputDirectory = $null
    }

    # verify that the environment we are on supports at least v3 API and later
    # as described in https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ncnbi/dc23b547-9ec4-4cb3-ab20-a6bfe01ddafb
    $currentRestVersion = (Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource 'Discovery' -Credential $NcRestCredential).properties.currentRestVersion
    [int]$currentRestVersionInt = $currentRestVersion.Replace('V','').Replace('v','').Trim()
    if ($currentRestVersionInt -lt 3) {
        "Auditing requires API version 3 or later. Network Controller supports version {0}" -f $currentRestVersionInt | Trace-Output -Level:Warning
        return
    }

    # check to see that auditing has been enabled
    $auditSettingsConfig = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Resource 'AuditingSettingsConfig' -ApiVersion $currentRestVersion -Credential $NcRestCredential
    if ([string]::IsNullOrEmpty($auditSettingsConfig.properties.outputDirectory)) {
        return $object
    }
    else {
        $object.Enabled = $true
        $object.OutputDirectory = $auditSettingsConfig.properties.outputDirectory

        return $object
    }
}
