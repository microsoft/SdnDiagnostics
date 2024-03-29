
function Get-SdnAuditLog {
    <#
    .SYNOPSIS
        Collects the audit logs for Network Security Groups (NSG) from the hypervisor hosts
    .PARAMETER OutputDirectory
        Directory the results will be saved to. If ommitted, will default to the current working directory.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER NCRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote compute
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$OutputDirectory = "$(Get-WorkingDirectory)\AuditLogs",

        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ValueFromPipeline)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

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
        "Audit logging is not enabled" | Trace-Output
        return
    }
    else {
        "Audit logging location: {0}" -f $auditSettingsConfig.properties.outputDirectory | Trace-Output
    }

    # if $ComputerName was not specified, then attempt to locate the servers within the SDN fabric
    # only add the servers where auditingEnabled has been configured as 'Firewall'
    if ($null -eq $ComputerName) {
        $sdnServers = Get-SdnResource -Resource Servers -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential -ApiVersion $currentRestVersion `
        | Where-Object {$_.properties.auditingEnabled -ieq 'Firewall'}

        $ComputerName = ($sdnServers.properties.connections | Where-Object {$_.credentialType -ieq 'UsernamePassword'}).managementAddresses
    }

    $ComputerName | ForEach-Object {
        "Collecting audit logs from {0}" -f $_ | Trace-Output
        $outputDir = Join-Path -Path $OutputDirectory -ChildPath $_.ToLower()
        Copy-FileFromRemoteComputer -ComputerName $_ -Credential $Credential -Path $auditSettingsConfig.properties.outputDirectory -Destination $outputDir -Recurse -Force
    }
}
