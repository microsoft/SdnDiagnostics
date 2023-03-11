function Get-SdnRoleConfiguration {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [SdnRoles]$Role
    )

    switch ($Role) {
        'Gateway' {
            return (Get-SdnGatewayModuleConfig)
        }

        default {
            return ($Global:SdnDiagnostics.Config[$Role])
        }
    }
}
