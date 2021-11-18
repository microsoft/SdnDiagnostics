function Get-InsightDetails {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Health','Issues')]
        [System.String]$Type
    )

    $content = Get-Content -Path "$PSScriptRoot\resources\$Type.json" | ConvertFrom-Json
    return $content[$Name]
}
