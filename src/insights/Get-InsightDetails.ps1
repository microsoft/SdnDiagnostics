function Get-InsightDetail {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Guid]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Health','Issues')]
        [System.String]$Type
    )

    $content = Get-Content -Path "$PSScriptRoot\resources\$Type.json" | ConvertFrom-Json
    $insight = $content | Where-Object {$_.Id -eq $Id}

    $healthInsight = [HealthInsight]@{
        Id          = $insight.id
        Description = $insight.description
        Reference   = $insight.documentation
        Remediation = $insight.remediation
    }

    return $healthInsight
}
