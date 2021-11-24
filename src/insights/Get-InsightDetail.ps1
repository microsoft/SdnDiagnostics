function Get-InsightDetail {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Guid]$Id,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Health','Issues')]
        [System.String]$Type
    )

    $content = (Get-Content -Path "$PSScriptRoot\resources\insights.json" | ConvertFrom-Json).$Type
    $currentInsight = $content | Where-Object {$_.Id -eq $Id}

    $insight = [Insight]@{
        Id              = $currentInsight.id
        Action          = $currentInsight.action
        Description     = $currentInsight.description
        Documentation   = $currentInsight.documentation
    }

    return $insight
}
