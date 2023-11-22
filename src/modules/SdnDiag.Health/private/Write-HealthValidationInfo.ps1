function Write-HealthValidationInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Role,

        [Parameter(Mandatory = $true)]
        [String]$Name,

        [Parameter(Mandatory = $false)]
        [String[]]$Remediation
    )

    $details = Get-HealthData -Property 'HealthValidations' -Id $Name

    $outputString = "[$Role] $Name"
    $outputString += "`r`n`r`n"
    $outputString += "--------------------------`r`n"
    $outputString += "Description:`t$($details.Description)`r`n"
    $outputString += "Impact:`t`t$($details.Impact)`r`n"

    if (-NOT [string]::IsNullOrEmpty($Remediation)) {
        $outputString += "Remediation:`r`n`t -`t$($Remediation -join "`r`n`t -`t")`r`n"
    }

    if (-NOT [string]::IsNullOrEmpty($details.PublicDocUrl)) {
        $outputString += "`r`n"
        $outputString += "Additional information can be found at $($details.PublicDocUrl).`r`n"
    }

    $outputString += "`r`n--------------------------`r`n"
    $outputString += "`r`n"

    $outputString | Write-Host -ForegroundColor Yellow
}
