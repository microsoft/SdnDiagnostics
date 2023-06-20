function Write-HealthValidationInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]$Name
    )

    $details = Get-HealthValidationDetail -Id $Name

    $outputString = $Name
    $outputString += "`r`n`r`n"
    $outputString += "--------------------------`r`n"
    $outputString += "Description:`t$($details.Description)`r`n"
    $outputString += "Impact:`t`t`t$($details.Impact)`r`n"
    $outputString += "`r`n"
    $outputString += "Additional information can be found at:`t$($details.PublicDoc)`r`n"
    $outputString += "--------------------------`r`n"
    $outputString += "`r`n"

    $outputString | Write-Host
}
