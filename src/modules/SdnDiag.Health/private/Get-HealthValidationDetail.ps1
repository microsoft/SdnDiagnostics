function Get-HealthValidationDetail {
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$Id
    )

    $configurationData = Import-PowerShellDataFile -Path $PSScriptRoot\SdnDiag.Health.Config.psd1
    return ($configurationData.HealthValidations[$Id])
}
