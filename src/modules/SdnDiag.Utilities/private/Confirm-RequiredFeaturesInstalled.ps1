function Confirm-RequiredFeaturesInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    if($null -eq $Name){
        return $true
    }
    else {
        foreach($obj in $Name){
            if(!(Get-WindowsFeature -Name $obj -ErrorAction SilentlyContinue).Installed){
                return $false
            }
        }

        return $true
    }

    return $false
}
