function Confirm-RequiredFeaturesInstalled {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$Name
    )

    try {

        if($null -eq $Name){
            return $true
        }
        else {
            foreach($obj in $Name){
                if(!(Get-WindowsFeature -Name $obj).Installed){
                    return $false
                }
            }

            return $true
        }
    }
    catch {
        $_ | Trace-Exception
        return $false
    }
}
