function Confirm-RequiredModulesLoaded {
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
                if(!(Get-Module -Name $obj)){
                    Import-Module -Name $obj -Force -ErrorAction Stop
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
