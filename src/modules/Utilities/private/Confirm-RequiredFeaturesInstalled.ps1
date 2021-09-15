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
                    "Required feature {0} is not installed on {1}" -f $obj, $env:COMPUTERNAME | Trace-Output -Level:Error
                    return $false
                }
            }
    
            return $true
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        return $false
    }
}
