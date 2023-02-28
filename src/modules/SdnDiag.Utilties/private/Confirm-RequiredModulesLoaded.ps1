# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

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
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
        return $false
    }
}
