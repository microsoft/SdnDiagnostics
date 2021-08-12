# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-ServerConfigState {
    <#
    #>

    try {
        [Uri]$ncUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl
        $credential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.NcRestCredential){
            $credential = $Global:SdnDiagnostics.NcRestCredential
        }

        "Validating configuration and provisioning state of Servers" | Trace-Output

        $unhealthyNode = $false
        $arrayList = [System.Collections.ArrayList]::new()
        $servers = Get-SdnServer -NcUri $ncUri.AbsoluteUri -Credential $credential

        foreach($object in $servers){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $unhealthyNode = $true

                $details = [PSCustomObject]@{
                    resourceRef = $object.resourceRef
                    provisioningState = $object.properties.provisioningState
                    configurationState = $object.properties.configurationState
                }
    
                [void]$arrayList.Add($details)
            }
        }
        
        if($unhealthyNode){
            return [PSCustomObject]@{
                Status = 'Failure'
                Properties = $arrayList
            }
        }
        else {
            return [PSCustomObject]@{
                Status = 'Success'
                Properties = $arrayList
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}