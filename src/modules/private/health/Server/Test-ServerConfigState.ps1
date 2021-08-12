# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-ServerConfigState {
    <#
    .SYNOPSIS
        Validate that the configurationState and provisioningState is Success
    #>

    try {
        "Validating configuration and provisioning state of Servers" | Trace-Output
        
        [Uri]$ncUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl

        $ncRestCredential = [System.Management.Automation.PSCredential]::Empty
        if($Global:SdnDiagnostics.NcRestCredential){
            $ncRestCredential = $Global:SdnDiagnostics.NcRestCredential
        }

        $status = 'Success'
        $arrayList = [System.Collections.ArrayList]::new()

        $servers = Get-SdnServer -NcUri $ncUri.AbsoluteUri -Credential $ncRestCredential
        foreach($object in $servers){
            if($object.properties.configurationState.status -ine 'Success' -or $object.properties.provisioningState -ine 'Succeeded'){
                $status = 'Failure'

                $details = [PSCustomObject]@{
                    resourceRef = $object.resourceRef
                    provisioningState = $object.properties.provisioningState
                    configurationState = $object.properties.configurationState
                }
    
                [void]$arrayList.Add($details)
            }
        }
        
        return [PSCustomObject]@{
            Status = $status
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}