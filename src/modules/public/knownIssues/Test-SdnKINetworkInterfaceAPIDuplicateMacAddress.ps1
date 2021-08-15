# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-KINetworkInterfaceAPIDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within the Network Controller Network Interfaces API that are duplicate
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )
    
    try {
        "Checking for orphaned network interfaces in Network Controller" | Trace-Output

        if($null -eq $NcUri){
            throw New-Object System.NullReferenceException("Please specify NcUri parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }
        
        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if(!$PSBoundParameters.ContainsKey('NcRestCredential')){
            if($Global:SdnDiagnostics.NcRestCredential){
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }    
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        $networkInterfaces = Get-SdnResource -NcUri $NcUri.AbsoluteUri -ResourceType:NetworkInterfaces -Credential $NcRestCredential
        $duplicateObjects = $networkInterfaces | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}

        if($duplicateObjects){
            [void]$arrayList.Add($duplicateObjects)
            $issueDetected = $true

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="ResourceId";e={"`t$($_.resourceId)"}} `
                    | Select-Object -ExpandProperty ResourceId `
                    | Out-String `
                ) | Trace-Output -Level:Warning
            }
        }
    
        return [PSCustomObject]@{
            Result = $issueDetected
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}