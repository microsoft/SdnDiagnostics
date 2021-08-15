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
        "Checking for duplicate network interfaces in Network Controller" | Trace-Output

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
        if($null -eq $networkInterfaces){
            throw New-Object System.NullReferenceException("No network interfaces returned from Network Controller")
        }

        $duplicateObjects = $networkInterfaces.properties | Group-Object -Property privateMacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            $issueDetected = $true

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                $duplicateInterfaces = $networkInterfaces | Where-Object {$_.properties.privateMacAddress -eq $obj.Name}
                [void]$arrayList.Add($duplicateInterfaces)

                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($duplicateInterfaces `
                    | Select-Object @{n="ResourceRef";e={"`t$($_.resourceRef)"}} `
                    | Select-Object -ExpandProperty ResourceRef `
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