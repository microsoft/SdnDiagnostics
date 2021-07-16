function Test-VfpDuplicatePorts {

    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.NcUrl
    )

    try {
        $vfpPorts = Get-SdnVFPVMSwitchPorts -ComputerName (Get-SdnServers -NcUri $NcUri.AbsoluteUri -ManagementAddress) -AsJob -PassThru
        $duplicateObjects = $vfpPorts | Where-Object {$_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress} | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
    
        if($duplicateObjects){
            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} VFP ports associated with {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="Portname";e={"`t$($_.Portname)"}} `
                    | Select-Object -ExpandProperty Portname `
                    | Out-String `
                ) | Trace-Output -Level:Warning
            }
    
            return [PSCustomObject]@{
                Result = $true
                Properties = $duplicateObjects
            }
        }
        else {
            return [PSCustomObject]@{
                Result = $false
                Properties = $null
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
