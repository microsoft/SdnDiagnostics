function Test-VfpDuplicatePort {
    <#
    .SYNOPSIS
        Validate there are no ports within VFP layer that may have duplicate MAC addresses.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-VfpDuplicatePort
    .EXAMPLE
        PS> Test-VfpDuplicatePort -NcUri "https://nc.contoso.com" -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    $sdnHealthObject = [SdnHealthResult]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validate no duplicate MAC addresses for ports within Virtual Filtering Platform (VFP)" | Trace-Output

        $servers = Get-SdnServer -NcUri $NcUri.AbsoluteUri -ManagementAddressOnly -Credential $NcRestCredential
        $vfpPorts = Get-SdnVfpVmSwitchPort -ComputerName $servers -Credential $Credential -AsJob -PassThru
        $duplicateObjects = $vfpPorts | Where-Object {$_.MACaddress -ne '00-00-00-00-00-00' -and $null -ne $_.MacAddress} | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            [void]$arrayList.Add($duplicateObjects)
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} VFP ports associated with {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="Portname";e={"`t$($_.Portname)"}} `
                    | Select-Object -ExpandProperty Portname `
                    | Out-String `
                ) | Trace-Output -Level:Warning
            }
        }

        $sdnHealthObject.Properties = $arrayList
        return $sdnHealthObject
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
