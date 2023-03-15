function Test-VMNetAdapterDuplicateMacAddress {
    <#
    .SYNOPSIS
        Validate there are no adapters within hyper-v dataplane that may have duplicate MAC addresses.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
	.PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
	.PARAMETER NcRestCredential
		Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-VMNetAdapterDuplicateMacAddress
    .EXAMPLE
        PS> Test-VMNetAdapterDuplicateMacAddress -NcUri "https://nc.contoso.com" -Credential (Get-Credential) -NcRestCredential (Get-Credential)
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

    $sdnHealthObject = [SdnHealth]::new()
    $sdnHealthObject.Result = 'PASS'
    $arrayList = [System.Collections.ArrayList]::new()

    try {
        "Validate no duplicate MAC addresses for network adapters within Hyper-V" | Trace-Output

        $servers = Get-SdnServer -NcUri $NcUri.AbsoluteUri -ManagementAddressOnly -Credential $NcRestCredential
        $vmNetAdapters = Get-SdnVMNetworkAdapter -ComputerName $servers -AsJob -PassThru -Timeout 900 -Credential $Credential
        $duplicateObjects = $vmNetAdapters | Group-Object -Property MacAddress | Where-Object {$_.Count -ge 2}
        if($duplicateObjects){
            [void]$arrayList.Add($duplicateObjects)
            $sdnHealthObject.Result = 'FAIL'

            # since there can be multiple grouped objects, we need to enumerate each duplicate group
            foreach($obj in $duplicateObjects){
                "Located {0} virtual machines associated with MAC address {1}:`r`n`n{2}`r`n" -f $obj.Count, $obj.Name, `
                    ($obj.Group `
                    | Select-Object @{n="VMName";e={"`t$($_.VMName)"}} `
                    | Select-Object -ExpandProperty VMName `
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
