function Get-SdnNetworkController {
    <#
    .SYNOPSIS
        Returns a list of servers from network controller
    .PARAMETER NetworkController
        One network conroller node name or ip address
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$NetworkController,

        [Parameter(Mandatory = $false)]
        [switch]$ServerNameOnly,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $result = Invoke-PSRemoteCommand -ComputerName $NetworkController -ScriptBlock {Get-NetworkControllerNode} -Credential $Credential
        foreach($obj in $result){
            if($obj.Status -ine 'Up'){
                "{0} is reporting status {1}" -f $obj.Name, $obj.Status | Trace-Output -Level:Warning
            }
        }

        if($ServerNameOnly){
            return $result.Name
        }
        else{
            return $result
        }

    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
