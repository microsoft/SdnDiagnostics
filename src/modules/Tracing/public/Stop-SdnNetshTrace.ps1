function Stop-SdnNetshTrace {

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Stop-SdnNetshTrace }
        }
        else {
            Stop-NetshTrace
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Exception
    }
}
