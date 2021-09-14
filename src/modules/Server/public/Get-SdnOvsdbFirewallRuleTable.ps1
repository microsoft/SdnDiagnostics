function Get-SdnOvsdbFirewallRuleTable {
    <#
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$Timeout = 300
    )

    try {
        Invoke-PSRemoteCommand -ComputerName $ComputerName -ScriptBlock { Get-OvsdbFirewallRuleTable } -Credential $Credential `
            -AsJob:($AsJob.IsPresent) -PassThru:($PassThru.IsPresent) -ExecutionTimeout $Timeout
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
