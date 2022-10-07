# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Invoke-PSRemoteCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [System.String]$Activity,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$ExecutionTimeout = 600
    )

    $session = New-PSRemotingSession -ComputerName $ComputerName -Credential $Credential
    if ($session) {
        "ComputerName: {0}, ScriptBlock: {1}" -f ($session.ComputerName -join ', '), $ScriptBlock.ToString() | Trace-Output -Level:Verbose

        if ($AsJob) {
            $result = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -AsJob -JobName $([guid]::NewGuid().Guid)
            if ($PassThru) {
                if ($Activity) {
                    $result = Wait-PSJob -Name $result.Name -ExecutionTimeOut $ExecutionTimeout -Activity $Activity
                }
                else {
                    $result = Wait-PSJob -Name $result.Name -ExecutionTimeOut $ExecutionTimeout
                }
            }

            return $result
        }
        else {
            return (Invoke-Command -Session $session -ScriptBlock $ScriptBlock)
        }
    }
}
