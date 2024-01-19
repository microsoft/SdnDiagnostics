function Invoke-PSRemoteCommand {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [bool]$ImportModuleOnRemoteSession,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Object[]]$ArgumentList = $null,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$AsJob,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [Switch]$PassThru,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [System.String]$Activity,

        [Parameter(Mandatory = $false, ParameterSetName = 'AsJob')]
        [int]$ExecutionTimeout = 600
    )

    $params = @{
        ScriptBlock = $ScriptBlock
    }

    $psSessionParams = @{
        ComputerName = $ComputerName
        Credential = $Credential
    }

    if ($PSBoundParameters.ContainsKey('ImportModuleOnRemoteSession')) {
        $psSessionParams.Add('ImportModuleOnRemoteSession', $ImportModuleOnRemoteSession)
    }

    $session = New-PSRemotingSession @psSessionParams
    if ($session) {
        $params.Add('Session', $session)
        "ComputerName: {0}, ScriptBlock: {1}" -f ($session.ComputerName -join ', '), $ScriptBlock.ToString() | Trace-Output -Level:Verbose
        if ($ArgumentList) {
            $params.Add('ArgumentList', $ArgumentList)
            "ArgumentList: {0}" -f ($ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
        }

        if ($AsJob) {
            $params += @{
                AsJob = $true
                JobName = "SdnDiag-{0}" -f $(Get-Random)
            }

            $result = Invoke-Command @params
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
            return (Invoke-Command @params)
        }
    }
}
