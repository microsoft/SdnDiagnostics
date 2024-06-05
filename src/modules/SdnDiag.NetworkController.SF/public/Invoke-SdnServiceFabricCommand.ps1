function Invoke-SdnServiceFabricCommand {
    <#
    .SYNOPSIS
        Connects to the service fabric ring that is used by Network Controller.
    .PARAMETER ScriptBlock
        Specifies the commands to run. Enclose the commands in braces ({ }) to create a script block. When using Invoke-Command to run a command remotely, any variables in the command are evaluated on the remote computer.
    .PARAMETER ArgumentList
        Supplies the values of parameters for the scriptblock. The parameters in the script block are passed by position from the array value supplied to ArgumentList. This is known as array splatting.
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Invoke-SdnServiceFabricCommand -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ScriptBlock { Get-ServiceFabricClusterHealth }
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory = $false)]
        [Object[]]$ArgumentList = $null
    )

    $params = @{
        ScriptBlock = $ScriptBlock
    }
    if ($ArgumentList) {
        $params.Add('ArgumentList', $ArgumentList)
    }
    if (-NOT (Test-ComputerNameIsLocal -ComputerName $NetworkController)) {
        $params.Add('ComputerName', $NetworkController)
        $params.Add('Credential', $Credential)
    }
    else {
        Confirm-IsNetworkController
    }

    "NetworkController: {0}, ScriptBlock: {1}" -f $NetworkController, $ScriptBlock.ToString() | Trace-Output -Level:Verbose
    if ($params.ArgumentList) {
        "ArgumentList: {0}" -f ($params.ArgumentList | ConvertTo-Json).ToString() | Trace-Output -Level:Verbose
    }

    $sfResults = Invoke-Command @params -ErrorAction Stop
    if ($sfResults.GetType().IsPrimitive -or ($sfResults -is [String])) {
        return $sfResults
    }
    else {
        return ($sfResults | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId)
    }
}
