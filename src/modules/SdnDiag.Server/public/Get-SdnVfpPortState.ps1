function Get-SdnVfpPortState {
    <#
    .SYNOPSIS
        Returns the current VFP port state for a particular port Id.
    .DESCRIPTION
        Executes 'vfpctrl.exe /get-port-state /port $port' to return back the current state of the port specified.
    .PARAMETER PortName
        The port name to return the state for.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of a remote computer. The default is the local computer.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnVfpPortState -PortName 3DC59D2B-9BFE-4996-AEB6-2589BD20B559
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [GUID]$PortName,

        [Parameter(Mandatory = $false)]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $params = @{
        PortName = $PortName
    }

    try {
        if ($PSBoundParameters.ContainsKey('ComputerName')) {
            $results = Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                param ([guid]$arg0)
                Get-VfpPortState -PortName $arg0
            } -ArgumentList @($params.PortName)
        }
        else {
            $results = Get-VfpPortState @params
        }

        return $results
    }
    catch {
        $_ | Trace-Exception
    }
}
