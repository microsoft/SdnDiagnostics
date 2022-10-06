# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Copy-FileToRemoteComputerWinRM {
    <#
    .SYNOPSIS
        Copies an item from one location to another using ToSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one remote computer.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Recurse
        Indicates that this cmdlet does a recursive copy.
    .PARAMETER Force
        Indicates that this cmdlet copies items that can't otherwise be changed, such as copying over a read-only file or alias.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$Path,

        [Parameter(Mandatory = $true)]
        [System.String]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $session = New-PSRemotingSession -ComputerName $ComputerName -Credential $Credential
    if ($session) {
        foreach ($subPath in $Path) {
            "Copying {0} to {1} using WinRM Session {2}" -f $subPath, $Destination.FullName, $session.Name | Trace-Output
            Copy-Item -Path $subPath -Destination $Destination.FullName -ToSession $session -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
        }
    }
    else {
        $msg = "Unable to copy files to {0} as no remote session could be established" -f $object
        throw New-Object System.Exception($msg)
    }
}
