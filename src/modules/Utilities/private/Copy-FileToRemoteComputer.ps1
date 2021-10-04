# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Copy-FileToRemoteComputer {
    <#
    .SYNOPSIS
        Copies an item from local path to a path at remote server
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
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
        [System.String[]]$ComputerName,

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

    try {
        foreach ($object in $ComputerName) {
            if (Test-ComputerNameIsLocal -ComputerName $object) {
                "Detected that {0} is local machine. Skipping copy operation." -f $object | Trace-Output -Level:Warning
                continue
            }

            # Try SMB Copy first and fallback to WinRM
            try {
                Copy-FileToRemoteComputerSMB -Path $Path -ComputerName $object -Destination $Destination -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent)
            }
            catch {
                "SMB Copy failed, fallback to WinRM" | Trace-Output
                try {
                    Copy-FileToRemoteComputerWinRM -Path $Path -ComputerName $object -Destination $Destination -Credential $credential -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent)
                }
                catch {
                    # Catch the copy failed exception to not stop the copy for other computers which might success
                    "WinRM Copy failed" | Trace-Output
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
