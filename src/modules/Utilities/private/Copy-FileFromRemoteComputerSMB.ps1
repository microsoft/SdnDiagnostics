# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Copy-FileFromRemoteComputerSMB {
    <#
    .SYNOPSIS
        Copies an item from one location to another using FromSession
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the remote computer.
    .PARAMETER Destination
        Specifies the path to the new location. The default is the current directory.
        To rename the item being copied, specify a new name in the value of the Destination parameter.
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

    $UNCPath = [System.Collections.ArrayList]::new()
    foreach($remotePath in $Path)
    {
        $driveName = [System.IO.Path]::GetPathRoot($remotePath)
        $remoteUNCPath = "\\{0}\{1}\{2}" -f $ComputerName, $driveName.Replace(":\", "$"), $remotePath.Substring(3)
        "Copying files from {0}" -f $remoteUNCPath | Trace-Output
        if(!(Test-Path $remoteUNCPath)){
            throw "Failed to access SMB path {0}" -f $remoteUNCPath
        }
        [void]$UNCPath.Add($remoteUNCPath)
    }
    Copy-Item -Path $UNCPath -Destination $Destination -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
}
