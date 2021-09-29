# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Copy-FileFromPSRemoteSession {
    <#
    .SYNOPSIS
        Copies an item from one location to another using FromSession
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
        foreach($object in $ComputerName){
            if(Test-ComputerNameIsLocal -ComputerName $object){
                "Detected that {0} is local machine. Skipping" -f $object | Trace-Output -Level:Warning
                continue
            }

            [System.IO.FileInfo]$outputDirectory = Join-Path -Path $Destination.FullName -ChildPath $object
            if(!(Test-Path -Path $outputDirectory.FullName -PathType Container)){
                $null = New-Item -Path $outputDirectory.FullName -ItemType Directory -Force
            }
            # Try SMB Copy first
            try{
                $UNCPath = [System.Collections.ArrayList]::new()
                foreach($remotePath in $Path)
                {
                    $driveName = [System.IO.Path]::GetPathRoot($remotePath)
                    $remoteUNCPath = "\\{0}\{1}\{2}" -f $object, $driveName.Replace(":\", "$"), $remotePath.Substring(3)
                    "Copying files from {0}" -f $remoteUNCPath | Trace-Output
                    if(!(Test-Path $remoteUNCPath)){
                        throw "Failed to access SMB path {0}" -f $remoteUNCPath
                    }
                    [void]$UNCPath.Add($remoteUNCPath)
                }
                Copy-Item -Path $UNCPath -Destination $outputDirectory.FullName -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
            }catch{
                "SMB Copy failed, fallback to WinRM" | Trace-Output
                $session = New-PSRemotingSession -ComputerName $object -Credential $Credential
                if($session){
                    "Copying files from {0} to {1} using {2}" -f $session.ComputerName, $outputDirectory.FullName, $session.Name | Trace-Output
                    Copy-Item -Path $Path -Destination $outputDirectory.FullName -FromSession $session -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction:Continue
                }
                else {
                    "Unable to copy files from {0} as no remote session could be established" -f $object | Trace-Output -Level:Warning
                    continue
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
