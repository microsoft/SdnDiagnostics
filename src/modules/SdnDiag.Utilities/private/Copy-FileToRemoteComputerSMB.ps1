function Copy-FileToRemoteComputerSMB {
    <#
    .SYNOPSIS
        Copies an item from local path to a path at remote server via SMB
    .PARAMETER Path
        Specifies, as a string array, the path to the items to copy. Wildcard characters are permitted.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of the remote computer.
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
        [System.String]$Destination = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    begin {
        $params = @{
            'Path'          = $null
            'Destination'   = $null
            'Force'         = $Force.IsPresent
            'Recurse'       = $Recurse.IsPresent
        }
        if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $null -ne $Credential) {
            $params.Add('Credential', $Credential)
        }

        # set this to suppress the information status bar from being displayed
        $Global:ProgressPreference = 'SilentlyContinue'
        $testNetConnection = Test-NetConnection -ComputerName $ComputerName -Port 445 -InformationLevel Quiet
        $Global:ProgressPreference = 'Continue'

        if (-NOT ($testNetConnection)) {
            $msg = "Unable to establish TCP connection to {0}:445" -f $ComputerName
            throw New-Object System.Exception($msg)
        }

        $remotePath = Convert-FileSystemPathToUNC -ComputerName $ComputerName -Path $Destination
        $params.Destination = $remotePath
    }
    process {
        foreach ($subPath in $Path) {
            $params.Path = $subPath

            try {
                "Copying {0} to {1}" -f $params.Path, $params.Destination | Trace-Output
                Copy-Item @params
            }
            catch [System.IO.IOException] {
                if ($_.Exception.Message -ilike "*used by another process*") {
                    "{0}\{1} is in use by another process" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Exception
                    continue
                }

                if ($_.Exception.Message -ilike "*already exists*") {
                    "{0}\{1} already exists" -f $remotePath, $_.CategoryInfo.TargetName | Trace-Output -Level:Exception
                    continue
                }

                $_ | Trace-Output -Level:Exception
            }
        }
    }
}
