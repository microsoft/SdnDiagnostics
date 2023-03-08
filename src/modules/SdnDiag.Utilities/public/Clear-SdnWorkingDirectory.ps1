function Clear-SdnWorkingDirectory {
    <#
    .SYNOPSIS
        Clears the contents of the directory specified
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Path
        Specifies a path of the items being removed. Wildcard characters are permitted. If ommitted, defaults to (Get-WorkingDirectory).
    .PARAMETER Recurse
        Indicates that this cmdlet deletes the items in the specified locations and in all child items of the locations.
    .PARAMETER Force
        Forces the cmdlet to remove items that cannot otherwise be changed, such as hidden or read-only files or read-only aliases or variables.
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -ComputerName PREFIX-NC01 -Path 'C:\Temp\SDN2'
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -ComputerName PREFIX-NC01,PREFIX-SLB01 -Credential (Get-Credential)
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -Force -Recurse
    .EXAMPLE
        PS> Clear-SdnWorkingDirectory -Path 'C:\Temp\SDN1','C:\Temp\SDN2' -Force -Recurse
    #>

    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [System.String[]]$Path = (Get-WorkingDirectory),

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false, ParameterSetName = 'Remote')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Local')]
        [Switch]$Force
    )

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Remote') {
            Invoke-PSRemoteCommand -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                Clear-SdnWorkingDirectory -Path $using:Path -Recurse:($using:Recurse.IsPresent) -Force:($using:Force.IsPresent)
            }
        }
        else {
            foreach ($object in $Path) {
                # enumerate through the allowed folder paths for cleanup to make sure the paths specified can be cleaned up
                $pathAllowed = $false
                foreach ($allowedFolderPath in $Global:SdnDiagnostics.Settings.FolderPathsAllowedForCleanup) {
                    if ($object -ilike $allowedFolderPath) {
                        $pathAllowed = $true
                    }
                }

                # once validated that the path can be removed then perform test to make sure path exists before attempting to remove
                if ($pathAllowed) {
                    if (Test-Path -Path $object) {
                        "Remove {0}" -f $object | Trace-Output -Level:Verbose
                        Remove-Item -Path $object -Exclude $Global:SdnDiagnostics.Settings.FilesExcludedFromCleanup -Force:($Force.IsPresent) -Recurse:($Recurse.IsPresent) -ErrorAction Continue
                    }
                }
                else {
                    "{0} is not defined as an allowed path for cleanup. Skipping" -f $object | Trace-Output -Level:Warning
                }
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}