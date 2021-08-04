function Install-SdnDiagnostic {
    <#
    .SYNOPSIS
        Install SdnDiagnostic Module to remote computers if not installed or version mismatch.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
    .PARAMETER Force
        Indicates that this cmdlet install SdnDiagnostic Module even if installed and version match.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {
        $moduleMissComputers = [System.Collections.ArrayList]::new()
        $localModuleInfo = Get-Module SdnDiagnostics
        if($Force){
            [void]$moduleMissComputers.AddRange($ComputerName)
            "SdnDiagnostics module will be forcely installed" | Trace-Output -Level:Verbose
        }
        else {
            foreach ($computer in $Computername){
                $session = New-PSRemotingSession -ComputerName $computer -Credential $Credential
                $remoteModuleInfo = Invoke-Command -Session $session -ScriptBlock{
                    return (Get-Module -ListAvailable -Name SdnDiagnostics)
                }
                if($null -ne $remoteModuleInfo){
                    # Module need to be installed if Version mismatch
                    if([Version]$remoteModuleInfo.Version -lt [Version]$localModuleInfo.Version){
                        [void]$moduleMissComputers.Add($computer)
                        "SdnDiagnostics module found on {0} but remote version {1} mismatch with local version {2}.  Will install it" -f $computer, $remoteModuleInfo.Version, $localModuleInfo.Version | Trace-Output -Level:Verbose
                    }
                    else {
                        "SdnDiagnostics module version {0} matched on {1}. No action taken" -f $remoteModuleInfo.Version, $computer | Trace-Output -Level:Verbose
                    }
                }
                else {
                    # Module need to be installed if never installed
                    [void]$moduleMissComputers.Add($computer)
                    "SdnDiagnostics module not found on {0}. Will install it" -f $computer | Trace-Output -Level:Verbose
                }
            }
        }
        
        if($moduleMissComputers.Count -gt 0){
            $modulePath = Get-Item -Path "$PSScriptRoot\..\..\..\"
            "SdnDiagnostics module found at {0}" -f $modulePath.FullName | Trace-Output -Level:Verbose
    
            if($modulePath){
                Copy-FileToPSRemoteSession -Path $modulePath.FullName -ComputerName $moduleMissComputers -Destination 'C:\Program Files\WindowsPowerShell\Modules' `
                    -Credential $Credential -Recurse -Force
            }    
        }
        # ensure that we destroy the current pssessions for the computer to prevent any odd caching issues
        Remove-PSRemotingSession -ComputerName $ComputerName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}