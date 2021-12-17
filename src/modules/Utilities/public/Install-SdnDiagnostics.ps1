# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Install-SdnDiagnostics {
    <#
    .SYNOPSIS
        Install SdnDiagnostic Module to remote computers if not installed or version mismatch.
    .PARAMETER ComputerName
        Type the NetBIOS name, an IP address, or a fully qualified domain name of one or more remote computers.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
        Type a user name, such as User01 or Domain01\User01, or enter a PSCredential object generated by the Get-Credential cmdlet. If you type a user name, you're prompted to enter the password.
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
        [System.IO.FileInfo]$moduleRootDir = "C:\Program Files\WindowsPowerShell\Modules"
        $filteredComputerName = [System.Collections.ArrayList]::new()
        $installNodes = [System.Collections.ArrayList]::new()

        # if we have multiple modules installed on the current workstation, 
        # abort the operation because side by side modules can cause some interop issues to the remote nodes
        $localModule = Get-Module -Name 'SdnDiagnostics'
        if ($localModule.Count -gt 1) {
            throw New-Object System.ArgumentOutOfRangeException("Detected more than one module version of SdnDiagnostics. Remove existing modules and restart your PowerShell session.")
        }

        # since we may not know where the module was imported from we cannot accurately assume the $localModule.ModuleBase is correct
        # manually generate the destination path we want the module to be installed on remote nodes
        if ($localModule.ModuleBase -ilike "*$($localModule.Version.ToString())") {
            [System.IO.FileInfo]$destinationPathDir = "{0}\{1}\{2}" -f $moduleRootDir.FullName, 'SdnDiagnostics', $localModule.Version.ToString()
        }
        else {
            [System.IO.FileInfo]$destinationPathDir = "{0}\{1}" -f $moduleRootDir.FullName, 'SdnDiagnostics'
        }

        "Current version of SdnDiagnostics is {0}" -f $localModule.Version.ToString() | Trace-Output
        
        # make sure that in instances where we might be on a node within the sdn dataplane, 
        # that we do not remove the module locally
        foreach ($computer in $ComputerName) {
            if (Test-ComputerNameIsLocal -ComputerName $computer) {
                "Detected that {0} is local machine. Skipping update operation for {0}." -f $computer | Trace-Output -Level:Warning
                continue
            }
            
            [void]$filteredComputerName.Add($computer)
        }

        # check to see if the current version is already present on the remote computers
        # else if we -Force defined, we can just move forward
        if ($Force) {
            "{0} will be installed on all computers" -f $localModule.Version.ToString() | Trace-Output
            $installNodes = $filteredComputerName
        }
        else {
            $remoteModuleVersion = Invoke-PSRemoteCommand -ComputerName $filteredComputerName -Credential $Credential -ScriptBlock {
                try {
                    $version = (Get-Module -Name SdnDiagnostics -ListAvailable -ErrorAction SilentlyContinue).Version.ToString()
                }
                catch {
                    # in some instances, the module will not be available and as such we want to skip the noise and return
                    # a string back to the remote call command which we can do proper comparison against
                    $version = '0.0.0.0'
                }
                
                return $version
            }

            # enumerate the versions returned for each computer and compare with current module version to determine if we should perform an update
            foreach ($computer in ($remoteModuleVersion.PSComputerName | Sort-Object -Unique)) {
                "Checking module version on {0}" -f $computer | Trace-Output -Level:Verbose
                $updateRequired = $false
                
                foreach ($version in ($remoteModuleVersion | Where-Object {$_.PSComputerName -ieq $computer})) {
                    if ([version]$version -lt [version]$localModule.Version) {
                        "{0} is currently using version {1}" -f $computer, $version.ToString() | Trace-Output -Level:Verbose 
                        $updateRequired = $true
                    }
                    elseif ([version]$version -ge [version]$localModule.Version) {
                        "{0} is currently using version {1}. Update is not required" -f $computer, $version.ToString() | Trace-Output -Level:Verbose
                        $updateRequired = $false
                    }
                }

                if ($updateRequired) {
                    "{0} will be updated to {1}" -f $computer, $localModule.Version.ToString() | Trace-Output
                    [void]$installNodes.Add($computer)
                }
            }
        }

        # clean up the module directory on remote computers
        "Cleaning up SdnDiagnostics in remote Windows PowerShell Module directory" | Trace-Output
        Invoke-PSRemoteCommand -ComputerName $installNodes -Credential $Credential -ScriptBlock {
            $modulePath = 'C:\Program Files\WindowsPowerShell\Modules\SdnDiagnostics'
            if (Test-Path -Path $modulePath -PathType Container) {
                Remove-Item -Path $modulePath -Recurse -Force
            }
        }

        # copy the module base directory to the remote computers
        # currently hardcoded to machine's module path. Use the discussion at https://github.com/microsoft/SdnDiagnostics/discussions/68 to get requirements and improvement
        Copy-FileToRemoteComputer -Path $localModule.ModuleBase -ComputerName $installNodes -Destination $destinationPathDir.FullName -Credential $Credential -Recurse -Force

        # ensure that we destroy the current pssessions for the computer to prevent any caching issues
        # we want to target all the original computers, as may be possible that we running on a node within the sdn fabric
        # and have existing PSSession to itself from previous execution run
        Remove-PSRemotingSession -ComputerName $ComputerName
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
