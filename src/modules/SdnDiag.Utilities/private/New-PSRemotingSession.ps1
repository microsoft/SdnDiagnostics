function New-PSRemotingSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool]$ImportModuleOnRemoteSession = $Global:SdnDiagnostics.Config.ImportModuleOnRemoteSession,

        [Parameter(Mandatory = $false)]
        [System.String]$ModuleName = $Global:SdnDiagnostics.Config.ModuleName,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    begin {
        $importRemoteModule = {
            param([string]$arg0, $arg1)
            try {
                Import-Module $arg0 -ErrorAction Stop
                $Global:SdnDiagnostics.Config = $arg1
            }
            catch {
                throw $_
            }
        }

        $confirmRemoteModuleImported = {
            param([string]$arg0)
            $moduleExists = Get-Module -Name $arg0 -ListAvailable -ErrorAction Ignore
            if ($moduleExists) {
                return $true
            }

            return $false
        }

        $remoteSessions = @()

        # return a list of current sessions on the computer
        # return only the sessions that are opened and available as this will allow new sessions to be opened
        # without having to wait for existing sessions to move from Busy -> Available
        $currentActiveSessions = Get-PSSession -Name "SdnDiag-*" | Where-Object { $_.State -ieq 'Opened' -and $_.Availability -ieq 'Available' }
    }
    process {
        $ComputerName | ForEach-Object {
            $session = $null
            $objectName = $_

            # check to see if session is already opened
            # if no session already exists or Force is defined, then create a new remote session
            if ($currentActiveSessions.ComputerName -contains $objectName -and !$Force) {
                $session = ($currentActiveSessions | Where-Object { $_.ComputerName -eq $objectName })[0]
                "Located existing powershell session {0} for {1}" -f $session.Name, $objectName | Trace-Output -Level:Verbose

                if ($ImportModuleOnRemoteSession) {
                    $moduleImported = Invoke-Command -Session $session -ScriptBlock $confirmRemoteModuleImported -ArgumentList @($ModuleName) -ErrorAction Stop
                    if (-NOT $moduleImported) {
                        "Importing module {0} on remote session {1}" -f $ModuleName, $session.Name | Trace-Output -Level:Verbose
                        Invoke-Command -Session $session -ScriptBlock $importRemoteModule -ArgumentList @($ModuleName, $Global:SdnDiagnostics.Config) -ErrorAction Stop
                    }
                }

                $remoteSessions += $session
                continue
            }

            # determine if an IP address was passed for the destination
            # if using IP address it needs to be added to the trusted hosts
            $isIpAddress = ($objectName -as [IPAddress]) -as [Bool]
            if ($isIpAddress) {
                try {
                    Confirm-IsAdmin

                    "{0} is an ip address" -f $objectName | Trace-Output -Level:Verbose
                    $trustedHosts = Get-Item -Path "WSMan:\localhost\client\TrustedHosts"
                    if ($trustedHosts.Value -notlike "*$objectName*" -and $trustedHosts.Value -ne "*") {
                        "Adding {0} to {1}" -f $objectName, $trustedHosts.PSPath | Trace-Output
                        Set-Item -Path "WSMan:\localhost\client\TrustedHosts" -Value $objectName -Concatenate
                    }
                }
                catch {
                    $_ | Trace-Output -Level:Error
                    continue
                }
            }

            try {
                if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                    "PSRemotingSession use user-defined credential" | Trace-Output -Level:Verbose
                    $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $objectName -Credential $Credential -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US -IdleTimeout 86400000) -ErrorAction Stop
                }
                else {
                    # if the credential is not defined, we want to check if we
                    if ($PSSenderInfo -and !(Get-WSManCredSSPState)) {
                        throw New-Object System.NotSupportedException("Unable to create PSSession to $objectName. This operation is not supported in a remote session without supplying -Credential.")
                    }

                    # if we need to create a new remote session, need to check to ensure that if using an IP Address that credentials are specified
                    # which is a requirement from a WinRM perspective. Will throw a warning and skip session creation for this computer.
                    if ($isIpAddress -and $Credential -eq [System.Management.Automation.PSCredential]::Empty) {
                        throw New-Object System.NotSupportedException("Unable to create PSSession to $objectName. The Credential parameter is required when using an IP Address.")
                    }

                    "PSRemotingSession use default credential" | Trace-Output -Level:Verbose
                    $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $objectName -SessionOption (New-PSSessionOption -Culture 'en-US' -UICulture 'en-US' -IdleTimeout 86400000) -ErrorAction Stop
                }

                "Created powershell session {0} to {1}" -f $session.Name, $objectName | Trace-Output -Level:Verbose
                if ($ImportModuleOnRemoteSession) {
                    "Importing module {0} on remote session {1}" -f $ModuleName, $session.Name | Trace-Output -Level:Verbose
                    Invoke-Command -Session $session -ScriptBlock $importRemoteModule -ArgumentList @($ModuleName, $Global:SdnDiagnostics.Config) -ErrorAction Stop
                }

                # add the session to the array
                $remoteSessions += $session
            }
            catch {
                "Unable to create powershell session to {0}`n`t{1}" -f $objectName, $_.Exception.Message | Trace-Output -Level:Error
                continue
            }
        }
    }
    end {
        $remoteSessions | Sort-Object -Unique
    }
}
