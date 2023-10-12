function New-PSRemotingSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool]$ImportModuleOnRemoteSession = $Global:SdnDiagnostics.Config.ImportModuleOnRemoteSession,

        [Parameter(Mandatory = $false)]
        [Switch]$Force
    )

    $importModule = {
        param([string]$arg0, $arg1)
        try {
            Import-Module $arg0 -ErrorAction Stop
            $Global:SdnDiagnostics.Config = $arg1
        }
        catch {
            throw $_
        }
    }

    $remoteSessions = [System.Collections.ArrayList]::new()

    # return a list of current sessions on the computer
    # return only the sessions that are opened and available as this will allow new sessions to be opened
    # without having to wait for existing sessions to move from Busy -> Available
    $currentActiveSessions = Get-PSSession -Name "SdnDiag-*" | Where-Object {$_.State -ieq 'Opened' -and $_.Availability -ieq 'Available'}

    foreach($obj in $ComputerName){
        $session = $null

        # determine if an IP address was passed for the destination
        # if using IP address it needs to be added to the trusted hosts
        $isIpAddress = ($obj -as [IPAddress]) -as [Bool]
        if($isIpAddress){
            "{0} is an ip address" -f $obj | Trace-Output -Level:Verbose
            $trustedHosts = Get-Item -Path "WSMan:\localhost\client\TrustedHosts"
            if($trustedHosts.Value -notlike "*$obj*" -and $trustedHosts.Value -ne "*") {
                "Adding {0} to {1}" -f $obj, $trustedHosts.PSPath | Trace-Output
                Set-Item -Path "WSMan:\localhost\client\TrustedHosts" -Value $obj -Concatenate
            }
        }

        # check to see if session is already opened
        # if no session already exists or Force is defined, then create a new remote session
        if($currentActiveSessions.ComputerName -contains $obj -and !$Force){
            $session = ($currentActiveSessions | Where-Object {$_.ComputerName -eq $obj})[0]
            "Located existing powershell session {0} for {1}" -f $session.Name, $obj | Trace-Output -Level:Verbose
        }
        else {
            try {
                if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
                    "PSRemotingSession use provided credential {0}" -f $Credential.UserName | Trace-Output -Level:Verbose
                    $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $obj -Credential $Credential -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US -IdleTimeout 86400000) -ErrorAction Stop
                }
                else {
                    # if we need to create a new remote session, need to check to ensure that if using an IP Address that credentials are specified
                    # which is a requirement from a WinRM perspective. Will throw a warning and skip session creation for this computer.
                    if ($isIpAddress -and $Credential -eq [System.Management.Automation.PSCredential]::Empty) {
                        "Unable to create PSSession to {0}. The Credential parameter is required when using an IP Address." -f $obj | Trace-Output -Level:Warning
                        continue
                    }

                    # if we are already in a remote session and we do not have credentials defined
                    # we need to throw a warning and skip session creation for this computer
                    # as the credentials via the current session cannot be passed to the new session without CredSSP enabled
                    if ($PSSenderInfo -and !(Get-WSManCredSSPState)) {
                        "Credential parameter is required when already in a remote session" | Trace-Output -Level:Warning
                        continue
                    }

                    "PSRemotingSession use default credential" | Trace-Output -Level:Verbose
                    $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $obj -SessionOption (New-PSSessionOption -Culture 'en-US' -UICulture 'en-US' -IdleTimeout 86400000) -ErrorAction Stop

                    if ($ImportModuleOnRemoteSession) {
                        Invoke-Command -Session $session -ScriptBlock $importModule -ArgumentList @($script:SdnDiagnostics_Utilities.Cache.RemoteModuleName, $Global:SdnDiagnostics.Config) -ErrorAction Stop
                    }
                }

                "Created powershell session {0} to {1}" -f $session.Name, $obj | Trace-Output -Level:Verbose
            }
            catch {
                "Unable to create powershell session to {0}`n`t{1}" -f $obj, $_.Exception | Trace-Output -Level:Warning
                continue
            }
        }

        # add the session to the array
        if($session){
            [void]$remoteSessions.Add($session)
        }
    }

    return $remoteSessions
}
