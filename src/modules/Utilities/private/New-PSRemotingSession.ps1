function New-PSRemotingSession {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    try {

        if((Get-Service -Name WinRM).Status -ine 'Running'){
            $service = Start-Service -Name WinRM -PassThru
            if($service.Status -ine 'Running'){
                $msg = "Unable to start WinRM service`n`t{0}" -f $_
                throw New-Object System.Exception($msg)
            }
        }

        $remoteSessions = [System.Collections.ArrayList]::new()

        # return a list of current sessions on the computer
        # return only the sessions that are opened and available as this will allow new sessions to be opened
        # without having to wait for existing sessions to move from Busy -> Available
        $currentActiveSessions = Get-PSSession -Name "SdnDiag-*" | Where-Object {$_.State -ieq 'Opened' -and $_.Availability -ieq 'Available'}

        $remoteSessions = [System.Collections.ArrayList]::new()
        foreach($obj in $ComputerName){

            $session = $null

            # determine if an IP address was passed for the destination
            # if using IP address it needs to be added to the trusted hosts
            $isIpAddress = ($obj -as [IPAddress]) -as [Bool]
            if($isIpAddress){
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
                "Located existing powershell session {0}" -f $session.Name | Trace-Output -Level:Verbose
            }
            else {
                try {
                    if($Credential -ne [System.Management.Automation.PSCredential]::Empty){
                        "PSRemotingSession use provided credential {0}" -f $Credential.UserName | Trace-Output -Level:Verbose
                        $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $obj -Credential $Credential -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US) -ErrorAction Stop
                    }
                    else {
                        "PSRemotingSession use default credential" | Trace-Output -Level:Verbose
                        $session = New-PSSession -Name "SdnDiag-$(Get-Random)" -ComputerName $obj -SessionOption (New-PSSessionOption -Culture en-US -UICulture en-US) -ErrorAction Stop
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
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
