function Install-SdnDiagnostic {
    <##>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $modulePath = Get-Item -Path "$PSScriptRoot\..\..\..\"
        "SdnDiagnostics module found at {0}" -f $modulePath.FullName | Trace-Output -Level:Verbose

        foreach($obj in $ComputerName){

            # skip if for any reason the computer defined is the current machine
            # the command is being executed from
            if(Test-ComputerNameIsLocal -ComputerName $obj){
                "Detected that {0} is local machine. Skipping" -f $obj | Trace-Output
                continue
            }

            $session = New-PSRemotingSession -ComputerName $obj -Credential $Credential
            "Copying {0} to {1} via WinRM" -f $modulePath.FullName, $session.ComputerName | Trace-Output
            Copy-Item -Path $modulePath.FullName -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -ToSession $session -Force

            # ensure that we destroy the current pssessions for the computer to prevent any odd caching issues
            Get-PSSession -ComputerName $session.ComputerName | Remove-PSSession
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}