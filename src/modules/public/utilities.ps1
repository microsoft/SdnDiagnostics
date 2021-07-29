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

        if($modulePath){
            Copy-FileToPSRemoteSession -Path $modulePath.FullName -ComputerName $ComputerName -Destination 'C:\Program Files\WindowsPowerShell\Modules' `
                -Credential $Credential -Recurse -Force
        }

        # ensure that we destroy the current pssessions for the computer to prevent any odd caching issues
        Get-PSSession -ComputerName $ComputerName | Where Availability -ne "Busy" | Remove-PSSession
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}