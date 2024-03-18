function New-SdnDiagNetworkMappedShare {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_.contains("\\") -and $_.contains("\")) {
                return $true
            }
            else {
                throw "The network share path must be in the format of \\server\share"
            }
        })]
        [System.String]$NetworkSharePath,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Creating new drive mapping to {0}" -f $NetworkSharePath | Trace-Output

        # create a new drive mapping to the network share path
        # if the credential is empty, we will not use a credential
        if ($Credential -eq [System.Management.Automation.PSCredential]::Empty) {
            $null = New-PSDrive -Name "SdnDiag_NetShare_Logs" -PSProvider FileSystem -Root $NetworkSharePath -ErrorAction Stop
        }
        else {
            $null = New-PSDrive -Name "SdnDiag_NetShare_Logs" -PSProvider FileSystem -Root $NetworkSharePath -Credential $Credential -ErrorAction Stop
        }

        "Successfully created network share mapping to {0}" -f $NetworkSharePath | Trace-Output
        return $true
    }
    catch {
        $_ | Trace-Exception
        return $false
    }
}
