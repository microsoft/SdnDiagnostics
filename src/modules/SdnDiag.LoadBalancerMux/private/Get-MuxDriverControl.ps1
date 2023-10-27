function Get-MuxDriverControl {
    if (-NOT (Get-Module -Name 'Microsoft.Cloudnet.Slb.Mux.MuxDriverControl')) {
        Import-Module "$env:SystemRoot\Windows\System32\Microsoft.Cloudnet.Slb.Mux.MuxDriverControl.dll" -Force
    }

    return ([Microsoft.Cloudnet.Slb.Mux.Driver.SlbDriverControl]::new())
}
