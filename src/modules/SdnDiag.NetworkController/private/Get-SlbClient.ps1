function Get-SlbClient {
    $rootDir = "$env:SystemRoot\NetworkController"
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\SharedAssemblies\Microsoft.CloudNet.Slb.Utilities.SlbClient.dll");
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\Framework\Microsoft.NetworkController.Utilities.dll");
    $null = [Reflection.Assembly]::LoadFrom("$rootDir\Framework\Microsoft.NetworkController.ServiceModule.dll");

    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::SlbClientInitializeWithDefaultSettings();
    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::UseInteractiveLogon = $false
    [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbManagerConnectionFactory]::EnableBlockingNotifications = $true;

    $slbClient = [Microsoft.Cloudnet.Slb.Utilities.SlbClient.SlbClient]::new()
    return $slbClient
}
