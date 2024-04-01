function Get-SdnServiceFabricService {
    <#
    .SYNOPSIS
        Gets a list of Service Fabric services from Network Controller.
    .PARAMETER ApplicationName
        A service fabric application name that exists on the provided ring, such as fabric:/NetworkController.
    .PARAMETER ServiceName
        A service fabric service name that is under the provided ApplicationName on the provided ring, such as fabric:/NetworkController/ApiService.
    .PARAMETER ServiceTypeName
        A service fabric service TypeName, such as VSwitchService
    .PARAMETER NetworkController
        Specifies the name of the network controller node on which this cmdlet operates.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential)
    .EXAMPLE
        PS> Get-SdnServiceFabricService -NetworkController 'Prefix-NC01' -Credential (Get-Credential) -ServiceTypeName 'ApiService'
    #>

    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param(
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ApplicationName = 'fabric:/NetworkController',

        [Parameter(Mandatory = $true, ParameterSetName = 'NamedService')]
        [System.String]$ServiceName,

        [Parameter(Mandatory = $true, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$ServiceTypeName,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.String]$NetworkController = $env:COMPUTERNAME,

        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedService')]
        [Parameter(Mandatory = $false, ParameterSetName = 'NamedServiceTypeName')]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $sfParams = @{
        NetworkController = $NetworkController
        Credential = $Credential
    }

    switch ($PSCmdlet.ParameterSetName) {
        'NamedService' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceName))
            $sb = {
                param([string]$param1, [string]$param2)
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceName $param2
            }
        }
        'NamedServiceTypeName' {
            $sfParams.Add('ArgumentList',@($ApplicationName, $ServiceTypeName))
            $sb = {
                param([string]$param1, [string]$param2)
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService -ServiceTypeName $param2
            }
        }
        default {
            $sfParams.Add('ArgumentList',@($ApplicationName))
            $sb = {
                param([string]$param1)
                Get-ServiceFabricApplication -ApplicationName $param1 | Get-ServiceFabricService
            }
        }
    }

    try {
        Invoke-SdnServiceFabricCommand @sfParams -ScriptBlock $sb
    }
    catch {
        $_ | Trace-Exception
        $_ | Write-Error
    }
}
