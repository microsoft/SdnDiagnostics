# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Start-SdnDataCollection {

    <#
    .SYNOPSIS
        Automated network diagnostics and data collection/tracing script.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER OutputDirectory
        Specifies a specific path and folder in which to save the files.    
    .PARAMETER DataCollectionType 
        Optional parameter that allows the user to define if they want to collect either Configuration, Logs or None. Default is Logs.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Uri]$NcUri,

        [Parameter(Mandatory = $false)]
        [System.IO.FileInfo]$OutputDirectory,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Configuration', 'Logs', 'None')]
        [System.String]$DataCollectionType = 'Logs',

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    "Starting SDN Data Collection" | Trace-Output
    if ($null -eq $OutputDirectory) {
        [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
    }

    [System.IO.FileInfo]$outputDir = (Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC))
    "Results will be saved to {0}" -f $outputDir.FullName | Trace-Output

    "Generating output of the NC API resources" | Trace-Output
    Get-SdnApiResource -NcUri $NcUri.AbsoluteUri -OutputDirectory $outputDir.FullName -Credential $Credential
}
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        $ncNodes = [System.Collections.Generic.List[Object]]::new()
        $slbNodes = [System.Collections.Generic.List[Object]]::new()
        $serverNodes = [System.Collections.Generic.List[Object]]::new()
        $gatewayNodes = [System.Collections.Generic.List[Object]]::new()
        $dataCollectionNodes = [System.Collections.Generic.List[Object]]::new()

        # setup the directory location where files will be saved to
        "Starting SDN Data Collection" | Trace-Output
        if ($null -eq $OutputDirectory) {
            [System.IO.FileInfo]$OutputDirectory = (Get-WorkingDirectory)
        }

        [System.IO.FileInfo]$OutputDirectory = Join-Path -Path $OutputDirectory.FullName -ChildPath (Get-FormattedDateTimeUTC)
        if (-NOT (Test-Path -Path $OutputDirectory.FullName -PathType Container)) {
            $null = New-Item -Path $OutputDirectory.FullName -ItemType Directory -Force
        }

        "Results will be saved to {0}" -f $outputDir.FullName | Trace-Output

        # generate a mapping of the environment and assign objects to variables for easy reference
        $sdnFabricDetails = Get-SdnInfrastructureInfo -NetworkController $NetworkController -Credential $Credential -NcRestCredential $NcRestCredential
        switch ($PSBoundParameters.ParameterSetName) {
            'Role' {
                foreach ($value in $Role) {
                    foreach ($node in $sdnFabricDetails[$value]) {
                        $object = [PSCustomObject]@{
                            Role = $value
                            Name = $node
                        }

                        $dataCollectionNodes.Add($object)
                    }
                }
            }
            
            'Node' {
                foreach ($value in $ComputerName) {
                    $roleName = $sdnFabricDetails.Name | Where-Object {$_.Value -icontains $value}

                    $object = [PSCustomObject]@{
                        Role = $roleName
                        Name = $value
                    }

                    $dataCollectionNodes.Add($object)
                }
            }
        }

        foreach ($object in $dataCollectionNodes) {
            switch ($object.Role) {
                'Gateway' { $gatewayNodes.Add($object.Name) }
                'NetworkController' { $ncNodes.Add($object.Name) }
                'Server' { $serverNodes.Add($object.Name) }
                'SoftwareLoadBalancer' { $slbNodes.Add($object.Name) }
            }
        }

        # generate configuration state files for the environment
        Get-SdnApiResource -NcUri $NcUri.AbsoluteUri -OutputDirectory $OutputDirectory.FullName -Credential $NcRestCredential


    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}

$dataCollectionNodes.Add($value, $Global:SdnDiagnostics.EnvironmentInfo[$value])