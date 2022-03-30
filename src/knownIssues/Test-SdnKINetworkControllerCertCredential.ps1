# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function Test-SdnKINetworkControllerCertCredential {
    <#
    .SYNOPSIS
        Query the NC Cert credential used to connect to SDN Servers, ensure cert exist.
    .PARAMETER NetworkController
        Specifies the name or IP address of the network controller node on which this cmdlet operates.
    .PARAMETER NcUri
        Specifies the Uniform Resource Identifier (URI) of the network controller that all Representational State Transfer (REST) clients use to connect to that controller.
    .PARAMETER Credential
        Specifies a user account that has permission to perform this action. The default is the current user.
    .PARAMETER NcRestCredential
        Specifies a user account that has permission to access the northbound NC API interface. The default is the current user.
    .EXAMPLE
        PS> Test-SdnKINetworkControllerCertCredential
    .EXAMPLE
        PS> Test-SdnKINetworkControllerCertCredential -Credential (Get-Credential) -NcRestCredential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String[]]$NetworkController = $global:SdnDiagnostics.EnvironmentInfo.NetworkController,

        [Parameter(Mandatory = $false)]
        [Uri]$NcUri = $Global:SdnDiagnostics.EnvironmentInfo.NcUrl,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $NcRestCredential = [System.Management.Automation.PSCredential]::Empty
    )

    try {
        "Validate Cert Credential resource of SDN Servers. Ensure Cert exist on each of the Network Controller " | Trace-Output

        if ($null -eq $NetworkController) {
            throw New-Object System.NullReferenceException("Please specify NetworkController parameter or execute Get-SdnInfrastructureInfo to populate environment details")
        }

        # if Credential parameter not defined, check to see if global cache is populated
        if (!$PSBoundParameters.ContainsKey('Credential')) {
            if ($Global:SdnDiagnostics.Credential) {
                $Credential = $Global:SdnDiagnostics.Credential
            }
        }

        # if NcRestCredential parameter not defined, check to see if global cache is populated
        if (!$PSBoundParameters.ContainsKey('NcRestCredential')) {
            if ($Global:SdnDiagnostics.NcRestCredential) {
                $NcRestCredential = $Global:SdnDiagnostics.NcRestCredential
            }    
        }

        $issueDetected = $false
        $arrayList = [System.Collections.ArrayList]::new()

        # enumerate each server's conection->credential object into the array
        $servers = Get-SdnServer -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential
        $serverCredentialRefs = [System.Collections.Hashtable]::new()
        foreach ($server in $servers) {
            # find the first connection with credential type of X509Certificate
            $serverConnection = $server.properties.connections | Where-Object { $_.credentialType -eq "X509Certificate" } | Select-Object -First 1;
            if ($null -ne $serverConnection) {
                $credRef = $serverConnection.credential[0].resourceRef
                "Adding credential {0} for server {1} for validation" -f $credRef, $serverConnection.managementAddresses[0] | Trace-Output -Level:Verbose
                if ($null -ne $credRef) {
                    if (-NOT $serverCredentialRefs.ContainsKey($credRef)) {
                        $serverList = [System.Collections.ArrayList]::new()
                        $serverCredentialRefs.Add($credRef, $serverList)
                    }
                    [void]$serverCredentialRefs[$credRef].Add($server)
                }     
            }
        }

        # iterate the credential object to validate certificate on each NC
        foreach ($credRef in $serverCredentialRefs.Keys) {
            $credObj = Get-SdnResource -NcUri $NcUri.AbsoluteUri -Credential $NcRestCredential -ResourceRef $credRef
            if ($null -ne $credObj) {
                $thumbPrint = $credObj.properties.value
                $scriptBlock = {
                    if (-NOT (Test-Path -Path Cert:\LocalMachine\My\$using:thumbPrint)) {
                        "Certificate with thumbprint $using:thumbPrint not found" | Trace-Output -Level:Warning
                        return $false
                    }
                    else {
                        return $true
                    }
                }
                
                # invoke command on each NC seperately so to record which NC missing certificate
                foreach ($nc in $NetworkController) {
                    "Validating certificate [{0}] on NC {1}" -f $thumbPrint, $nc | Trace-Output -Level:Verbose
                    $result = Invoke-PSRemoteCommand -ComputerName $nc -ScriptBlock $scriptBlock -Credential $Credential
                    if ($result -ne $true) {
                        # if any NC missing certificate, it indicate issue detected
                        $issueDetected = $true
                        $object = [PSCustomObject]@{
                            NetworkController  = $nc
                            CertificateMissing = $thumbPrint
                            AffectedServers    = $serverCredentialRefs[$credRef]
                        }
        
                        [void]$arrayList.Add($object)
                    }    
                }
                
            }
        }

        return [PSCustomObject]@{
            Result     = $issueDetected
            Properties = $arrayList
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
