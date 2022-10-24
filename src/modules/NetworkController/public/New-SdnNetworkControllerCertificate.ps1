# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

function New-SdnNetworkControllerCertificate {
    <#
    .SYNOPSIS
        Generate new Self-Signed Certificate to be used by Network Controller.
    .PARAMETER NetworkController
        Specifies the name the network controller node on which this cmdlet operates. The parameter is optional if running on network controller node.
    .PARAMETER Credential
		Specifies a user account that has permission to perform this action. The default is the current user.
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo
    .EXAMPLE
        PS> Get-SdnInfrastructureInfo -NetworkController 'NC01' -Credential (Get-Credential)
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $NetworkController = $(HostName),
        [Parameter(Mandatory = $false)]
        [String]
        $NcRestName,
        [Parameter(Mandatory = $false)]
        [datetime]
        $NotAfter = (Get-Date).AddYears(1)
    )


    try {
        $NcInfraInfo = Get-SdnNetworkControllerInfoOffline -NetworkController $NetworkController
        Trace-Output "Network Controller Infrastrucutre Info detected:"
        Trace-Output "ClusterCredentialType: $($NcInfraInfo.ClusterCredentialType)"
        Trace-Output "NcRestName: $($NcInfraInfo.NcRestName)"
        
        $NcNodeList = $NcInfraInfo.NodeList
    
        if($null -eq $NcNodeList -or $NcNodeList.Count -eq 0){
            Trace-Output "Failed to get NC Node List from NetworkController: $NetworkController" -Level:Error
            return 
        }
    
        Trace-Output "NcNodeList: $($NcNodeList.IpAddressOrFQDN)"
    
        if([String]::IsNullOrEmpty($NcInfraInfo.NcRestName)){
            Trace-Output "Failed to get NcRestName using current secret certificate thumbprint. This might indicate the certificate not found on $NetworkController. We won't be able to recover." -Level:Error
            return
        }else
        {
            $NcRestName = $NcInfraInfo.NcRestName
        }
        
        $NcVMs = $NcNodeList.IpAddressOrFQDN
    
        $certpwdstring = -join ((48..122) | Get-Random -Count 30 | ForEach-Object { [char]$_ })
        Trace-Output "Creating local temp directory." -Level:Verbose
    
        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force
        $TempDir = $TempFile.FullName
        New-Item -ItemType Directory -Force -Path $TempDir | out-null
    
        Trace-Output "Temp directory is: $($TempFile.FullName)" -Level:Verbose
        Trace-Output "Creating REST cert on: $($NcVMs[0])" -Level:Verbose
        # Create NC Rest Cert and import to NC Node's Trusted Root store
        $RestCertPfxData = invoke-command -computername $NcVMs[0] {
            param(
                [String] $RestName,
                [String] $certpwdstring,
                [datetime] $NotAfter
            )
            # function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
            # function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
    
            write-verbose "Creating new REST certificate." 
            $Cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$RESTName" `
                -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 `
                -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") `
                -NotAfter $NotAfter
    
            $TempFile = New-TemporaryFile
            Remove-Item $TempFile.FullName -Force | out-null
            [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
            $CertData = Get-Content $TempFile.FullName -Encoding Byte
            Remove-Item $TempFile.FullName -Force | out-null
    
            write-verbose "Returning Cert Data." 
    
            return ,$CertData
        } -ArgumentList $NcRestName.ToUpper(), $certpwdstring, $NotAfter
        
        $TempFile = New-TemporaryFile
        Remove-Item $TempFile.FullName -Force
        $RestCertPfxData | set-content $TempFile.FullName -Encoding Byte
        $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
        $RESTCertPFX = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\my" -password $certpwd -exportable
        Remove-Item $TempFile.FullName -Force
    
        $RESTCertThumbprint = $RESTCertPFX.Thumbprint
        Trace-Output "REST cert thumbprint: $RESTCertThumbprint"
        Trace-Output "Exporting REST cert to PFX and CER in temp directory." -Level:Verbose
        
        [System.io.file]::WriteAllBytes("$TempDir\$NcRestName.pfx", $RestCertPFX.Export("PFX", $certpwdstring))
        Export-Certificate -Type CERT -FilePath "$TempDir\$RESTName.cer" -cert $RestCertPFX | out-null
        
        Trace-Output "Importing REST cert (public key only) into Root store."
        import-certificate -filepath "$TempDir\$RESTName.cer" -certstorelocation "cert:\localmachine\root" | Out-Null
    
        $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
        if($NcVMs -contains $NodeFQDN){
            Trace-Output "NOT Deleting REST cert from My store as [$(HostName)] is one of the NC VM"
        }else{
            Trace-Output "Deleting REST cert from My store as this is not one of the NC VM"
            Remove-Item -path cert:\localmachine\my\$RESTCertThumbprint
        }
        
    
        Trace-Output "Installing REST cert to my and root store of each NC node."
    
        foreach ($ncnode in $NcVMs) {
            Trace-Output "Installing REST cert to my and root store of: $ncnode"
            invoke-command -computername $ncnode {
                param(
                    [String] $RESTName,
                    [byte[]] $RESTCertPFXData,
                    [String] $RESTCertThumbprint,
                    [String] $certpwdstring
                )
                # function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                # function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
        
                $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
    
                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force
                $RESTCertPFXData | set-content $TempFile.FullName -Encoding Byte
    
                $Cert = get-childitem "Cert:\localmachine\my" | where-object { $_.Subject.ToUpper().StartsWith("CN=$RestName".ToUpper() -and $_.Thumbprint -eq $RESTCertThumbprint) }
                write-verbose "Found $($cert.count) certificate(s) in my store with subject name matching $RESTCertThumbprint"
                if ($null -eq $Cert) {
                    write-verbose "Importing new REST cert into My store."
                    $cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\my" -password $certpwd -Exportable
                }
                else {
                    if ($cert.Thumbprint -ne $RestCertThumbprint) {
                        Remove-Item $TempFile.FullName -Force
                        throw "REST cert already exists in My store on $(hostname), but thumbprint does not match cert on other nodes."
                    }
                }
                
                write-verbose "Setting permissions on REST cert."
                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $RESTCertThumbprint
                <# $targetCertPrivKey = $Cert.PrivateKey 
                $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object { $_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName } 
                $privKeyAcl = Get-Acl $privKeyCertFile
                $permission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow" 
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
                $privKeyAcl.AddAccessRule($accessRule) 
                Set-Acl $privKeyCertFile.FullName $privKeyAcl #>
    
                $Cert = get-childitem "Cert:\localmachine\root\$RestCertThumbprint" -erroraction Ignore
                if ($null -eq $Cert) {
                    write-verbose "REST cert does not yet exist in Root store, adding."
                    $Cert = import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
                }
    
                Remove-Item $TempFile.FullName -Force
            } -Argumentlist $RESTName, $RESTCertPFXData, $RESTCertThumbprint, $certpwdstring
        }
    
        if($NcInfraInfo.ClusterCredentialType -ne "X509")
        {
            Trace-Output "Node Certificate creation skipped for non-certificate ClusterCredentialType"
            return
        }
    
        foreach ($ncVM in $NcVMs) {
            $NcNodeCertPfxData = invoke-command -computername $ncVM {
                param(
                    [String] $certpwdstring,
                    [datetime] $NotAfter
                )
                # function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                # function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
        
                $NodeFQDN = (get-ciminstance win32_computersystem).DNSHostName + "." + (get-ciminstance win32_computersystem).Domain
               
                write-verbose "Creating new self signed certificate in My store."
                $cert = New-SelfSignedCertificate -Type Custom -KeySpec KeyExchange -Subject "CN=$NodeFQDN" `
                    -KeyExportPolicy Exportable -HashAlgorithm sha256 -KeyLength 2048 `
                    -CertStoreLocation "Cert:\LocalMachine\My" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2") `
                    -NotAfter $NotAfter
                write-verbose "Setting permissions on node cert."
                
                Set-SdnCertificateAcl -Path 'Cert:\LocalMachine\My' -Thumbprint $cert.Thumbprint
                
                <# $targetCertPrivKey = $Cert.PrivateKey 
                $privKeyCertFile = Get-Item -path "$ENV:ProgramData\Microsoft\Crypto\RSA\MachineKeys\*"  | where-object { $_.Name -eq $targetCertPrivKey.CspKeyContainerInfo.UniqueKeyContainerName } 
                $privKeyAcl = Get-Acl $privKeyCertFile
                $permission = "NT AUTHORITY\NETWORK SERVICE", "Read", "Allow" 
                $accessRule = new-object System.Security.AccessControl.FileSystemAccessRule $permission 
                $privKeyAcl.AddAccessRule($accessRule) | out-null
                Set-Acl $privKeyCertFile.FullName $privKeyAcl | out-null #>
        
                write-verbose "Exporting node cert."
                $TempFile = New-TemporaryFile
                Remove-Item $TempFile.FullName -Force | out-null
                [System.io.file]::WriteAllBytes($TempFile.FullName, $cert.Export("PFX", $certpwdstring)) | out-null
                $CertData = Get-Content $TempFile.FullName -Encoding Byte
                Remove-Item $TempFile.FullName -Force | out-null
        
                return ,$CertData
            } -ArgumentList $CertPwdString, $NotAfter
    
            $TempFile = New-TemporaryFile
            Remove-Item $TempFile.FullName -Force
            
            $NcNodeCertPfxData | set-content $TempFile.FullName -Encoding Byte
            $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
            # $AllNodeCerts += import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd
            Remove-Item $TempFile.FullName -Force
    
            foreach ($othernode in $NcVMs) {
                Trace-Output "Installing node cert for $ncVM into root store of $othernode."
    
                invoke-command -computername $othernode {
                    param(
                        [String] $CertPwdString,
                        [Byte[]] $CertData
                    )
                    # function private:write-verbose { param([String] $Message) write-output "[V]"; write-output $Message}
                    # function private:write-output { param([PSObject[]] $InputObject) write-output "$($InputObject.count)"; write-output $InputObject}
                        
                    $TempFile = New-TemporaryFile
                    Remove-Item $TempFile.FullName -Force
    
                    $CertData | set-content $TempFile.FullName -Encoding Byte
                    $certpwd = ConvertTo-SecureString $certpwdstring -AsPlainText -Force  
                    import-pfxcertificate -filepath $TempFile.FullName -certstorelocation "cert:\localmachine\root" -password $certpwd | Out-Null
                    Remove-Item $TempFile.FullName -Force
                } -ArgumentList $certPwdString, $NcNodeCertPfxData       
            }
        }
    }
    catch {
        "{0}`n{1}" -f $_.Exception, $_.ScriptStackTrace | Trace-Output -Level:Error
    }
}
