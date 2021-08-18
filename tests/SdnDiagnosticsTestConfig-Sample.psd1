@{
    # Required. Specify the one of NC VM Name for tests to start with
    NcVM = 'sdnexpnc01.corp.contoso.com'

    # Configure NcRestCredential if needed
    # NcRestCredentialUser = 'domain\user'

    # The Password need to be secure string from (Get-Credential).Password | ConvertFrom-SecureString
    # NcRestCredentialPassword = 'YourPassword'

    # Required. Specify the SdnDiagnosticsModule Path
    SdnDiagnosticsModule = '<The Path of SdnDiagnostics Module>'

    # The number of each infra node. This will ensure the module able to get information match the test environment. 
    NumberOfNc = 3
    NumberOfMux = 2
    NumberOfServer = 3
    NumberOfGateway = 2
}