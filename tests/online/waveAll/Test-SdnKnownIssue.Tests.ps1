# Pester tests
Describe 'Test-SdnKnownIssue test' {
    It "Test-SdnKnownIssue run all Known Issues test with no exception" {
        { Test-SdnKnownIssue -NetworkController $Global:PesterOnlineTests.configdata.NcVM -NcRestCredential $Global:PesterOnlineTests.NcRestCredential } | Should -Not -Throw
    }
}
