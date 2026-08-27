Describe 'Utilities - Format Functions' {
    Context 'Format-MacAddressWithDashes' {
        It "Converts 12-char MAC to dashed format" {
            InModuleScope SdnDiagnostics {
                $result = Format-MacAddressWithDashes -MacAddress "001DD8070001"
                $result | Should -Be "00-1D-D8-07-00-01"
            }
        }

        It "Normalizes lowercase to uppercase" {
            InModuleScope SdnDiagnostics {
                $result = Format-MacAddressWithDashes -MacAddress "001dd8070001"
                $result | Should -Be "00-1D-D8-07-00-01"
            }
        }

        It "Passes through already-dashed MAC unchanged (uppercased)" {
            InModuleScope SdnDiagnostics {
                $result = Format-MacAddressWithDashes -MacAddress "00-1D-D8-07-00-01"
                $result | Should -Be "00-1D-D8-07-00-01"
            }
        }

        It "Throws on invalid length (not 12 chars, no dashes)" {
            InModuleScope SdnDiagnostics {
                { Format-MacAddressWithDashes -MacAddress "001DD807" } | Should -Throw
            }
        }

        It "Throws on invalid dashed format (wrong segment length)" {
            InModuleScope SdnDiagnostics {
                { Format-MacAddressWithDashes -MacAddress "001-DD8-070-001-00-01" } | Should -Throw
            }
        }
    }

    Context 'Format-MacAddressNoDashes' {
        It "Removes dashes from valid MAC address" {
            InModuleScope SdnDiagnostics {
                $result = Format-MacAddressNoDashes -MacAddress "00-1D-D8-07-00-01"
                $result | Should -Be "001DD8070001"
            }
        }

        It "Returns uppercase when already no dashes" {
            InModuleScope SdnDiagnostics {
                $result = Format-MacAddressNoDashes -MacAddress "001dd8070001"
                $result | Should -Be "001DD8070001"
            }
        }

        It "Throws on invalid dashed format (wrong segment length)" {
            InModuleScope SdnDiagnostics {
                { Format-MacAddressNoDashes -MacAddress "001-DD8-070-001-00-01" } | Should -Throw
            }
        }
    }

    Context 'Format-SdnMacAddress' {
        It "Without -Dashes returns no-dash format" {
            InModuleScope SdnDiagnostics {
                $result = Format-SdnMacAddress -MacAddress "00-1D-D8-07-00-01"
                $result | Should -Be "001DD8070001"
            }
        }

        It "With -Dashes returns dashed format" {
            InModuleScope SdnDiagnostics {
                $result = Format-SdnMacAddress -MacAddress "001DD8070001" -Dashes
                $result | Should -Be "00-1D-D8-07-00-01"
            }
        }
    }

    Context 'Format-ByteSize' {
        It "Converts bytes to GB and MB" {
            InModuleScope SdnDiagnostics {
                $result = Format-ByteSize -Bytes 1073741824
                $result.GB | Should -Be "1"
                $result.MB | Should -Be "1024"
            }
        }

        It "Handles zero bytes" {
            InModuleScope SdnDiagnostics {
                $result = Format-ByteSize -Bytes 0
                $result.GB | Should -Be "0"
                $result.MB | Should -Be "0"
            }
        }
    }

    Context 'Format-KiloBitSize' {
        It "Converts kilobits to GB and MB" {
            InModuleScope SdnDiagnostics {
                $result = Format-KiloBitSize -KiloBits 1000000
                $result.GB | Should -Be "1"
                $result.MB | Should -Be "1000"
            }
        }

        It "Handles zero kilobits" {
            InModuleScope SdnDiagnostics {
                $result = Format-KiloBitSize -KiloBits 0
                $result.GB | Should -Be "0"
                $result.MB | Should -Be "0"
            }
        }
    }
}

Describe 'Utilities - IP Address Validation' {
    Context 'Confirm-IpAddressInRange' {
        It "Returns true when IP is within range" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInRange -IpAddress "192.168.1.50" -StartAddress "192.168.1.1" -EndAddress "192.168.1.100"
                $result | Should -BeTrue
            }
        }

        It "Returns true when IP equals start address" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInRange -IpAddress "192.168.1.1" -StartAddress "192.168.1.1" -EndAddress "192.168.1.100"
                $result | Should -BeTrue
            }
        }

        It "Returns false when IP is above range" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInRange -IpAddress "192.168.1.101" -StartAddress "192.168.1.1" -EndAddress "192.168.1.100"
                $result | Should -BeFalse
            }
        }

        It "Returns false when IP is null or empty" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInRange -IpAddress "" -StartAddress "192.168.1.1" -EndAddress "192.168.1.100"
                $result | Should -BeFalse
            }
        }
    }

    Context 'Confirm-IpAddressInCidrRange' {
        It "Returns true for IP within /24 network" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInCidrRange -IpAddress "10.20.30.50" -Cidr "10.20.30.0/24"
                $result | Should -BeTrue
            }
        }

        It "Returns false for IP outside /24 network" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInCidrRange -IpAddress "10.20.31.1" -Cidr "10.20.30.0/24"
                $result | Should -BeFalse
            }
        }

        It "Returns true for exact match on /32" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInCidrRange -IpAddress "10.20.30.5" -Cidr "10.20.30.5/32"
                $result | Should -BeTrue
            }
        }

        It "Returns false for non-match on /32" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInCidrRange -IpAddress "10.20.30.6" -Cidr "10.20.30.5/32"
                $result | Should -BeFalse
            }
        }

        It "Returns true for any IP within /0 (matches all addresses)" {
            InModuleScope SdnDiagnostics {
                $result = Confirm-IpAddressInCidrRange -IpAddress "192.168.1.1" -Cidr "0.0.0.0/0"
                $result | Should -BeTrue
            }
        }
    }
}


Describe 'New-PSRemotingSession - WinRM over HTTPS' -Tag 'Unit' {
    Context 'Port defaults' {
        It "Uses port 5985 by default (HTTP)" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession { return @() }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-Test'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 1
                    }
                }

                New-PSRemotingSession -ComputerName 'DVLAB-S1-N01'

                Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                    $Port -eq 5985 -and (-not $UseSSL)
                }
            }
        }

        It "Uses port 5986 when -UseSSL is specified" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession { return @() }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-Test'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 1
                    }
                }

                New-PSRemotingSession -ComputerName 'DVLAB-S1-N01' -UseSSL

                Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                    $Port -eq 5986 -and $UseSSL -eq $true
                }
            }
        }

        It "Uses custom port when -Port is specified with -UseSSL" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession { return @() }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-Test'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 1
                    }
                }

                New-PSRemotingSession -ComputerName 'DVLAB-S1-N01' -UseSSL -Port 5988

                Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                    $Port -eq 5988 -and $UseSSL -eq $true
                }
            }
        }
    }

    Context 'Global config UseSSL and Port' {
        It "Reads UseSSL from global config when not explicitly passed" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession { return @() }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-Test'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 1
                    }
                }

                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 0
                try {
                    New-PSRemotingSession -ComputerName 'DVLAB-S1-N01'

                    Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                        $Port -eq 5986 -and $UseSSL -eq $true
                    }
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }

        It "Reads Port from global config when not explicitly passed" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession { return @() }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-Test'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 1
                    }
                }

                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 5987
                try {
                    New-PSRemotingSession -ComputerName 'DVLAB-S1-N01'

                    Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                        $Port -eq 5987 -and $UseSSL -eq $true
                    }
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }
    }

    Context 'Session cache reuse' {
        It "Does not reuse a cached HTTP/5985 session when -UseSSL -Port 5986 is requested" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession {
                    return @(
                        [PSCustomObject]@{
                            Name         = 'SdnDiag-Cached'
                            ComputerName = 'DVLAB-S1-N01'
                            State        = 'Opened'
                            Availability = 'Available'
                            Id           = 1
                            Runspace     = [PSCustomObject]@{
                                ConnectionInfo = [PSCustomObject]@{
                                    Port   = 5985
                                    UseSSL = $false
                                }
                            }
                        }
                    )
                }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-New'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 2
                    }
                }

                New-PSRemotingSession -ComputerName 'DVLAB-S1-N01' -UseSSL -Port 5986

                Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                    $Port -eq 5986 -and $UseSSL -eq $true
                }
            }
        }

        It "Does not reuse a cached HTTP/5985 session when a custom -Port is requested" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession {
                    return @(
                        [PSCustomObject]@{
                            Name         = 'SdnDiag-Cached'
                            ComputerName = 'DVLAB-S1-N01'
                            State        = 'Opened'
                            Availability = 'Available'
                            Id           = 1
                            Runspace     = [PSCustomObject]@{
                                ConnectionInfo = [PSCustomObject]@{
                                    Port   = 5985
                                    UseSSL = $false
                                }
                            }
                        }
                    )
                }
                Mock New-PSSession {
                    return [PSCustomObject]@{
                        Name         = 'SdnDiag-New'
                        ComputerName = $ComputerName
                        State        = 'Opened'
                        Availability = 'Available'
                        Id           = 2
                    }
                }

                New-PSRemotingSession -ComputerName 'DVLAB-S1-N01' -Port 5987

                Should -Invoke New-PSSession -Times 1 -ParameterFilter {
                    $Port -eq 5987 -and (-not $UseSSL)
                }
            }
        }

        It "Reuses a cached session when ComputerName, Port, and UseSSL all match" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Get-PSSession {
                    return @(
                        [PSCustomObject]@{
                            Name         = 'SdnDiag-Cached'
                            ComputerName = 'DVLAB-S1-N01'
                            State        = 'Opened'
                            Availability = 'Available'
                            Id           = 1
                            Runspace     = [PSCustomObject]@{
                                ConnectionInfo = [PSCustomObject]@{
                                    Port   = 5986
                                    UseSSL = $true
                                }
                            }
                        }
                    )
                }
                Mock New-PSSession { throw "New-PSSession should not be invoked when a matching cached session exists" }

                New-PSRemotingSession -ComputerName 'DVLAB-S1-N01' -UseSSL -Port 5986

                Should -Invoke New-PSSession -Times 0
            }
        }
    }
}

Describe 'Invoke-PSRemoteCommand forwards UseSSL and Port' -Tag 'Unit' {
    It "Passes UseSSL and Port to New-PSRemotingSession" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock New-PSRemotingSession { return $null }

            Invoke-PSRemoteCommand -ComputerName 'DVLAB-S1-N01' -ScriptBlock { hostname } -UseSSL -Port 5988

            Should -Invoke New-PSRemotingSession -Times 1 -ParameterFilter {
                $UseSSL -eq $true -and $Port -eq 5988
            }
        }
    }

    It "Does not pass UseSSL or Port when not specified" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            $script:sessionBoundParameters = $null
            Mock New-PSRemotingSession {
                $script:sessionBoundParameters = $PesterBoundParameters
                return $null
            }

            Invoke-PSRemoteCommand -ComputerName 'DVLAB-S1-N01' -ScriptBlock { hostname }

            $script:sessionBoundParameters.ContainsKey('UseSSL') | Should -BeFalse
            $script:sessionBoundParameters.ContainsKey('Port') | Should -BeFalse
        }
    }
}

Describe 'Copy-FileFromRemoteComputerWinRM forwards UseSSL and Port' -Tag 'Unit' {
    It "Passes UseSSL and Port to New-PSRemotingSession" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock New-PSRemotingSession { return $null }

            { Copy-FileFromRemoteComputerWinRM -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp' -UseSSL -Port 5988 } | Should -Throw

            Should -Invoke New-PSRemotingSession -Times 1 -ParameterFilter {
                $UseSSL -eq $true -and $Port -eq 5988
            }
        }
    }

    It "Does not pass UseSSL or Port when not specified" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock New-PSRemotingSession { return $null }

            { Copy-FileFromRemoteComputerWinRM -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp' } | Should -Throw

            Should -Invoke New-PSRemotingSession -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL') -and -not $PesterBoundParameters.ContainsKey('Port')
            }
        }
    }
}

Describe 'Copy-FileToRemoteComputerWinRM forwards UseSSL and Port' -Tag 'Unit' {
    It "Passes UseSSL and Port to New-PSRemotingSession" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock New-PSRemotingSession { return $null }

            { Copy-FileToRemoteComputerWinRM -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp' -UseSSL -Port 5988 } | Should -Throw

            Should -Invoke New-PSRemotingSession -Times 1 -ParameterFilter {
                $UseSSL -eq $true -and $Port -eq 5988
            }
        }
    }

    It "Does not pass UseSSL or Port when not specified" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock New-PSRemotingSession { return $null }

            { Copy-FileToRemoteComputerWinRM -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp' } | Should -Throw

            Should -Invoke New-PSRemotingSession -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL') -and -not $PesterBoundParameters.ContainsKey('Port')
            }
        }
    }
}

Describe 'Install-SdnDiagnostics forwards UseSSL and Port' -Tag 'Unit' {
    Context 'Version probe (Invoke-Command)' {
        It "Passes explicit UseSSL and Port to Invoke-Command" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Get-Module { [PSCustomObject]@{ Version = [Version]'1.2.3'; ModuleBase = 'C:\Module' } }
                Mock Invoke-Command { return '1.2.3' }
                Mock Copy-FileToRemoteComputer {}
                Mock Remove-PSRemotingSession {}

                Install-SdnDiagnostics -ComputerName 'DVLAB-S1-N01' -Path '/tmp/SdnDiagnostics' -UseSSL -Port 5988

                Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                    $UseSSL -eq $true -and $Port -eq 5988
                }
            }
        }

        It "Falls back to global config UseSSL and Port when not explicitly passed" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Get-Module { [PSCustomObject]@{ Version = [Version]'1.2.3'; ModuleBase = 'C:\Module' } }
                Mock Invoke-Command { return '1.2.3' }
                Mock Copy-FileToRemoteComputer {}
                Mock Remove-PSRemotingSession {}

                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 5987

                try {
                    Install-SdnDiagnostics -ComputerName 'DVLAB-S1-N01' -Path '/tmp/SdnDiagnostics'

                    Should -Invoke Invoke-Command -Times 1 -ParameterFilter {
                        $UseSSL -eq $true -and $Port -eq 5987
                    }
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }
    }

    Context 'WinRM copy fallback (Copy-FileToRemoteComputer)' {
        It "Passes explicit UseSSL and Port to Copy-FileToRemoteComputer" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Get-Module { [PSCustomObject]@{ Version = [Version]'1.2.3'; ModuleBase = 'C:\Module' } }
                Mock Copy-FileToRemoteComputer {}
                Mock Remove-PSRemotingSession {}

                Install-SdnDiagnostics -ComputerName 'DVLAB-S1-N01' -Path '/tmp/SdnDiagnostics' -Force -UseSSL -Port 5988

                Should -Invoke Copy-FileToRemoteComputer -Times 1 -ParameterFilter {
                    $UseSSL -eq $true -and $Port -eq 5988
                }
            }
        }

        It "Falls back to global config UseSSL and Port when not explicitly passed" {
            InModuleScope SdnDiag.Utilities {
                Mock Trace-Output {}
                Mock Test-ComputerNameIsLocal { return $false }
                Mock Get-Module { [PSCustomObject]@{ Version = [Version]'1.2.3'; ModuleBase = 'C:\Module' } }
                Mock Copy-FileToRemoteComputer {}
                Mock Remove-PSRemotingSession {}

                $Global:SdnDiagnostics.Config.UseSSL = $true
                $Global:SdnDiagnostics.Config.Port = 5987

                try {
                    Install-SdnDiagnostics -ComputerName 'DVLAB-S1-N01' -Path '/tmp/SdnDiagnostics' -Force

                    Should -Invoke Copy-FileToRemoteComputer -Times 1 -ParameterFilter {
                        $UseSSL -eq $true -and $Port -eq 5987
                    }
                }
                finally {
                    $Global:SdnDiagnostics.Config.UseSSL = $false
                    $Global:SdnDiagnostics.Config.Port = 0
                }
            }
        }
    }
}

Describe 'Invoke-SdnCommand forwards UseSSL and Port' -Tag 'Unit' {
    It "Passes UseSSL and Port to Invoke-PSRemoteCommand" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock Invoke-PSRemoteCommand {}

            Invoke-SdnCommand -ComputerName 'DVLAB-S1-N01' -ScriptBlock { hostname } -UseSSL -Port 5988

            Should -Invoke Invoke-PSRemoteCommand -Times 1 -ParameterFilter {
                $UseSSL -eq $true -and $Port -eq 5988
            }
        }
    }

    It "Does not pass UseSSL or Port when not specified" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock Invoke-PSRemoteCommand {}

            Invoke-SdnCommand -ComputerName 'DVLAB-S1-N01' -ScriptBlock { hostname }

            Should -Invoke Invoke-PSRemoteCommand -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL') -and -not $PesterBoundParameters.ContainsKey('Port')
            }
        }
    }
}

Describe 'Copy-SdnFileFromComputer forwards UseSSL and Port' -Tag 'Unit' {
    It "Passes UseSSL and Port to Copy-FileFromRemoteComputer" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock Copy-FileFromRemoteComputer {}

            Copy-SdnFileFromComputer -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp' -UseSSL -Port 5988

            Should -Invoke Copy-FileFromRemoteComputer -Times 1 -ParameterFilter {
                $UseSSL -eq $true -and $Port -eq 5988
            }
        }
    }

    It "Does not pass UseSSL or Port when not specified" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock Copy-FileFromRemoteComputer {}

            Copy-SdnFileFromComputer -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp'

            Should -Invoke Copy-FileFromRemoteComputer -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL') -and -not $PesterBoundParameters.ContainsKey('Port')
            }
        }
    }
}

Describe 'Copy-SdnFileToComputer forwards UseSSL and Port' -Tag 'Unit' {
    It "Passes UseSSL and Port to Copy-FileToRemoteComputer" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock Copy-FileToRemoteComputer {}

            Copy-SdnFileToComputer -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp' -UseSSL -Port 5988

            Should -Invoke Copy-FileToRemoteComputer -Times 1 -ParameterFilter {
                $UseSSL -eq $true -and $Port -eq 5988
            }
        }
    }

    It "Does not pass UseSSL or Port when not specified" {
        InModuleScope SdnDiag.Utilities {
            Mock Trace-Output {}
            Mock Copy-FileToRemoteComputer {}

            Copy-SdnFileToComputer -Path 'C:\test.txt' -ComputerName 'DVLAB-S1-N01' -Destination '/tmp'

            Should -Invoke Copy-FileToRemoteComputer -Times 1 -ParameterFilter {
                -not $PesterBoundParameters.ContainsKey('UseSSL') -and -not $PesterBoundParameters.ContainsKey('Port')
            }
        }
    }
}
