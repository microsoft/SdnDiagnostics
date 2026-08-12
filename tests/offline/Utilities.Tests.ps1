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
