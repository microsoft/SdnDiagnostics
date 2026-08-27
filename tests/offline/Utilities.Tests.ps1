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

Describe 'Utilities - Object Helpers' {
    Context 'Copy-ObjectWithPropertyOverride' {
        It "Replaces the value of the specified property" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ name = 'original'; value = 1 }
                $result = Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride @{ 'name' = 'updated' }
                $result.name | Should -Be 'updated'
            }
        }

        It "Leaves the properties that were not overridden unchanged" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ name = 'original'; value = 1 }
                $result = Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride @{ 'name' = 'updated' }
                $result.value | Should -Be 1
            }
        }

        It "Matches property names without regard to casing" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ Name = 'original' }
                $result = Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride @{ 'NAME' = 'updated' }
                $result.Name | Should -Be 'updated'
            }
        }

        It "Does not modify the object supplied by the caller" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ name = 'original' }
                $null = Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride @{ 'name' = 'updated' }
                $source.name | Should -Be 'original'
            }
        }

        It "Ignores override entries for properties that do not exist on the object" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ name = 'original' }
                $result = Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride @{ 'missing' = 'value' }
                $result.PSObject.Properties.Name | Should -Be 'name'
                $result.name | Should -Be 'original'
            }
        }

        It "Applies an override that sets the property value to null" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ name = 'original'; value = 1 }
                $result = Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride @{ 'name' = $null }
                $result.PSObject.Properties.Name | Should -Contain 'name'
                $result.name | Should -BeNullOrEmpty
                $result.value | Should -Be 1
            }
        }

        It "Throws when more than one override key matches the same property" {
            InModuleScope SdnDiagnostics {
                $source = [PSCustomObject]@{ name = 'original' }
                $override = [System.Collections.Hashtable]::new()
                $override.Add('name', 'first')
                $override.Add('NAME', 'second')
                { Copy-ObjectWithPropertyOverride -Object $source -PropertyOverride $override } | Should -Throw
            }
        }
    }
}
