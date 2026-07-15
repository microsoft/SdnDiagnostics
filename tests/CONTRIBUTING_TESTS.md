# Contributing Pester Tests

This guide explains how to add new Pester tests to the SdnDiagnostics project.

## Test Categories

| Category | Location | When to Use |
|----------|----------|-------------|
| **Offline** | `tests/offline/` | Function can be tested with mocked data, no live SDN deployment needed |
| **Online** | `tests/online/wave1/` or `waveAll/` | Function requires a live SDN deployment |

**Prefer offline tests.** If a function's behavior can be validated through mocking, write an offline test.

## Adding a New Offline Test

### Step 1: Choose or Create a Test File

Test files are named after the module they test:

| Module | Test File |
|--------|-----------|
| `SdnDiag.Utilities.psm1` | `Utilities.Tests.ps1` |
| `SdnDiag.NetworkController.psm1` | `NetworkController.Tests.ps1` |
| `SdnDiag.LoadBalancerMux.psm1` | `SoftwareLoadBalancer.Tests.ps1` |
| `SdnDiag.Health.psm1` | `Health.Tests.ps1` |
| `SdnDiag.Server.psm1` | `Server.Tests.ps1` |
| `SdnDiag.Gateway.psm1` | `Gateway.Tests.ps1` |

If your function belongs to a module without a test file, create one following the naming pattern `<ModuleName>.Tests.ps1`.

### Step 2: Understand the Mock Data Structure

Mock data lives in `tests/offline/data/SdnApiResources/`. The `RunTests.ps1` script loads all JSON files into a global hashtable:

```powershell
$Global:PesterOfflineTests.SdnApiResources['servers']          # Array of server objects
$Global:PesterOfflineTests.SdnApiResources['gateways']         # Array of gateway objects
$Global:PesterOfflineTests.SdnApiResources['networkInterfaces'] # Array of NIC objects
# etc.

$Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N01']  # Lookup by resourceRef
```

**JSON file format:** Each file wraps data in `{ "value": [...], "nextLink": "" }` matching the NC REST API response format.

### Step 3: Write Your Test

#### Pattern A: Pure Unit Tests (no mocking needed)

For functions that accept input and return output without external dependencies:

```powershell
Describe 'Utilities - My New Function' {
    It "Returns expected output for valid input" {
        $result = My-Function -Parameter "value"
        $result | Should -Be "expected"
    }

    It "Throws on invalid input" {
        { My-Function -Parameter $null } | Should -Throw
    }
}
```

#### Pattern B: Functions that call Get-SdnResource

Most NC-querying functions internally call `Get-SdnResource`. Mock it to return test data:

```powershell
Describe 'NetworkController - My-NewFunction' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Get-SdnResource {
            if (![string]::IsNullOrEmpty($ResourceRef)) {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef[$ResourceRef]
            }
            else {
                return $Global:PesterOfflineTests.SdnApiResources[$ResourceType.ToString()]
            }
        }
    }

    It "Returns expected data" {
        $result = My-NewFunction -NcUri "https://dvlab-nc.dvlab.contoso.local"
        $result | Should -Not -BeNullOrEmpty
    }
}
```

#### Pattern C: Functions that call remote commands

For functions using `Invoke-PSRemoteCommand` or `Invoke-Command`:

```powershell
Describe 'Server - My-RemoteFunction' {
    BeforeAll {
        Mock -ModuleName SdnDiagnostics Invoke-PSRemoteCommand {
            # Return what the remote command would return
            return @{ Status = "OK"; Data = "mocked" }
        }
    }

    It "Processes remote data correctly" {
        $result = My-RemoteFunction -ComputerName "DVLAB-S1-N01"
        $result.Status | Should -Be "OK"
    }
}
```

### Step 4: Add Mock Data (if needed)

If your test needs data not currently in `data/SdnApiResources/`:

1. **Edit the appropriate JSON file** in `tests/offline/data/SdnApiResources/`
2. **Follow naming conventions:**
   - Deployment prefix: `DVLAB`
   - Domain: `dvlab.contoso.local`
   - Servers: `DVLAB-S1-N01` through `DVLAB-S1-N04`
   - Network Controllers: `DVLAB-NC01` through `DVLAB-NC03`
   - Gateways: `DVLAB-GW01` through `DVLAB-GW03`
   - Muxes: `DVLAB-MUX01` through `DVLAB-MUX02`
3. **Keep names consistent** — if you reference `DVLAB-S1-N01` in one file, use the same name everywhere
4. **IP addresses** may use any RFC1918 range — they don't need randomizing
5. **Never use real customer data** — use the `DVLAB` prefix pattern

#### Adding a new resource type

If you need a resource type not currently in the data folder:

```json
{
  "value": [
    {
      "resourceRef": "/yourResourceType/resource-id-0001",
      "resourceId": "resource-id-0001",
      "etag": "W/\"your-etag-0001\"",
      "instanceId": "your-instance-0001-aaaa-bbbb-cccccccccccc",
      "properties": {
        "provisioningState": "Succeeded"
      }
    }
  ],
  "nextLink": ""
}
```

The file name (minus `.json`) becomes the key in `$Global:PesterOfflineTests.SdnApiResources`.

### Step 5: Run Your Tests

```powershell
# Run all offline tests
cd tests\offline
.\RunTests.ps1

# Run a specific test file
.\RunTests.ps1 -TestFile ".\Utilities.Tests.ps1"

# Run tests matching a tag
.\RunTests.ps1 -Tag "Unit"
```

**Prerequisites:**
- Pester v5+: `Install-Module -Name Pester -Force -SkipPublisherCheck`
- Build the module first: run the build script to populate `out/build/`

## Test Design Guidelines

1. **One assertion per `It` block** — makes failures easy to identify
2. **Test both happy path and error cases** — include boundary conditions
3. **Use descriptive test names** — describe what the test validates, not how
4. **Include a Failed/Unhealthy resource** in mock data — tests should validate detection of problems
5. **Don't depend on test execution order** — each `Describe` block should be independent
6. **Use `BeforeAll` for shared mocks** — not `BeforeEach` (avoids repeated setup)

## Mock Data Reference

### Current test environment (DVLAB)

| Resource | Count | Names |
|----------|-------|-------|
| Servers | 4 | DVLAB-S1-N01 through N04 (N04 is in Failed state) |
| Gateways | 3 | DVLAB-GW01 through GW03 |
| Muxes | 2 | DVLAB-MUX01, DVLAB-MUX02 |
| Virtual Servers | 5 | DVLAB-GW01–03, DVLAB-MUX01–02 |
| Network Interfaces | 4 | tenantvm1, tenantvm2, nic-vm01-0001, nic-vm02-0002 |
| Load Balancers | 1 | lb-outbound-0001 (with OutboundNatPool) |
| Virtual Networks | 1 | vnet-0001 (192.168.33.0/24) |
| Public IPs | 3 | gw-vip-0001, pip-tenant-0001, pip-outbound-0001 |

### Key test scenarios built into mock data

- **Happy path:** DVLAB-S1-N01 through N03 are healthy (Succeeded/Success)
- **Failure detection:** DVLAB-S1-N04 has `provisioningState: Failed` and `configurationState: Failure`
- **Outbound NAT:** tenantvm2 is in `OutboundNatPool` → resolves to pip-outbound-0001 (40.40.40.4)
- **Direct VIP:** tenantvm1 has publicIPAddress → resolves to pip-tenant-0001 (40.40.40.5)

## Online Tests

Online tests require a live SDN deployment. See `tests/online/SdnDiagnosticsTestConfig-Sample.psd1` for configuration.

- Place tests in `wave1/` if execution order matters (runs first)
- Place tests in `waveAll/` if order doesn't matter
- Use `$Global:PesterOnlineTests.ConfigData` for environment-specific values
