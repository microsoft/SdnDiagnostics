# Contributing Pester Tests

This guide explains how to add new Pester tests to the SdnDiagnostics project.

## Test Categories

| Category | Location | When to Use |
|----------|----------|-------------|
| **Offline** | `tests/offline/` | Function can be tested with mocked data, no live SDN deployment needed |

**All tests should be offline.** If a function's behavior can be validated through mocking, write an offline test.

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

**JSON file format:** Each file wraps data in `{ "value": [...], "nextLink": "" }` matching the NC REST API response format. Singleton configuration resources (e.g., iDNS) may use a raw object without the `value` wrapper — `RunTests.ps1` handles both formats.

### Step 3: Understand the Module Architecture

SdnDiagnostics uses **nested modules** (`NestedModules` in the manifest). Each nested module has its own session state. This is critical for mocking:

- **Private/internal functions** (e.g., `Format-*`, `Confirm-*`) are NOT exported — you must use `InModuleScope SdnDiagnostics { ... }` to access them
- **Functions in nested modules** (e.g., `Get-SdnServer` in `SdnDiag.NetworkController`) execute in their nested module's scope — mocks must be placed in THAT scope
- **Cross-module calls** (e.g., Health → NetworkController) require mocking the called function in the caller's module scope

### Step 4: Write Your Test

#### Pattern A: Pure Unit Tests (private/internal functions)

For private functions that are not exported (e.g., `Format-MacAddressWithDashes`, `Confirm-IsAdmin`):

```powershell
Describe 'Utilities - Format-MyFunction' {
    It "Returns expected output for valid input" {
        InModuleScope SdnDiagnostics {
            $result = Format-MyFunction -Input "test"
            $result | Should -Be "expected"
        }
    }

    It "Throws on invalid input" {
        InModuleScope SdnDiagnostics {
            { Format-MyFunction -Input $null } | Should -Throw
        }
    }
}
```

#### Pattern B: NC REST functions (mock Invoke-RestMethodWithRetry)

For functions in `SdnDiag.NetworkController` that call `Invoke-RestMethodWithRetry`:

```powershell
Describe 'NetworkController - Get-SdnMyResource' {
    It "Returns resources" {
        InModuleScope SdnDiag.NetworkController {
            Mock Invoke-RestMethodWithRetry {
                $path = ([Uri]$Uri).AbsolutePath
                if ($path -match '/networking/v1/(.+)$') {
                    $resourceType = ($Matches[1] -split '/')[0]
                    $refKey = "/$($Matches[1])"
                    if ($Global:PesterOfflineTests.SdnApiResourcesByRef.ContainsKey($refKey)) {
                        return $Global:PesterOfflineTests.SdnApiResourcesByRef[$refKey]
                    }
                    return [PSCustomObject]@{ value = $Global:PesterOfflineTests.SdnApiResources[$resourceType] }
                }
            }
            $result = Get-SdnMyResource -NcUri "https://dvlab-nc.dvlab.contoso.local"
            $result | Should -Not -BeNullOrEmpty
        }
    }
}
```

**Why this pattern?** `Get-SdnServer` → `Get-SdnResource` → `Invoke-RestMethodWithRetry` all execute within `SdnDiag.NetworkController`'s session state. The mock must be injected into THAT scope. Mocking at the parent module level (`-ModuleName SdnDiagnostics`) does NOT intercept calls between functions within nested modules.

#### Pattern C: Health functions (invoke via InModuleScope with mocked Get-SdnResource)

Health functions (`Test-SdnResourceProvisioningState`, `Test-SdnResourceConfigurationState`) call
`Get-SdnResource` (imported from `SdnDiag.NetworkController`) and `Trace-Output` (from
`SdnDiag.Utilities`). Both are available in `SdnDiag.Health`'s session state because Health
explicitly imports those modules at the top of `SdnDiag.Health.psm1`.

Mock `Get-SdnResource` inside `InModuleScope SdnDiag.Health` to intercept calls made by the
health functions, and then invoke the health functions directly to validate their returned result:

```powershell
Describe 'Health - Test-SdnResourceProvisioningState' {
    It "Returns FAIL for a resource with Failed provisioning state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N04']
            }
            $result = Test-SdnResourceProvisioningState -Resource 'Servers' -ResourceId 'DVLAB-S1-N04' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'FAIL'
        }
    }

    It "Returns PASS for a resource with Succeeded provisioning state" {
        InModuleScope SdnDiag.Health {
            Mock Get-SdnResource {
                return $Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N01']
            }
            $result = Test-SdnResourceProvisioningState -Resource 'Servers' -ResourceId 'DVLAB-S1-N01' -NcUri 'https://dvlab-nc.dvlab.contoso.local'
            $result.Result | Should -Be 'PASS'
        }
    }
}
```

**Why this pattern works:** `SdnDiag.Health.psm1` imports `SdnDiag.NetworkController.psm1` at module
load time, so `Get-SdnResource` is available in Health's session state. `Mock Get-SdnResource`
inside `InModuleScope SdnDiag.Health` replaces it in that scope, intercepting calls from health
functions. The health function logic (switch statements, result assignment, remediation) then runs
against the mocked data and returns a real health-test object that tests can assert against.

#### Pattern D: Remote command functions

For functions using `Invoke-PSRemoteCommand`:

```powershell
Describe 'Server - Get-SdnMyRemoteData' {
    It "Returns remote data" {
        InModuleScope SdnDiag.Server {
            Mock Invoke-PSRemoteCommand {
                return @{ Status = "OK"; Data = "mocked" }
            }
            $result = Get-SdnMyRemoteData -ComputerName "DVLAB-S1-N01"
            $result.Status | Should -Be "OK"
        }
    }
}
```

### Step 5: Add Mock Data (if needed)

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

### Step 6: Run Your Tests

```powershell
# Run all offline tests
cd tests\offline
.\RunTests.ps1

# Run a specific test file
.\RunTests.ps1 -TestFile ".\Utilities.Tests.ps1"
```

**Prerequisites:**
- Pester v5+: `Install-Module -Name Pester -Force -SkipPublisherCheck`
- Build the module first: run the build script to populate `out/build/`

## Test Design Guidelines

1. **One behavior per `It` block** — test one logical behavior; multiple related assertions on the same result are fine (e.g., checking both count and a property)
2. **Test both happy path and error cases** — include boundary conditions
3. **Use descriptive test names** — describe what the test validates, not how
4. **Include a Failed/Unhealthy resource** in mock data — tests should validate detection of problems
5. **Don't depend on test execution order** — each `Describe` block should be independent
6. **Mock + call inside the same InModuleScope block** — never separate them
7. **Use `@(...)` for counts** — when filtering with `Where-Object`, wrap in `@()` before checking `.Count` (single-result gotcha)

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

