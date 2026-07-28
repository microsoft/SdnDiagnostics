---
description: Pester test authoring patterns and conventions for SdnDiagnostics
applyTo: "tests/**/*.ps1,tests/**/*.md"
---

# Pester Test Authoring Instructions

Apply when creating, modifying, or expanding Pester tests for SdnDiagnostics.

## Test Location and Structure

All tests are **offline** (mock-based). No live SDN environment is required.

- Test files: `tests/offline/<ModuleName>.Tests.ps1`
- Mock data: `tests/offline/data/SdnApiResources/*.json`
- Runner: `tests/offline/RunTests.ps1`
- The module must be built first (`.\build.ps1`) before tests can run

## File Naming

| Source Module | Test File |
|---------------|-----------|
| `SdnDiag.Utilities.psm1` | `Utilities.Tests.ps1` |
| `SdnDiag.NetworkController.psm1` | `NetworkController.Tests.ps1` |
| `SdnDiag.LoadBalancerMux.psm1` | `SoftwareLoadBalancer.Tests.ps1` |
| `SdnDiag.Health.psm1` | `Health.Tests.ps1` |
| `SdnDiag.Server.psm1` | `Server.Tests.ps1` |
| `SdnDiag.Gateway.psm1` | `Gateway.Tests.ps1` |

## Mock Data Access

`RunTests.ps1` loads all JSON files into globals before tests execute:

```powershell
# Collection access (returns array of objects)
$Global:PesterOfflineTests.SdnApiResources['servers']
$Global:PesterOfflineTests.SdnApiResources['networkInterfaces']

# Single-resource lookup by resourceRef path
$Global:PesterOfflineTests.SdnApiResourcesByRef['/servers/DVLAB-S1-N01']
```

## Module Scope and Mocking

SdnDiagnostics uses nested modules (SdnDiag.Utilities, SdnDiag.NetworkController, etc.). Each nested module has its own session state. This means:

- **Private/internal functions** (not exported) must be called inside `InModuleScope SdnDiagnostics { ... }`
- **Mocks for functions called within nested modules** must use `InModuleScope <NestedModuleName>` to intercept internal calls
- `Mock -ModuleName SdnDiagnostics` does NOT intercept calls between functions within nested modules

## Three Mock Patterns

### Pattern A: Pure Unit Test (private utility functions)

Use for internal functions that transform input without external calls (Format-*, Confirm-*, Convert-*). These are NOT exported, so `InModuleScope` is required:

```powershell
Describe 'Format-MyFunction' {
    It "Transforms input correctly" {
        InModuleScope SdnDiagnostics {
            $result = Format-MyFunction -Input "test"
            $result | Should -Be "expected"
        }
    }

    It "Handles null gracefully" {
        InModuleScope SdnDiagnostics {
            { Format-MyFunction -Input $null } | Should -Throw
        }
    }
}
```

### Pattern B: Mock Invoke-RestMethodWithRetry (NC REST functions)

Use for any function that internally queries the Network Controller REST API. Mock `Invoke-RestMethodWithRetry` inside `InModuleScope SdnDiag.NetworkController` to intercept the HTTP call:

```powershell
Describe 'Get-SdnMyResource' {
    It "Returns resources from NC" {
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

**Key points:**
- The mock must be inside `InModuleScope SdnDiag.NetworkController` (where the functions live)
- Always use `-NcUri` as a named parameter (it is NOT positional)
- The mock handles both collection requests (returns `{value: [...]}`) and single-resource lookups (returns the object directly via `SdnApiResourcesByRef`)

### Pattern C: Mock Remote Commands

Use for functions that execute commands on remote hosts via `Invoke-PSRemoteCommand`:

```powershell
Describe 'Get-SdnMyRemoteData' {
    It "Processes remote output" {
        InModuleScope SdnDiag.Server {
            Mock Invoke-PSRemoteCommand {
                return @{ Status = "OK"; Data = "mocked-response" }
            }
            $result = Get-SdnMyRemoteData -ComputerName "DVLAB-S1-N01"
            $result.Status | Should -Be "OK"
        }
    }
}
```

## Mock Data Naming Conventions

All mock data uses a consistent fictional deployment:

| Element | Convention |
|---------|-----------|
| Deployment prefix | `DVLAB` |
| Domain | `dvlab.contoso.local` |
| Hyper-V servers | `DVLAB-S1-N01` through `DVLAB-S1-N04` |
| Network Controllers | `DVLAB-NC01` through `DVLAB-NC03` |
| NC URI | `https://dvlab-nc.dvlab.contoso.local` |
| Gateways | `DVLAB-GW01` through `DVLAB-GW03` |
| Muxes | `DVLAB-MUX01`, `DVLAB-MUX02` |

**Rules:**
- Never use real customer data or deployment names
- Keep naming consistent across all JSON files (same server name everywhere)
- IP addresses may use any RFC1918 range without randomization
- DVLAB-S1-N04 is intentionally in `Failed` state for health-detection tests

## Adding Mock Data

JSON files use the NC REST API response wrapper format:

```json
{
  "value": [
    {
      "resourceRef": "/resourceType/resource-id-0001",
      "resourceId": "resource-id-0001",
      "properties": {
        "provisioningState": "Succeeded"
      }
    }
  ],
  "nextLink": ""
}
```

**Exception:** Singleton configuration resources (e.g., `iDNSServer_configuration.json`, `loadBalancerManager_config.json`) use the raw object without the `value` wrapper. `RunTests.ps1` handles both formats automatically.

The filename (minus `.json`) becomes the lookup key in `$Global:PesterOfflineTests.SdnApiResources`.

## Test Design Rules

1. **One behavior per `It` block** — test one logical behavior; multiple related assertions on the same result are fine
2. **Test both success and failure paths** — include resources with Failed state
3. **Descriptive test names** — describe WHAT is validated ("Returns 4 servers"), not HOW
4. **Independent Describe blocks** — no cross-block state dependencies
5. **Mock + call inside the same `InModuleScope` block** — never separate them; `BeforeAll` mocks do not cross `InModuleScope` boundaries
6. **Use Pester v5+ syntax** — `Should -Be`, not legacy `Should Be`
7. **Tag tests** when grouping: `Describe 'My Test' -Tag 'Unit' { ... }`

## Running Tests

```powershell
# Build the module first
.\build.ps1

# Run all offline tests
cd tests\offline
.\RunTests.ps1

# Run a specific file
.\RunTests.ps1 -TestFile ".\Utilities.Tests.ps1"

# Run by tag
.\RunTests.ps1 -Tag "Unit"
```

## CI Pipeline

Tests run automatically via `.github/workflows/pester-tests.yml` on every PR and push to main. A failing test blocks the PR.

## Key Test Scenarios in Mock Data

- **Healthy resources:** DVLAB-S1-N01 through N03 (provisioningState: Succeeded)
- **Unhealthy resource:** DVLAB-S1-N04 (provisioningState: Failed, configurationState: Failure)
- **Outbound NAT chain:** tenantvm2 → lb-outbound-0001/OutboundNatPool → pip-outbound-0001 (40.40.40.4)
- **Direct VIP:** tenantvm1 → publicIPAddress → pip-tenant-0001 (40.40.40.5)
- **MAC pools:** Pool with range 00-11-22-00-00-00 to 00-11-22-FF-FF-FF
