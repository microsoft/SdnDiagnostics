---
description: Review for missing Pester test coverage on new or modified functions
applyTo: "src/**/*.psm1,src/**/*.ps1"
---

# Code Review: Pester Test Coverage

When reviewing changes to PowerShell source files in `src/`, check that corresponding Pester tests exist.

## Rules

1. **New exported functions MUST have tests.** If a new function is added to any `.psm1` file, there should be a corresponding test in `tests/offline/<ModuleName>.Tests.ps1`. Flag if missing.

2. **Modified function signatures should update tests.** If parameters are added, renamed, or removed, existing tests should reflect the change.

3. **Bug fixes should add a regression test.** If the PR fixes a bug, there should be a test that would have caught it.

## What to check

- Look for new `function <Verb>-Sdn<Noun>` definitions in the diff
- Verify a `Describe '<Module> - <FunctionName>'` block exists in the corresponding test file
- If no test file exists for the module yet, flag that one should be created

## How to flag

If tests are missing, comment:

> This PR adds/modifies `<FunctionName>` but no corresponding Pester test was found in `tests/offline/`. Please add offline tests following the patterns in `tests/CONTRIBUTING_TESTS.md`.

## Exceptions (do not flag)

- Private helper functions (not exported, names without `Sdn` prefix)
- Changes to build scripts, manifests, or documentation only
- Trivial parameter alias additions
