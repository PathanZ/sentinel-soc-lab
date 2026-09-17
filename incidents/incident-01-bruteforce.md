# Incident 01: Brute Force Authentication (T1110)

## Summary
Sentinel detected a high volume of failed authentication attempts against
multiple local accounts on the victim host, consistent with MITRE ATT&CK
technique **T1110 - Brute Force** (sub-technique **T1110.001 - Password
Guessing**).

## Incident Details
| Field | Value |
|---|---|
| Incident ID | 29 |
| Title | T1110 - Brute Force Authentication |
| Severity | Medium |
| Status | Active |
| Category | Credential Access |
| MITRE ATT&CK | T1110, T1110.001 |
| Detection source | Scheduled detection (Microsoft Sentinel) |
| First activity | Sep 17, 2026, 12:19:33 AM |
| Last activity | Sep 17, 2026, 5:19:33 AM |
| Creation time | Sep 17, 2026, 5:24:42 AM |
| Active alerts | 1/1 |

## Affected Asset
- **Computer:** `vm-victim-01`
- **Target Accounts:** `vm-victim-01\administrator`, `vm-victim-01\azureuser`

## Detection Query
```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(3d)
| summarize FailedAttempts = count(), TargetAccounts = make_set(Account), LatestAttempt = max(TimeGenerated) by IpAddress, Computer
| where FailedAttempts >= 5
| order by FailedAttempts desc
```

## Evidence
| IpAddress | Computer | FailedAttempts | TargetAccounts | LatestAttempt |
|---|---|---|---|---|
| (local/loopback) | vm-victim-01 | 27 | `vm-victim-01\administrator`, `vm-victim-01\azureuser` | Sep 17, 2026, 4:25:20 AM |

27 failed logon events (Event ID 4625) were aggregated against a single source,
targeting two distinct local accounts on `vm-victim-01`, well above the
detection threshold of 5 attempts.

## Analysis
The failed attempts span both a built-in administrative account
(`administrator`) and the standard operational account (`azureuser`),
indicating a non-targeted, opportunistic password-guessing pattern rather
than an attack focused on one specific credential. The activity was generated
locally on the VM as part of a controlled simulation using
`New-Object System.Management.Automation.PSCredential` with a deliberately
incorrect password, repeated across multiple account/credential combinations.

## Response Actions
1. Confirmed activity was isolated to the lab VM `vm-victim-01` (simulated
   environment — no real external attacker).
2. Verified both `administrator` and `azureuser` accounts remained unlocked
   with no successful authentication following the failed attempts.
3. Documented the aggregation query as effective at surfacing brute-force
   patterns across multiple target accounts from a single source.

## Lessons Learned / Tuning Notes
- The `ago(3d)` lookback window in this query is appropriate for ad hoc hunting
  but too wide for a scheduled analytics rule — combined with a short rule
  run frequency, this caused duplicate incident re-firing on the same
  underlying data during testing (see project-level lessons learned). A
  production version of this rule should use a tighter window (e.g. `ago(1h)`)
  aligned to the rule's own schedule.
- Consider adding a check for successful authentication (Event ID 4624)
  immediately following a failed-attempt cluster from the same source, which
  would indicate a successful brute-force compromise rather than a
  contained/unsuccessful attempt.
- `IpAddress` was effectively local/loopback in this single-VM lab setup;
  in a network-based real-world scenario this field becomes a key pivot for
  identifying and blocking the external source.
