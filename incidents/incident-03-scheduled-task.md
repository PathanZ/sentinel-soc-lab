# Incident 03: Scheduled Task Persistence (T1053.005)

## Summary
Sentinel detected repeated scheduled task creation events on the victim host,
consistent with MITRE ATT&CK technique **T1053.005 - Scheduled Task/Job:
Scheduled Task**, a common persistence mechanism.

## Incident Details
| Field | Value |
|---|---|
| Incident ID | 27 |
| Title | T1053.005 - Scheduled Task Persistence |
| Severity | Medium |
| Status | Active |
| Category | Persistence |
| MITRE ATT&CK | T1053, T1053.005 |
| Detection source | Scheduled detection (Microsoft Sentinel) |
| First activity | Sep 17, 2026, 4:16:58 AM |
| Last activity | Sep 17, 2026, 4:27:53 AM |
| Creation time | Sep 17, 2026, 5:21:06 AM |
| Active alerts | 1/1 |

## Affected Asset
- **Computer:** `vm-victim-01`
- **Account:** *(blank in the Sentinel query output — see Analysis below)*

## Detection Query
```kql
SecurityEvent
| where EventID == 4698
| project TimeGenerated, Computer, Account, Activity
| order by TimeGenerated desc
```

## Evidence
Five matching events were captured within the incident window, all on `vm-victim-01`:

| TimeGenerated | Computer | Account | Activity |
|---|---|---|---|
| Sep 17, 2026 4:27:53 AM | vm-victim-01 | *(blank)* | 4698 - A scheduled task was created. |
| Sep 17, 2026 4:27:47 AM | vm-victim-01 | *(blank)* | 4698 - A scheduled task was created. |
| Sep 17, 2026 4:27:41 AM | vm-victim-01 | *(blank)* | 4698 - A scheduled task was created. |
| Sep 17, 2026 4:23:xx AM | vm-victim-01 | *(blank)* | 4698 - A scheduled task was created. |
| Sep 17, 2026 4:16:58 AM | vm-victim-01 | *(blank)* | 4698 - A scheduled task was created. |

## Analysis
Unlike Event 4688 (process creation), Event 4698 does not always populate the
`Account` field via the parsed `SecurityEvent` schema — the creating user's
identity is typically embedded in the raw event XML under `SubjectUserName`
rather than surfaced in the flattened `Account` column Sentinel exposes by
default. This is a known schema limitation, not a logging failure: the task
creation was performed interactively as `azureuser` via `schtasks /create`
on the victim VM, but that attribution isn't visible without parsing the
embedded event XML.

The three events fired within a tight ~12-second window (4:27:41–4:27:53 AM),
consistent with a single `schtasks /create` command being run multiple times
in quick succession during the simulation, plus two earlier standalone events
at 4:16:58 AM and ~4:23 AM.

This is documented here as a **detection gap** worth calling out: a
production-grade version of this rule should extend the query to parse
`EventData` and surface `SubjectUserName` directly, rather than relying on
the generic `Account` column.

## Response Actions
1. Confirmed activity was isolated to the lab VM `vm-victim-01` (simulated
   environment).
2. Verified all 5 events correspond to the `schtasks /create` simulation
   command (task name: `UpdateCheckTask`) run during testing.
3. Documented the `Account` field gap as a detection engineering finding rather
   than treating it as inconclusive evidence.

## Lessons Learned / Tuning Notes
- **Account attribution gap:** the `Account` column is not reliably populated
  for Event 4698 — a future iteration should parse `EventData`/XML to extract
  `SubjectUserName` for proper attribution.
- Baseline legitimate scheduled task creation (software updaters, backup jobs)
  before enabling this as a production alert, to avoid noisy false positives.
- Flag tasks whose action executes from unusual paths (`%TEMP%`, `%APPDATA%`,
  user-writable directories) or references encoded/obfuscated commands as
  higher-severity.
- Consider a companion query on EventID 4699 (task deleted) / 4702 (task
  updated) to catch defense-evasion cleanup after persistence is achieved.
