# Threat Hunt 01: Lateral Movement via RDP

## Hypothesis
Following persistence established via scheduled task (see `incident-03-scheduled-task.md`), an attacker with a persistent foothold may attempt to move laterally to other hosts on the network using RDP with valid or brute-forced credentials, rather than triggering a new alertable authentication-failure event.

**MITRE ATT&CK:** T1021.001 — Remote Services: Remote Desktop Protocol

## Scope
- Monitored VM(s) in the Sentinel lab environment
- Time window: last 30 days of `SecurityEvent` / `DeviceLogonEvents` data
- Data sources: Windows Security Event Log (Event ID 4624/4625), Sentinel `SigninLogs` (if hybrid-joined)

## Data Sources
| Table | Purpose |
|---|---|
| `SecurityEvent` | Logon Type 10 (RemoteInteractive) events, EventID 4624/4625 |
| `DeviceNetworkEvents` (if MDE connected) | Outbound RDP connections (port 3389) |
| `DeviceProcessEvents` | `mstsc.exe` execution as a precursor indicator |

## Hunting Query (draft — validate field names against your workspace schema)

```kql
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where TimeGenerated > ago(30d)
| project TimeGenerated, Computer, Account, IpAddress, LogonType
| summarize LogonCount = count(), DistinctHosts = dcount(Computer) by Account, IpAddress
| where DistinctHosts > 1
| order by DistinctHosts desc
```

**Logic:** flags accounts that successfully authenticated via RDP (LogonType 10) to more than one distinct host — a signal consistent with lateral movement rather than routine single-host remote access.

## Expected Outcome
- **If no matches:** establishes a clean baseline; document as a negative result (still valuable — proves the environment doesn't show this pattern yet).
- **If matches found:** pivot into `DeviceNetworkEvents`/`DeviceProcessEvents` for the flagged account to build a timeline, then escalate to an incident write-up if the activity isn't attributable to the analyst's own testing.

## Execution Plan
1. Run baseline query against current lab data (pre-simulation) to confirm no false positives from legitimate lab access.
2. Simulate lateral movement using Atomic Red Team test **T1021.001** from the persistence host to a second monitored VM.
3. Re-run the hunting query; confirm the simulated activity surfaces.
4. Capture screenshots (query results, DeviceLogonEvents timeline) → `screenshots/`.
5. Document findings below.

## Findings
*(fill in after execution)*

## Follow-up Detection
*(if the hunt proves the pattern is detectable and worth alerting on, convert this query into a scheduled analytics rule: `detections/T1021.001-lateral-rdp.kql`)*
