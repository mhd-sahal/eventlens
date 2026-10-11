# EventLens - Windows Security Event Log Triage Tool

An **educational**, browser-based tool that turns a Windows Event Viewer CSV export into a SOC-style triage report. It explains *why* an event might deserve investigation, what innocent explanations exist, and what an analyst would check next.

> **Educational SOC triage tool.** Findings indicate activity that may deserve investigation and do not prove malicious behaviour.
> **Only analyse logs from systems you own or are authorised to investigate.**

**Your Windows security logs are analysed locally in your browser. Files are not uploaded or transmitted anywhere.**

---

## Contents

1. [Project purpose](#project-purpose)
2. [Background: Windows Event Logs and SOC triage](#background)
3. [Run it locally (Windows)](#run-it-locally)
4. [How to export suitable Windows event data](#exporting-data)
5. [Supported Event IDs](#supported-event-ids)
6. [Detection and correlation rules](#rules)
7. [Default thresholds and settings](#thresholds)
8. [Explainable investigation score](#scoring)
9. [Sample datasets and the recruiter demo](#samples)
10. [False positives](#false-positives)
11. [Limitations](#limitations)
12. [Privacy architecture](#privacy)
13. [Security of uploaded files](#security)
14. [Accessibility](#accessibility)
15. [Project structure](#structure)
16. [Testing](#testing)
17. [Educational use](#educational-use)
18. [Ideas for future improvement](#future)

---

<a id="project-purpose"></a>
## Project purpose

Most beginner security tools either overwhelm students with raw logs or pretend to be an "AI that detects hackers". EventLens does neither. Its goals are to teach students:

- how Windows security events work,
- how SOC analysts **correlate** events (the real value is in how events relate to each other),
- why false positives happen,
- how analysts decide what deserves further investigation.

The tool is deliberately **rule-based and explainable**. Every finding lists exactly what triggered it and exactly how its score was added up. There are no probabilities, no "93% malicious" numbers, and no machine-learning black box.

<a id="background"></a>
## Background

### What are Windows Event Logs?
Windows records what happens on a computer in event logs. The **Security** log records audited activity: logons, failed logons, account changes, group changes, and so on. Each event has an **Event ID** (a number such as 4624) that says what kind of event it is, a timestamp, and a **Message** with the details (who, from where, to what).

Which events exist in your log depends on your **audit policy**. If an activity is not audited, there is no event for it.

### What is SOC triage?
A Security Operations Centre (SOC) analyst receives many alerts. *Triage* means quickly deciding which ones deserve attention first and what to check. A good analyst never trusts one event on its own: they ask whether the activity is expected, look at related events, and gather more evidence before deciding to escalate.

> One security event rarely tells the entire story. Analysts build context by correlating multiple events.
>
> A detection is a reason to investigate, not proof that an attacker is present.

<a id="run-it-locally"></a>
## Run it locally (Windows)

**Nothing needs to be installed.** You only need a modern browser (Edge, Chrome or Firefox).

1. Put the whole project folder somewhere on your laptop (for example your Desktop). Keep the files together: `index.html`, `styles.css`, `script.js`, `sample-data.js`, and the `samples` folder.
2. Open the folder in File Explorer.
3. **Double-click `index.html`.** It opens in your browser.
4. Click one of the **Demo Data** buttons to try it immediately, or choose your own CSV file.

Everything works offline. You can disconnect from the internet and it behaves identically.

If you later host it as a static website, upload the same files to any static host (GitHub Pages, Netlify, an S3 bucket, and so on). There is no server-side code, build step or configuration.

<a id="exporting-data"></a>
## How to export suitable Windows event data

EventLens needs a **CSV file with an Event ID column** and, for useful analysis, the event **Message** text. The account names, source IPs, workstation names, group names and process names all live inside the Message.

### Option A: Event Viewer (GUI)

1. Open **Event Viewer**.
2. Go to **Windows Logs → Security**.
3. (Optional) **Filter Current Log…** to a time range and the Event IDs you care about.
4. Use **Save Filtered Log File As…** (or **Save All Events As…**) and choose the **CSV** type.
5. Upload the CSV.

> **Heads-up, please check your own file.** Depending on the Windows version, the CSV saved from the Event Viewer window may contain only the *list columns* (such as Keywords/Level, Date and Time, Source, Event ID, Task Category) and **not** the Message text. This was not confirmed against an official source while writing this tool, so open your CSV and look. If there is no Message column, EventLens will still load the file and will say so, but it cannot read accounts or IPs, so most correlation will not be possible.

### Option B: PowerShell (recommended, includes the Message)

Open **Windows PowerShell as Administrator** (reading the Security log needs it) and run:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4688,4720,4726,4728,4732,1102} -MaxEvents 5000 |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, TaskDisplayName, Message |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation -Encoding UTF8
```

Notes:

- `-MaxEvents 5000` returns the **newest** 5000 matching events. On a busy machine 4624 can be very frequent, so you may need a larger number or a narrower time range. To limit the time, add `StartTime=(Get-Date).AddDays(-1)` inside the `@{ ... }`.
- If PowerShell says *No events were found*, none of those IDs exist in the log (or auditing is off).
- EventLens recognises PowerShell's column names (`TimeCreated`, `Id`, `ProviderName`, `MachineName`, and so on) as well as Event Viewer's.

### Adding service installs (7045) and PowerShell script blocks (4104)

These live in other logs. Run extra commands that **append** to the same file with the same columns:

```powershell
# 7045 service installed (System log)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, TaskDisplayName, Message |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation -Encoding UTF8 -Append

# 4104 PowerShell script block logging (only exists if that logging is enabled)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 500 |
  Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, TaskDisplayName, Message |
  Export-Csv -Path "$env:USERPROFILE\Desktop\security-events.csv" -NoTypeInformation -Encoding UTF8 -Append
```

For 7045 and 4104, the "account" EventLens shows comes from the `User` column if present. These PowerShell exports do not include one, so the account may show as unknown. That is a known limitation.

### Do not upload `.evtx` files
Version 1 does not parse raw `.evtx` files. If you try, EventLens tells you so.

<a id="supported-event-ids"></a>
## Supported Event IDs

| Event ID | Name | Default severity | What EventLens does |
|---|---|---|---|
| **4624** | Successful logon | Informational | Counted. Used as context and for correlation. Never alerts on its own. |
| **4625** | Failed logon | Informational | Counted per account. Repeated failures trigger Rule 1 / Rule 2. |
| **4688** | Process created | Informational | Displays process, parent process, command line and account where present. No detection in V1. |
| **4720** | User account created | Medium | Standalone finding, or part of Rule 3. |
| **4726** | User account deleted | Low | Low. Medium if the same account was created earlier in the same file (short-lived account). |
| **4728** | Member added to global security group | Medium | High if the group name looks privileged. Part of Rule 3 if the member was just created. |
| **4732** | Member added to local security group | Medium | High if the group name looks privileged (for example Administrators). Part of Rule 3 if the member was just created. |
| **1102** | Audit log cleared | High | Always a High finding (Rule 4). |
| **4104** | PowerShell script block logging | Informational | Recognised. Medium only if the script text looks encoded or heavily obfuscated. Plain PowerShell is **not** flagged. |
| **7045** | Service installed | Low | Medium if the service file is in a user-writable folder (Temp, AppData, Users\Public, ProgramData) or is a script host (cmd, powershell, mshta, wscript...). |

Any other Event ID is kept, counted, shown as "Other event", and never causes an error.

"Privileged" group names are matched by a simple pattern: names containing *admin*, *operators* or *DnsAdmins*, or *Group Policy Creator Owners* (for example Administrators, Domain Admins, Backup Operators). It is a name check only. A group with a harmless-looking name could still be powerful, and a group named "admin-readonly" would be flagged unnecessarily.

<a id="rules"></a>
## Detection and correlation rules

Events are first **sorted by time** (Event Viewer exports are newest-first, so file order is not trusted when timestamps can be read), then grouped by account (case-insensitive).

### Rule 1: Repeated failed logons
- **Trigger:** an account has at least *threshold* 4625 events (default **5**), inside a sliding time window if enabled (default **10 minutes**).
- **Severity:** Medium. Low if the account name could not be read.
- **Extra context:** lists source IPs, and notes if the same source IP also failed logons against other accounts (a hint of password spraying, which can also be a shared proxy or NAT).

### Rule 2: Failed logons followed by success
- **Trigger:** Rule 1 conditions, **and** a 4624 for the same account occurs after the last failure (and within the time window if enabled).
- **Severity:** **High**, but **Medium** if the success came from a *different* source IP than all the failures (that lowers confidence that it is the same actor).
- **De-duplication:** when Rule 2 fires, the separate Rule 1 alert for that account is suppressed, because it would say the same thing twice.
- A success that came **before** the failures does not count. Order matters.

### Rule 3: Account created then privilege added
- **Trigger:** a 4720 for an account, followed in the same file by a 4728 or 4732 where the *member* is that same account.
- **Severity:** **High** if the group looks privileged, otherwise Medium.
- Reports who created the account (the event's Subject).
- Matching handles `DOMAIN\user`, `CN=user,CN=Users,DC=...` and plain names. If the member only appears as an unresolved SID (`S-1-5-21-...`), it cannot be matched to the creation event and is reported as a standalone group change with a note.

### Rule 4: Security log cleared
- **Trigger:** any 1102.
- **Severity:** High.

### Rule 5: Administrative / Privilege Activity
- If the file contains account creation or deletion, group membership changes, service installs or log clearing, they are summarised together in a table with who did what.
- **No automatic linking between different users.** The section only lists them side by side.

### Cross-link (same account only)
If the account that *performed* an admin action (for example created a user or cleared the log) **also** has a "failed logons followed by success" finding, the admin finding says so and adds points. This links events through a shared account only, never by guessing.

<a id="thresholds"></a>
## Default thresholds and settings

| Setting | Default | Notes |
|---|---|---|
| Failed login threshold | 5 | Whole number 1 to 1000 |
| Failed login time window | 10 minutes | 1 to 1440. Can be switched off to count failures across the whole file |
| Group change "quickly" (Rule 3 score bonus) | 60 minutes | Fixed in code (`PRIVILEGE_QUICK_MINUTES` in `script.js`) |

**Reset Defaults** restores them. Security thresholds vary by environment. These values are educational defaults rather than universal SOC detection rules.

**Timestamps:** Windows writes dates in the computer's regional format, so `03/04/2026` could be 3 April or 4 March. EventLens detects day-first or month-first from the data (a value like `14/10/2026` settles it). If every date in the file is ambiguous it assumes month-first and tells you. If the dates are inconsistent or unreadable, **time-window analysis is switched off**, failures are counted across the whole file, and the page says so. Times are shown as exported, with **no timezone conversion**.

<a id="scoring"></a>
## Explainable investigation score

Each finding shows a list of points and the reason for each. Example:

```
+10  Repeated failed logons (at or above the threshold of 5)
+20  Successful logon (4624) followed the failures
+10  Success came from the same source IP as the failures
 40  Total investigation score
```

Other points include: +25 added to a privileged group, +30 security log cleared, +15 acting account also had failed-then-successful logons, and so on. See `script.js` (search for `scoreItems`).

**This is an educational prioritisation aid, not a mathematical probability of compromise.** A higher score means "look at this sooner", not "this is more likely to be malicious". The numbers are teaching weights chosen by the author and are not calibrated against real incident data.

<a id="samples"></a>
## Sample datasets and the recruiter demo

All sample data is **fictional**. Users, computers and IP addresses do not exist, and IPs are from private ranges (`192.168.x.x`, `10.x.x.x`). The page labels loaded samples **Demo Data**.

| File (in `samples/`) | Button | Expected result |
|---|---|---|
| `normal-windows-events.csv` | Load Normal Sample | Mostly informational. Two stray failed logons stay below threshold. One routine account deletion is a **Low** finding. No Medium or High. |
| `failed-logons-only.csv` | Load Failed Logons Sample | **Repeated Failed Logons** (Medium). No success afterwards, so it is not escalated. (An earlier success for that account is deliberately included to show that order matters.) |
| `password-guessing.csv` | Load Password Guessing Sample | **Possible Password Guessing Followed By Success** (High). |
| `account-persistence.csv` | Load Privilege Escalation Sample | **New Account Granted Privileges** (High). |
| `audit-log-cleared.csv` | Load Log Cleared Sample | **Security Audit Log Cleared** (High). |
| `suspicious-admin-activity.csv` | Load Mixed SOC Sample | Several correlated findings, the Administrative / Privilege Activity summary, and cross-links through the account `jsmith`. |

Two extra files beyond the four in the original brief (`failed-logons-only.csv` and `audit-log-cleared.csv`) exist so that demo Tests 2 and 5 each have a clean, single-purpose dataset.

### Suggested demo script (buttons 1 to 5, then 6)
1. **Normal** - "Mostly informational. Ordinary logons and processes."
2. **Failed logons** - "Repeated failures raise an alert, but without a success it stays Medium."
3. **Password guessing** - "Same failures, now followed by a success from the same IP: High."
4. **Privilege escalation** - "An account is created then added to Administrators."
5. **Log cleared** - "One event, High priority: evidence may be gone."
6. **Mixed** - "The individual events matter, but the real value comes from understanding how they relate to one another."

You can also show the **upload** flow with the real files in `samples/`. They are written newest-first like genuine Event Viewer exports, which shows off the time sorting.

### Why are there two copies of the sample data?
Browsers block web pages opened from your disk (`file://`) from reading other local files. So the demo buttons use `sample-data.js`, a copy of the CSVs embedded in JavaScript. If you change the CSVs, regenerate that file with the optional `node tools/generate-samples.js` (requires Node.js, not needed to just use the tool), which rewrites both.

<a id="false-positives"></a>
## False positives (read this)

Everything below can trigger a finding and be completely innocent:

- **Repeated failed logons:** users mistyping or forgetting passwords; an old password saved in a mapped drive, scheduled task, service or phone; software retrying a locked account.
- **Failures then success:** the real user eventually typed the right password. This is the normal ending of most failure streaks.
- **New account plus group membership:** a real onboarding, a lab or test setup, an approved change.
- **Account deletion:** leaver clean-up and test account removal.
- **Log cleared:** planned maintenance, a lab reset, freeing disk space.
- **Service installed:** software or driver installs and updates.
- **Encoded PowerShell:** some management tools and installers legitimately pass Base64-encoded commands.
- **Many accounts failing from one IP:** a shared gateway, proxy, terminal server or VPN concentrator.

Each finding shows its own "Possible benign explanation". The skill you are practising is deciding which is more likely, using additional evidence.

<a id="limitations"></a>
## Limitations

Honest list:

- **CSV exports differ between Windows configurations and versions.** Column names, date formats and whether the Message is included all vary.
- **Not every event contains a source IP.** Local logons usually show `-`.
- **Event logging configuration affects available telemetry.** If an audit policy is off (for example Process Creation, or command-line logging), those events simply do not exist.
- **Absence of an event does not prove activity did not occur.** "No findings" means no rule matched, not "safe".
- **This tool does not replace an EDR, SIEM or professional SOC platform.**
- **Static browser analysis provides limited correlation.** It sees one file at a time, no history, no baselines, no other data sources.
- **Detecting malicious behaviour requires context.** Windows Event IDs alone cannot determine intent.
- **Message parsing assumes English Windows.** Field labels such as "Account Name:" are matched in English. On other languages, accounts and IPs will not be extracted.
- **Account extraction is pattern-based.** Unusual message layouts, flattened (single-line) messages or truncated exports can lose details.
- **Timestamps:** regional date formats can be ambiguous (see above). If timestamps cannot be read and the file is newest-first, file order (assumed oldest-first) can reverse sequences. EventLens warns when this happens.
- **Machine and system accounts** (for example `WS-LAB-01$`, `SYSTEM`) are not filtered out of statistics.
- **Rule 2 only looks for a success inside the time window** after the failures (default 10 minutes). A later success will not correlate.
- **Large files:** a browser tab holds everything in memory. Files over 50 MB are refused, and only the first 250,000 rows are analysed. Very large files may be slow.
- **Messages are truncated** to 6,000 characters per event for display.
- Windows 11 puts a narrow no-break space before AM/PM. This is handled, but other locale quirks may exist.
- 4688 and 4104 are only *displayed* in V1. There is no malware detection.

<a id="privacy"></a>
## Privacy architecture

The uploaded file never leaves your computer. This is enforced in layers, not just promised:

1. **No code that sends data.** `script.js` contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, forms or external scripts. No analytics, tracking, cookies, advertising or telemetry. No external fonts, CDNs or libraries.
2. **A browser-enforced policy.** `index.html` carries a Content-Security-Policy that sets `connect-src 'none'`, so even if a bug or injected code *tried* to make a network request, the browser would refuse. Scripts and styles may only load from the project's own files, and inline script is not allowed.
3. **No storage.** Nothing is written to `localStorage`, `sessionStorage`, cookies or IndexedDB. The file is read into memory, analysed, and discarded when you close or refresh the page, or press **Clear loaded data**.
4. **No referrer.** The page tells the browser not to send referrer information.

You can verify this yourself: open the browser's developer tools (F12) → **Network** tab, load a file, and watch that no requests appear. (If you host the project, your web host may still log the *page* request for `index.html`. It never sees your CSV.)

<a id="security"></a>
## Security of uploaded files

A CSV is treated as **untrusted input**. Event messages can contain attacker-controlled text (for example a username typed into a login box).

- **Output escaping:** every value from the file is inserted into the page with `textContent` or text nodes only. The code never uses `innerHTML` and never builds HTML from file content. A username such as `<img src=x onerror=...>` is displayed literally as text.
- **No execution paths:** no `eval`, no `new Function`, no dynamic script loading.
- **Fails safely:** malformed CSV (for example an unclosed quote), binary files, `.evtx` files, empty files, missing columns and non-numeric Event IDs produce a clear message instead of a crash.
- **Size limits:** 50 MB file limit, 250,000 row limit, truncated message display.
- **No retention:** nothing is kept after the page session.

This was tested with a deliberately hostile CSV (script tags, image `onerror` handlers, SVG `onload`, attribute-breaking quotes in account, IP, group, source and computer fields). Nothing executed and no HTML elements were created from file content.

<a id="accessibility"></a>
## Accessibility

Semantic HTML (one `h1`, `main`, ordered headings, `table` with `caption` and `scope`), skip link, labelled form controls, keyboard-operable everything, visible focus outlines, live-region status messages, severity shown by **word + shape + colour** (never colour alone), dark theme with high-contrast text, no animation, and a layout that works down to phone width. A native file input inside the drop zone keeps file selection keyboard accessible.

This was checked with automated tests and by eye, **not** with a screen reader. A real assistive-technology review is a sensible future step.

<a id="structure"></a>
## Project structure

```
index.html            page structure and privacy policy (CSP)
styles.css            dark theme
script.js             parser, rules, scoring, interface (all logic)
sample-data.js        embedded copy of the sample CSVs for the demo buttons (generated)
samples/              fictional sample CSV files you can also upload manually
tools/generate-samples.js   OPTIONAL: regenerates samples + sample-data.js (needs Node.js)
tests/run-tests.js          OPTIONAL: logic tests (needs Node.js)
README.md
```

Inside `script.js`, in order: constants and plain-English knowledge base (`CATALOG`) → CSV parser → timestamp handling → message field extraction → event building → `analyse()` (all rules and scoring) → user interface.

<a id="testing"></a>
## Testing

Optional, requires Node.js: `node tests/run-tests.js` runs 68 checks covering all sample datasets, thresholds and windows, column-name variants, malformed and missing-column files, timestamp formats, newest-first ordering, and message parsing.

The page itself was also exercised in headless Chromium opened from `file://`: demo buttons, upload, drag-and-drop, settings, filters, error messages, injection safety, zero external network requests, CSP blocking, empty browser storage, labels and table markup.

<a id="educational-use"></a>
## Educational use

Suggested classroom exercises:

1. Load each demo in order and have students predict the findings *before* clicking.
2. Open a sample CSV in Notepad and find the account name inside the Message.
3. Change the threshold (try 3, then 20) and discuss why "right" depends on the environment.
4. Turn the time window off in the Failed Logons sample and discuss what changes.
5. For each finding, argue the benign explanation, then list evidence that would confirm or refute it.
6. Export a few hours of your own lab machine's Security log (with permission) and compare.

<a id="future"></a>
## Ideas for future improvement

Not implemented in Version 1 (no external APIs are used or planned for V1):

- raw `.evtx` parsing
- Sysmon support
- PowerShell 4104 deeper analysis
- process-tree visualisation
- MITRE ATT&CK mapping
- richer timeline analysis
- login-time baselining
- service-creation detection
- scheduled task monitoring
- Windows Defender event analysis
- exportable incident report
- SIEM integration

---

*EventLens is a learning project. It is not a security product.*
