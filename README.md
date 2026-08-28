# SOC Sentinel Lab

## Overview

This repository documents my hands-on cybersecurity SOC lab using Microsoft Sentinel.

The lab focuses on security monitoring, Windows Security Events, KQL (Kusto Query Language), and basic incident investigation.

## Objectives

- Investigate Windows security events
- Write and use KQL queries
- Analyse authentication activity
- Investigate process creation events
- Identify potentially suspicious activity
- Develop SOC investigation and documentation skills

## Tools

- Microsoft Sentinel
- Kusto Query Language (KQL)
- Windows Security Events
- Microsoft Azure

## Investigations

This repository will contain KQL queries, investigation notes, and supporting screenshots from my SOC lab.

More investigations will be added as I progress.

### Evidence

A screenshot of the Microsoft Sentinel query results showing Windows Event ID 4624 successful logon events.

![Windows Event ID 4624 results](4624.jpeg)
## Investigation 2: Windows Event ID 4688 – Process Creation

### Findings

Event ID 4688 represents a Windows process creation event.

The query was used to identify process creation activity involving potentially interesting executables, including cmd.exe, rundll32.exe, powershell.exe, and mshta.exe.

The results show multiple process creation events on the VM-Sentinel1-wi computer. The observed processes include cmd.exe and rundll32.exe.

These processes are not automatically malicious, but their execution should be reviewed in context using the command line, parent process, account, and timing.

### Field Analysis

- **TimeGenerated** – Time when the process creation event was recorded.
- **Account** – User account associated with the process.
- **Computer** – Computer where the process was created.
- **NewProcessName** – Name and path of the newly created process.
- **CommandLine** – Command-line arguments used to start the process.
- **ParentProcessName** – Process that started the newly created process.

### Investigation Notes

The query filters Windows Event ID 4688 and searches for commonly monitored process names.

The results can be reviewed to determine which account created the process, which computer was involved, what process was created, the command line used, and which parent process launched it.

The presence of cmd.exe or rundll32.exe does not by itself confirm malicious activity. Additional investigation is required to determine whether the process execution was expected or suspicious.

### Evidence

A screenshot of the Microsoft Sentinel query results showing Windows Event ID 4688 process creation events.

![Windows Event ID 4688 results](4688.jpeg)
## Investigation 3: Windows Event ID 4672 - Special Privileges

### Findings

Event ID 4672 represents a Windows security event where special privileges are assigned to a new logon.

The query was used to identify accounts receiving special privileges on the monitored Windows computer.

The results show multiple Event ID 4672 events associated with the `NT AUTHORITY\SYSTEM` account on the `VM-Sentinel1-wi` computer.

The account type is shown as `Machine`, and the observed privilege list includes `SeAssignPrimaryTokenPrivilege`.

The observed activity is associated with the SYSTEM account and does not by itself confirm malicious activity. The account, privileges, timing, and surrounding events should be reviewed when determining whether the activity is expected.

### Field Analysis

- **TimeGenerated** - Time when the Event ID 4672 event was recorded.
- **Account** - Account associated with the privileged logon.
- **AccountType** - Type of account associated with the event.
- **Computer** - Computer where the event occurred.
- **PrivilegeList** - Special privileges assigned during the logon.

### Investigation Notes

The query filters Windows Event ID 4672 and displays the account, account type, computer, and privilege information.

The results show repeated privileged events for `NT AUTHORITY\SYSTEM` on `VM-Sentinel1-wi`. The presence of a privileged event alone does not establish malicious activity and should be assessed in context.

### Evidence

A screenshot of the Microsoft Sentinel query results showing Windows Event ID 4672 special privilege events.

![Windows Event ID 4672 results](4672.jpeg)
## Investigation 4: Windows Event ID 4662 - Directory Service Access

### Findings

Event ID 4662 represents an operation performed on an object.

The query was used to identify Windows Event ID 4662 activity and review the associated account, computer, activity, object name, and subject user.

The results show multiple Event ID 4662 events on the `VM-Sentinel1-wi` computer. The account shown is `WORKGROUP\VM-Sentinel1-wi$`.

The observed activity occurred around 04:01 AM on 27/08/2026, and the ObjectName values shown begin with `root\CIM`.

The presence of Event ID 4662 events does not by itself confirm malicious activity. The account, object accessed, activity, timing, and surrounding events should be reviewed to determine whether the activity was expected.

### Field Analysis

- **TimeGenerated** - Time when the event was recorded.
- **Account** - Account associated with the event.
- **Computer** - Computer where the activity occurred.
- **Activity** - Description of the operation performed.
- **ObjectName** - Object associated with the operation.
- **SubjectUserName** - User associated with the activity.

### Investigation Notes

The query filters Windows Event ID 4662 and displays the main fields needed to investigate object access activity.

The results show repeated events associated with the machine account `WORKGROUP\VM-Sentinel1-wi$` on `VM-Sentinel1-wi`. Further investigation would be required to determine the purpose and context of the `root\CIM` object activity.

### Evidence

A screenshot of the Microsoft Sentinel query results showing Windows Event ID 4662 activity.

![Windows Event ID 4662 results](4662.jpeg)

## Investigation Conclusion

Windows Event ID 4662 records an operation was performed on an object in Active Directory.

The queried events were associated with the machine account `WORKGROUP\VM-Sentinel1-wi$` on `VM-Sentinel1-wi`.

The repeated 4662 events indicate object access activity, but Event ID 4662 alone does not establish that the activity was malicious. Further investigation would be required to identify the specific object accessed, the access rights used, and the process or activity that generated the events.

### Recommended Next Steps

- Review the full Event ID 4662 details, especially `ObjectName`, `ObjectType`, and `AccessMask`.
- Correlate the events with other Windows Security events such as 4624 (successful logon) and 4688 (process creation).
- Check whether the activity occurred during a known administrative or system task.
- Investigate the machine account and determine why it generated repeated object-access events.
- Document whether the activity is confirmed benign, suspicious, or requires further investigation.

### Analyst Assessment

At this stage, the activity should be treated as **requiring further investigation rather than confirmed malicious activity**. The available evidence demonstrates repeated object-access events, but additional event correlation and context are needed to determine intent.

## Skills Demonstrated

- Microsoft Sentinel
- Kusto Query Language (KQL)
- Windows Security Event Log analysis
- Active Directory object-access investigation
- Event ID 4662 analysis
- SIEM investigation and evidence documentation
- Security event correlation
- Basic incident investigation methodology
- ## Detection & Investigation Summary

This investigation used Microsoft Sentinel and Kusto Query Language (KQL) to identify and review repeated Windows Security Event ID 4662 activity.

The investigation focused on:

- Identifying repeated Event ID 4662 events within the selected time range.
- Reviewing the account and computer associated with the activity.
- Examining fields including `ObjectName`, `ObjectType`, `AccessMask`, and `SubjectUserName`.
- Assessing whether the activity represented expected administrative or system behaviour.
- Recognising that repeated object-access events require additional context before being classified as malicious.
- Documenting recommended follow-up actions and evidence requirements.

### Detection Logic

The investigation used the following KQL query:

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4662
| project TimeGenerated, Account, Computer, Activity, ObjectName, SubjectUserName
| order by TimeGenerated desc

## MITRE ATT&CK Mapping

The investigation was reviewed against the MITRE ATT&CK framework to access potentially relevant techniques. The available evidence did not confirm any specific malicious ATT&CK technique...

- **T1070 - Indicator Removal:** ...
- **T1003 - OS Credential Dumping:** ...
- **T1087 - Account Discovery:** ...

The available telemetry was insufficient...


## Final SOC Analyst Assessment

The investigation identified repeated Windows Event ID 4662 activity associated with the machine account `WORKGROUP\VM-Sentinel1-wi` on `VM-Sentinel1-wi`.

The activity confirms repeated object-access events, but the available evidence does not establish malicious intent.

Based on the current evidence, the appropriate classification is:

**Status: Requires Further Investigation**

Recommended investigation priorities include reviewing the complete Event ID 4662 fields, identifying the specific Active Directory objects accessed, analysing the AccessMask and ObjectType values, and correlating the activity with related Windows Security events such as Event ID 4624 and Event ID 4688.

This investigation demonstrates a structured SOC workflow of detection, event analysis, correlation, evidence review, and cautious classification.

This lab demonstrates a practical SOC investigation workflow:

1. Identify relevant security events.
2. Build a focused KQL query.
3. Extract useful investigation fields.
4. Review repeated activity for patterns.
5. Correlate events with additional Windows security telemetry.
6. Assess the available evidence.
7. Document findings and recommended next steps.

The investigation highlights the importance of **context and event correlation** when analysing Windows security events. A single event should not automatically be treated as malicious without supporting evidence.
