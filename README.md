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
