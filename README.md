# 01-sherlock-htb-campfire
Investigated Kerberoasting activity in an Active Directory environment using Splunk, Windows Event Logs, and Prefetch analysis. Identified suspicious Kerberos service ticket requests, PowerView reconnaissance activity, and Rubeus execution using PECmd and Timeline Explorer.
# Campfire - Kerberoasting Investigation

**Tools:** Splunk, PECmd, Timeline Explorer  
**Technique:** Kerberoasting (T1558.003)

## Overview

Investigated suspected Kerberoasting activity in an Active Directory environment using Windows Event Logs and Prefetch artifacts.

## 1. Kerberos Analysis

Searched Event ID 4769 for suspicious service ticket requests.

```spl
index="htb-campfire" EventCode=4769
| where Service_Name!="krbtgt" AND NOT like(Service_Name,"%$")
```

Identified a successful RC4-encrypted service ticket request with the following details:

- Account: `alonzo.spire@FORELA.LOCAL`
- Service: `MSSQLService`
- Source IP: `172.17.79.129`
- Encryption: `0x17` (RC4)
- Result: `0x0` (Success)

This activity was consistent with Kerberoasting.

## 2. PowerShell Analysis

Investigated Event ID 4104 for suspicious PowerShell activity.

```spl
index="htb-campfire" EventCode=4104
| table _time host Message
| sort _time
```

Identified PowerView-related code on `Forela-Wkstn001.forela.local`, referencing the `alonzo.spire` Downloads directory.

The script contained Active Directory enumeration functions such as `Get-NetUser`, `Get-NetComputer`, and `Get-NetGroupMember`.

3. Prefetch and Event Log Analysis

Reviewed Windows events following the PowerView discovery to correlate suspicious activity.

Parsed workstation Prefetch artifacts using PECmd:

.\PECmd.exe -d "PATH_TO_PREFETCH" --csv . --csvf campfire-prefetch.csv -q

Analyzed 207 Prefetch files in Timeline Explorer.

Findings:

Executable: RUBEUS.EXE

Execution: 2024-05-21 03:18:08

Path: \USERS\ALONZO.SPIRE\DOWNLOADS\RUBEUS.EXE

Rubeus execution, PowerView activity, and suspicious Kerberos ticket requests collectively supported suspected Kerberoasting.

## Conclusion

The investigation identified suspicious RC4 Kerberos ticket activity, PowerView reconnaissance code, and Rubeus execution.

Together, these findings strongly support suspected Kerberoasting activity, although successful password cracking was not confirmed.
**Assessment:** Evidence strongly supports suspected Kerberoasting activity. Successful password cracking or further compromise was not confirmed.

---

**Skills Demonstrated:** `Splunk` `SPL` `Windows Event Logs` `Kerberos` `PowerShell` `Prefetch Analysis`
