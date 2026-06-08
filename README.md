# Threat-Hunting-Scenario-TOR

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/nathanhsjc/Threat-Hunting-Scenario-TOR/blob/main/Threat-Hunting-Scenario-TOR-Event-Creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "n4t3" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-06-05T01:54:13.4810532Z`. These events began at `2026-06-05T01:31:07.3366763Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "nate-th-vm"  
| where InitiatingProcessAccountName == "n4t3"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-06-05T01:31:07.3366763Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1718" height="585" alt="image" src="https://github.com/user-attachments/assets/f9cb12d3-f96a-429a-82af-62539327b2ac" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2026-06-05T01:35:37.6102838Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "nate-th-vm"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="982" height="243" alt="image" src="https://github.com/user-attachments/assets/bc2be5fe-2259-4481-81fe-fda5ccdc3e23" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "n4t3" actually opened the TOR browser. There was evidence that they did open it at `2026-06-05T01:36:43.50353Z`. There were several other instances of `firefox.exe` (TOR).

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "nate-th-vm"  
| where FileName has_any ("tor.exe", "firefox.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="971" height="382" alt="image" src="https://github.com/user-attachments/assets/ce8c1803-dc0b-476f-8bd5-909d4fadba09" />


---

<img width="976" height="343" alt="image" src="https://github.com/user-attachments/assets/d4e8c7b5-33be-40cf-8bfc-dec2fff99c98" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-06-05T01:37:52.8196718Z`, an n4t3 on the "nate-th-vm" device successfully established a connection to the remote IP address `15.204.175.29` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\n4t3\desktop\tor browser\browser\torbrowser\tor\tor.exe`. This activity indicates that the Tor client successfully connected to the Tor network and began routing traffic through the anonymity service

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "nate-th-vm"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="895" height="341" alt="image" src="https://github.com/user-attachments/assets/f3f5f8e5-133f-40d3-88cc-bee7e6a08e70" />



---

Chronological Event Timeline

### 1. File Download - TOR Installer

**Timestamp:** 2026-06-05T01:31:07.3366763Z

**Event:** The user "n4t3" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.15.exe` to the Downloads folder.

**Action:** File download detected.

**File Path:**
C:\Users\n4t3\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe

---

### 2. Process Execution - TOR Browser Installation

**Timestamp:** 2026-06-05T01:35:37.6102838Z

**Event:** The user "n4t3" executed the file `tor-browser-windows-x86_64-portable-15.0.15.exe` in silent mode, initiating a background installation of the TOR Browser.

**Action:** Process creation detected.

**Command:**
tor-browser-windows-x86_64-portable-15.0.15.exe /S

**File Path:**
C:\Users\n4t3\Downloads\tor-browser-windows-x86_64-portable-15.0.15.exe

---

### 3. Process Execution - TOR Browser Launch

**Timestamp:** 2026-06-05T01:36:43.50353Z

**Event:** User "n4t3" launched the TOR Browser. Subsequent TOR-related processes, including `firefox.exe` and `tor.exe`, were created, indicating the browser launched successfully.

**Action:** Process creation of TOR Browser-related executables detected.

**File Path:**
C:\Users\n4t3\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

---

### 4. Network Connection - TOR Network

**Timestamp:** 2026-06-05T01:37:52.8196718Z

**Event:** A network connection to IP address `15.204.175.29` on port `9001` was established by user "n4t3" using `tor.exe`, confirming TOR network activity.

**Action:** Connection success.

**Process:**
tor.exe

**File Path:**
C:\Users\n4t3\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

---

### 5. Additional Network Connections - TOR Browser Activity

**Timestamps:**

* 2026-06-05T01:37:54Z - Connected to `152.53.18.121` on port `9001`
* 2026-06-05T01:37:54Z - Connected to `185.80.30.102` on port `9001`
* 2026-06-05T01:38:01Z - Local connection to `127.0.0.1` on port `9150`

**Event:** Additional TOR network connections were established, indicating ongoing TOR Browser activity and successful routing of browser traffic through the TOR network.

**Action:** Multiple successful connections detected.

---

### 6. File Creation - TOR Shopping List

**Timestamp:** 2026-06-05T01:54:13.4810532Z

**Event:** The user "n4t3" created a file named `tor-shopping-list.txt` on the desktop after TOR Browser activity was observed.

**Action:** File creation detected.

**File Path:**
C:\Users\n4t3\Desktop\tor-shopping-list.txt

---

## Summary

The user "n4t3" on the device "nate-th-vm" downloaded and installed the TOR Browser using a silent installation process. The browser was subsequently launched, resulting in the creation of TOR-related processes including `firefox.exe` and `tor.exe`. Network telemetry confirmed successful connections to TOR relay nodes over TCP port 9001 and communication with the local TOR SOCKS proxy on port 9150, demonstrating active TOR Browser usage. Following the TOR session, the user created a file named `tor-shopping-list.txt` on the desktop, indicating additional activity associated with the TOR Browser session.

## Response Taken

TOR Browser usage was confirmed on endpoint "nate-th-vm" by user "n4t3". The activity was documented and escalated for review in accordance with organizational security procedures.

