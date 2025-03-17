# Incident Response Report - Premium House Lights
- [Threat Scenario](scenario-PHL.md)

## Platforms and Languages Leveraged
- Wireshark

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.


### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Analysis of Webserver Logs

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-02-05T21:57:08.5445515Z`. These events began at `2025-02-05T21:36:20.8753533Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "employee"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-05T21:36:20.8753533Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/d0bf7915-5078-4dec-a463-78d89f6aa449)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.5.exe". Based on the logs returned, at `2025-02-05T21:38:29.9122643Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/36112462-3652-458d-96da-b5037ac03080)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-02-05T21:39:29.3972508Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/1a30f4c9-b824-45f2-8b04-f02efc595f1e)

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-02-05T21:39:55.3308187Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "443", "80")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/2dccf940-1fbb-48fd-934e-f129a22d8511)

---

## Chronological Event Timeline 

![Image](https://github.com/user-attachments/assets/73e09489-724e-4c9b-a384-3568e15ddd43)

### **1️⃣ Tor Browser Download**
- **🕒 Timestamp:** `2025-02-05T16:36:20 UTC`
- **📂 Event Type:** File Download
- **💻 Device:** `threat-hunt-lab`
- **👤 User:** `employee`
- **🔍 Details:**
  - The file **"tor-browser-windows-x86_64-portable-14.0.5.exe"** was **downloaded** into the **Downloads** folder.
  - This indicates **intentional** acquisition of the Tor browser.

---

### **2️⃣ Tor Browser Installation**
- **🕒 Timestamp:** `2025-02-05T16:38:29 UTC`
- **📂 Event Type:** Process Execution (Installation)
- **💻 Device:** `threat-hunt-lab`
- **👤 User:** `employee`
- **🔍 Details:**
  - The user executed **"tor-browser-windows-x86_64-portable-14.0.5.exe"** with the **"/S"** flag (**silent installation**).
  - **File Hash (SHA256):** `c5bb78b482300188ab228ed36251ab1ef208cc48a0a50864f2db7454debfc04e`
  - The installation was performed inside the **Downloads** folder.

---

### **3️⃣ Creation of Tor Browser Files**
- **🕒 Timestamp:** `2025-02-05T16:39:00 UTC`
- **📂 Event Type:** File Creation
- **💻 Device:** `threat-hunt-lab`
- **👤 User:** `employee`
- **🔍 Details:**
  - Several **Tor-related configuration files** were created:
    - `Tor-Launcher.txt`
    - `Torbutton.txt`
    - `Tor.txt`
  - These files were stored inside:  
    **`C:\Users\employee\Desktop\Tor Browser\Browser\`**
  - Indicates **successful installation and configuration** of Tor.

---

### **4️⃣ Tor Browser Execution**
- **🕒 Timestamp:** `2025-02-05T16:39:29 UTC`
- **📂 Event Type:** Process Execution
- **💻 Device:** `threat-hunt-lab`
- **👤 User:** `employee`
- **🔍 Details:**
  - The user **launched** `tor.exe`, initiating the **Tor browser**.
  - Multiple **firefox.exe** processes (Tor-based) were created, confirming active usage.

---

### **5️⃣ Establishing Tor Network Connections**
- **🕒 Timestamp:** `2025-02-05T16:39:55 - 16:40:06 UTC`
- **📂 Event Type:** Network Connection
- **💻 Device:** `threat-hunt-lab`
- **👤 User:** `employee`
- **🔍 Details:**
  - The **tor.exe** process established connections to known **Tor relay nodes**:
    - **88.99.142.177:9001**
    - **176.198.159.33:9001**
    - **127.0.0.1:9150** (local proxy connection)
    - **94.23.88.117:443** (HTTPS)
  - The browser accessed **Tor-specific URLs**, such as:
    - `https://www.xmh4xtbgfzpy3em.com`
    - `https://www.mhvt.com`
    - `https://www.wfb4ikugupgn4.com`
  - Confirms **successful Tor network access**.

---

### **6️⃣ Suspicious File Creation: "tor-shopping-list.txt"**
- **🕒 Timestamp:** `2025-02-05T16:57:08 UTC`
- **📂 Event Type:** File Created
- **💻 Device:** `threat-hunt-lab`
- **👤 User:** `employee`
- **🔍 Details:**
  - A file named **"tor-shopping-list.txt"** was created inside:
    - **`C:\Users\employee\Documents\`**
  - This file could contain **details related to Tor activity**, such as:
    - **Visited sites**
    - **Credentials**
    - **Planned actions**
  - **Further analysis recommended** to determine its content.

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
