# RSAT - Remote Security Audit Tool

RSAT is a lightweight, cross-platform security assessment instrument designed for consultants and IT professionals. It executes a "one-shot" audit of a client endpoint—detecting encryption status, network vulnerabilities, and hygiene issues—without requiring installation or pre-existing dependencies.

The tool compiles into a standalone zero-dependency binary that generates a professional, self-contained HTML report in seconds.

## 🚀 Key Features

RSAT interrogates the native OS kernel and subsystems to provide a definitive "source of truth" audit:

| Security Domain | Windows Checks | macOS Checks |
| :--- | :--- | :--- |
| **🔐 Disk Encryption** | Verifies BitLocker status, protection level, and suspension states (via PowerShell/manage-bde). | Verifies FileVault 2 status and encryption progress (via fdesetup). |
| **🛡️ Network Defense** | Audits Windows Defender Firewall profiles (Domain, Private, Public). | Audits Application Firewall (ALF) state and Stealth Mode configuration. |
| **📡 Port Scanning** | Multi-threaded scan of high-risk ports: 21, 22, 23, 25, 53, 80, 139, 445, 3389, 5900, 8080. Only reports Open/Exposed ports. | Same architecture using BSD Sockets. |
| **🩹 System Hygiene** | Checks Registry for Pending Reboot flags (Windows Update/Component Based Servicing). | Checks `SoftwareUpdate.plist` for pending recommended updates. |
| **📊 Reporting** | Generates a locally saved `Audit_Report_[Hostname].html` with embedded CSS and logic-based color coding (Pass/Fail/Warn). | Same structure. |

## 🏗️ Technical Architecture

RSAT is engineered with a Zero-Dependency philosophy. It avoids heavy third-party libraries that bloat binary size or introduce supply chain risks.

### 1. Hybrid Execution Model
The tool uses Python for control logic but outsources data gathering to native OS binaries. This ensures the audit relies on the OS's own "Source of Truth" rather than potentially outdated Python wrappers.
* **Windows:** Uses `ctypes` to call Win32 APIs and `subprocess` to invoke PowerShell/manage-bde.
* **macOS:** Uses `plistlib` to parse system preferences and `subprocess` to invoke fdesetup/socketfilterfw.

### 2. Autonomous Privilege Escalation
Security auditing requires administrative access. RSAT implements a self-elevation mechanism:
* **Windows:** Detects privileges via `shell32.IsUserAnAdmin()`. If false, it re-launches itself using `ShellExecuteW` with the `runas` verb to trigger the UAC prompt.
* **macOS:** Detects root via `os.getuid()`. If false, it re-launches via `os.execvp` using `sudo`, prompting the user for their password in the terminal.

### 3. Cross-Platform Compilation
The build system utilizes **PyInstaller** to bundle the Python interpreter and script into a single executable file (`.exe` for Windows, Mach-O binary for macOS). This eliminates the need for the client to have Python installed.

## 📥 Usage (For Clients)

**No Python knowledge or installation is required.**

1. Navigate to the **Releases** page of this repository.
2. Download the binary for your system:
    * Windows: `AuditTool_Windows.exe`
    * macOS: `AuditTool_macOS`
3. **Run with Privileges:**

**Windows:**
Right-click the file and select "Run as Administrator".

**macOS:**
Open your terminal, navigate to the download folder, and run:
```bash
sudo ./AuditTool_macOS
```

> **Note:** Administrative privileges are strictly required to query BitLocker keys, Firewall profiles, and Global System Updates. The tool will auto-generate an HTML report in the same folder.

## 🛠️ Development & Build Setup

To contribute or build the binary locally, follow these steps.

### 1. Clone the Repository
```bash
git clone [https://github.com/Kajahkura/RSAT_Project.git](https://github.com/Kajahkura/RSAT_Project.git)
cd RSAT_Project
```

### 2. Set up Virtual Environment
```bash
python -m venv venv

# Windows:
venv\Scripts\activate

# macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
The tool relies on the Python Standard Library (`os`, `sys`, `socket`, `subprocess`, `ctypes`) for logic. The only external dependency is PyInstaller for the build process.

```bash
pip install -r requirements.txt
```

### 4. Run from Source
```bash
python src/audit_tool.py
```

### 5. Build Binary Locally
To create the standalone executable (frozen binary):

```bash
pyinstaller --onefile --console --clean --name AuditTool_Local src/audit_tool.py
```
The executable will appear in the `dist/` folder.

## ⚙️ CI/CD Pipeline

This project utilizes GitHub Actions for automated cross-platform compilation.

* **Workflow File:** `.github/workflows/build.yml`
* **Trigger:** The build pipeline runs automatically when a new tag (e.g., `v1.0.0`) is pushed.
* **Matrix Strategy:** Builds simultaneously on `windows-latest` and `macos-latest` runners to ensure native binary compatibility.

## ⚠️ Disclaimer

**This tool is for authorized security auditing purposes only.**

Port scanning and security enumeration without permission may be illegal in certain jurisdictions. The author assumes no liability for the misuse of this software or for any damage caused by the software. Always ensure you have explicit permission from the system owner before running this tool.

## 📄 License

This project is licensed under the MIT License.

**Copyright (c) 2025 OFINFIX**

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
