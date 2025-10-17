# WinCare

**Professional Windows Maintenance & Optimization Tool**

---

## 📋 Overview

**WinCare** is a comprehensive, lightweight Windows maintenance and optimization tool designed to keep your system running smoothly. It provides an intuitive interface for cleaning temporary files, managing startup applications, repairing common system issues, and applying safe performance tweaks.

Available in two editions:
- **PowerShell Script** (`wincare.ps1`) - Flexible command-line interface
- **GUI Application** (`WinCarePro.exe`) - User-friendly graphical interface

## ✨ Features

### 🧹 Cleaning & Optimization
- **Temporary Files Cleanup** - Remove temp files, cache, and logs
- **Browser Cache Cleaning** - Clear cache from Chrome, Edge, and Firefox
- **Windows Update Cache** - Clean outdated update components
- **Recycle Bin Management** - Quick emptying of recycle bin
- **Disk Optimization** - Smart defragmentation for HDDs and TRIM for SSDs

### 🔧 System Repair & Maintenance
- **System File Checker (SFC)** - Repair corrupted system files
- **DISM RestoreHealth** - Fix Windows component store corruption
- **Check Disk (CHKDSK)** - Scan and repair disk errors
- **Network Stack Reset** - Fix DNS and networking issues
- **Windows Update Repair** - Reset Windows Update components

### ⚡ Performance Enhancement
- **Startup Application Analysis** - Manage programs that run at boot
- **Service Optimization** - Identify and optimize unnecessary services
- **Smart Recommendations** - AI-driven suggestions based on system state

### 🛡️ Security & Safety
- **Windows Defender Quick Scan** - Fast malware detection
- **System Restore Points** - Create backup points before changes
- **Safe Operations** - Clear prompts and reversible actions
- **Detailed Logging** - Complete activity logs for troubleshooting

### 📊 System Information
- **Health Overview** - Comprehensive system status display
- **Installed Updates List** - View recent Windows updates
- **Driver Inventory** - Complete list of installed drivers
- **System Report Generation** - Detailed HTML/text reports

### 🤖 Auto Mode
- **One-Click Maintenance** - Automated safe cleaning and optimization
- **Smart Detection** - Automatically identifies issues needing attention
- **Progress Tracking** - Real-time status updates

## 💻 System Requirements

### Compatibility

| Operating System | Support Status |
|-----------------|----------------|
| Windows 11 (21H2+) | ✅ Fully Supported |
| Windows 10 (1607+) | ✅ Fully Supported |
| Windows 8.1 | ⚠️ Limited Support |
| Windows 7 | ⚠️ Basic Support |

### Architecture Support
- **x64** (Recommended)
- **x86** (32-bit)
- **ARM64** (PowerShell edition only)

### PowerShell Edition Requirements
- PowerShell 5.1 or higher (pre-installed on Windows 10/11)
- Administrator privileges for system-level operations
- Execution policy allowing local scripts

### GUI Edition Requirements
- .NET Desktop Runtime (version depends on release)
- Administrator rights for most operations
- Display resolution: 1280x720 minimum

## 📥 Installation

### Method 1: Download from GitHub

1. Visit the [releases page](https://github.com/almezali/wincare/releases)
2. Download the latest release archive
3. Extract to a convenient location (e.g., `C:\Tools\WinCare`)
4. Run as Administrator

### Method 2: Clone Repository

```bash
git clone https://github.com/almezali/wincare.git
cd wincare
```

## 🚀 Usage

### PowerShell Edition

#### Basic Usage

1. **Open PowerShell as Administrator**
   - Right-click Start → Windows PowerShell (Admin)

2. **Allow Script Execution** (choose one method):

   ```powershell
   # Option A: Temporarily allow for current session
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
   
   # Option B: Unblock specific file (recommended)
   Unblock-File -Path .\wincare.ps1
   ```

3. **Run WinCare**

   ```powershell
   .\wincare.ps1
   ```
   4. **OR Run WinCare**
   ```powershell
    powershell -ExecutionPolicy Bypass -File wincare.ps1
    ```

#### Advanced Usage with Parameters

```powershell
# Clean temporary files
.\wincare.ps1 -CleanTemp

# Fix DNS and network issues
.\wincare.ps1 -FixDNS

# Reset Windows Update components
.\wincare.ps1 -ResetWU

# Verbose output
.\wincare.ps1 -Verbose

# Combine multiple tasks
.\wincare.ps1 -CleanTemp -FixDNS -ResetWU -Verbose
```

#### Available Parameters

| Parameter | Description |
|-----------|-------------|
| `-CleanTemp` | Remove temporary files and caches |
| `-FixDNS` | Flush DNS and re-register network settings |
| `-ResetWU` | Reset Windows Update components |
| `-Verbose` | Show detailed output |
| `-DryRun` | Simulate actions without making changes |

### GUI Edition (WinCarePro.exe)

1. **Right-click** `WinCarePro.exe`
2. Select **"Run as Administrator"**
3. Choose desired actions from the interface
4. Review prompts and confirm operations
5. Monitor progress through status indicators

## 📸 Screenshots

### Main Interface
![WinCare Main Interface](https://github.com/almezali/wincare/blob/main/01-wincare.png)
*Clean, intuitive main menu with system information and recommendations*

### Action Panel
![WinCare Actions](https://github.com/almezali/wincare/blob/main/02-wincare.png)
*Comprehensive action panel with progress tracking*

## 🎯 Key Features Explained

### 🤖 Auto Mode
Automatically performs safe maintenance tasks:
- Cleans temporary files
- Clears browser cache
- Optimizes startup applications
- Analyzes services
- Generates system report

Perfect for regular maintenance without manual intervention.

### 📊 Smart Recommendations
WinCare analyzes your system and provides intelligent recommendations:
- **Critical alerts** for low disk space
- **Warnings** for high disk usage
- **Suggestions** for system file checks
- **Reminders** for pending reboots
- **Advice** based on system uptime

### 🔒 Safety First
- **Dry-Run Mode** - Test operations without changes
- **Clear Prompts** - Confirm before critical actions
- **Restore Points** - Create backups before modifications
- **Detailed Logging** - Track all operations
- **Reversible Actions** - Undo most changes

## 🛠️ Troubleshooting

### Common Issues

**"Execution Policy" Error**
```powershell
# Run this command to allow the script
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

**"Access Denied" Error**
- Ensure you're running as Administrator
- Right-click PowerShell/App → "Run as Administrator"

**Antivirus Blocking**
- Temporarily disable aggressive antivirus software
- Add WinCare to your antivirus whitelist

**GUI Not Opening**
- Install latest .NET Desktop Runtime
- Check Windows Event Viewer for errors

**Operations Fail Silently**
- Check the log file: `C:\ProgramData\WinCare\Logs\`
- Run with `-Verbose` parameter for details

## 📝 Logging

WinCare maintains detailed logs for all operations:

**Log Location**: `C:\ProgramData\WinCare\Logs\`

**Log Format**: `wincare-YYYYMMDD-HHMMSS.log`

**Log Levels**:
- `[INFO]` - General information
- `[SUCCESS]` - Successful operations
- `[WARN]` - Warnings (non-critical)
- `[ERROR]` - Error conditions

## 🔐 Security & Privacy

- **No Data Collection** - WinCare doesn't send any data externally
- **Local Operations** - All processing happens on your machine
- **Open Source** - Code is fully transparent and auditable
- **No Hidden Actions** - Every operation is logged and visible
- **Administrator Required** - Prevents unauthorized usage

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit your changes**
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push to the branch**
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open a Pull Request**

### Contribution Guidelines
- Test on Windows 10 and 11 if possible
- Include detailed description of changes
- Follow existing code style
- Update documentation as needed
- Add comments for complex logic


## 👨‍💻 Author

**Mahmoud Almezali**
- GitHub: [@almezali](https://github.com/almezali)
- Company: Multitech

## 🙏 Acknowledgments

- Thanks to all contributors
- Inspired by Windows built-in maintenance tools
- Community feedback and suggestions

## 📞 Support

Need help? Here are your options:

- **Issues**: [GitHub Issues](https://github.com/almezali/wincare/issues)
- **Discussions**: [GitHub Discussions](https://github.com/almezali/wincare/discussions)
- **Documentation**: Check the [Wiki](https://github.com/almezali/wincare/wiki)

## ⚠️ Disclaimer

**Use at your own risk.** While WinCare is designed with safety in mind and uses conservative defaults, system modifications can have unintended consequences. Always:

- ✅ Create a restore point before major changes
- ✅ Back up important data regularly
- ✅ Test in a non-production environment first
- ✅ Review operations before confirming
- ✅ Keep system backups

The authors and contributors are not responsible for any damage or data loss resulting from the use of this tool.

## 🔄 Changelog

### Version 2.0 (Current)
- ✨ Complete UI overhaul with ASCII art banner
- 🚀 Auto Mode for one-click maintenance
- 🧠 Smart system recommendations
- 📊 Enhanced system detection
- 🎨 Improved color-coded output
- 📝 Better logging and error handling
- 🔧 Browser cache cleaning
- 🛡️ Dry-run mode for testing

### Version 1.0
- Initial release
- Basic cleanup functions
- System file checker integration
- Network reset tools

---


**⭐ Star this repository if you find it helpful!**

Made with ❤️ by [Mahmoud Almezali](https://github.com/almezali)

[Report Bug](https://github.com/almezali/wincare/issues) • [Request Feature](https://github.com/almezali/wincare/issues) • [Documentation](https://github.com/almezali/wincare/wiki)
