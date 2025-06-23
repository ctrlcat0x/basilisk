# <p align="center">Basilisk - Windows 11 Debloating Utility </p>

<p align="center">
  <img src="banner.png" alt="Basilisk Banner" width="800">
</p>

<p align="center">
  <strong>A comprehensive Windows 11 debloating utility that automates the process of removing bloatware, optimizing system settings, and configuring a clean Windows environment in just a single click.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-system-requirements">Requirements</a> •
  <a href="#-installation--usage">Installation</a> •
  <a href="#-safety--compatibility">Safety</a> •
  <a href="#-contributing">Contributing</a>
</p>

---

## ⚠️ Important Notice

> **Basilisk is designed to be used on freshly installed Windows 11 systems.** Using Basilisk on an already in-use system, or any older versions of Windows, is not guaranteed to work and can cause some apps to stop working properly and system corruption!

> **You must disable Real-time Protection, Tamper Protection & add a C:/ drive exclusion in windows security before running basilisk.**

## ✨ Features

- 🚀 **Automated Debloating** - Removes Windows bloatware and unnecessary applications
- ⚡ **System Optimization** - Applies registry tweaks for better performance
- 🌐 **Network Optimization Tweaks** - Disables Delivery Optimization, tunes TCP/IP, and improves network performance
- 🛡️ **Telemetry & Tracking Blocker** - Blocks known Microsoft telemetry and ad servers at the hosts file level
- 💾 **SSD & Hardware-Specific Optimizations** - Detects SSDs, enables TRIM, disables scheduled defrag, and applies hardware-specific tweaks
- 🔧 **Update Policy Configuration** - Configures Windows Update policies based on your edition
- 🎨 **Custom Desktop Background** - Sets a custom desktop wallpaper
- 🖥️ **User-Friendly Interface** - Simple GUI with progress tracking
- 📝 **Comprehensive Logging** - Detailed logging for troubleshooting
- 🛡️ **Safety First** - Creates system restore points before modifications

## 📋 System Requirements

- **Operating System**: Windows 11 Home or Professional (fresh pro installation recommended)
- **Architecture**: x64
- **Python**: 3.12.4 or greater (for development)
- **Administrator Privileges**: Required for system modifications
- **Internet Connection**: Required for downloading scripts and system optimization

## 🚀 Installation & Usage

### Quick Start (One-Liner)

Run Basilisk directly from GitHub with a single command:

```powershell
iex (irm https://raw.githubusercontent.com/ctrlcat0x/basilisk/master/scripts/run.ps1)
```

**Requirements:**
- PowerShell (run as Administrator)
- Internet connection
- Windows 11

This command will automatically:
- Configure Windows Defender settings
- Download the latest Basilisk executable
- Launch Basilisk with administrator privileges

### Pre-built Binary (Recommended)

1. Download the latest version from [GitHub Releases](https://github.com/ctrlcat0x/basilisk/releases)
2. Temporarily whitelist your C: drive in Windows Defender
3. **Run as Administrator**
4. Follow the on-screen prompts (if any)

### Building from Source

#### Prerequisites
```bash
# Install Python 3.12.4 or greater
# Install required dependencies
pip install -r requirements.txt
```

#### Build Process
```bash
# Run the build script
build.bat
```

The build process uses Nuitka to create a standalone executable with PyQt5 GUI framework and all dependencies bundled.

### Command Line Options

```bash
# Developer mode (no installation overlay)
python basilisk.py --developer-mode

# Skip specific steps
python basilisk.py --skip-download-scripts-step
python basilisk.py --skip-registry-tweaks-step
python basilisk.py --skip-configure-updates-step
# ... etc for all 7 steps
```

## 📦 Automatically Installed Applications

Basilisk can automatically install several useful applications during the debloating process. These installations are handled by the external tools (ChrisTitusTech WinUtil) that Basilisk integrates with.

### 🛠️ Core Development & System Tools
- **Microsoft Windows Terminal** - Modern terminal emulator with tabs and customization
- **Git** - Distributed version control system for software development
- **7-Zip** - High-compression file archiver and extractor
- **Microsoft Visual C++ Redistributables (2015+)** - Essential runtime libraries
  - x86 version for 32-bit applications
  - x64 version for 64-bit applications

### 🌐 Web Browsers
- **Brave Browser** - Privacy-focused web browser with built-in ad blocking
- **Zen Browser** - Alternative web browser with enhanced privacy features

### 🔧 Development Runtime
- **Microsoft .NET Desktop Runtime 8** - .NET framework for desktop applications
- **Microsoft .NET Desktop Runtime 9** - Latest .NET framework version
- **Microsoft Edge WebView2 Runtime** - Web component framework for applications

### 📋 Installation Method
Applications are installed using **WinGet** (Windows Package Manager) as the primary method, with Chocolatey as a fallback option.

### ⚠️ Important Notes
- **External Tool Dependency**: Installation is handled by ChrisTitusTech WinUtil, not directly by Basilisk
- **User Choice**: Installation may be configurable or optional depending on WinUtil settings
- **System Requirements**: Some applications require specific Windows versions or prerequisites
- **Installation Success**: Individual package installation success depends on system compatibility and network connectivity

## 🏗️ Architecture Overview

Basilisk follows a modular 8-step debloating process:

1. **📥 Download Scripts** - Downloads PowerShell scripts from Github servers
2. **🦅 Execute Scripts** - Runs custom scripts for Edge removal and Office Online cleanup
3. **🔧 Execute External Scripts** - Runs ChrisTitusTech WinUtil and Raphi's Win11Debloat
4. **🔒 Execute Privacy.sexy** - Runs comprehensive privacy and security hardening
5. **⚙️ Registry Tweaks** - Applies visual and performance registry modifications
6. **🚀 Advanced Optimizations** - Enables Ultimate Performance, disables telemetry, removes UWP apps
7. **🔄 Configure Updates** - Sets appropriate update policies for your Windows edition
8. **🎨 Apply Background** - Sets custom desktop wallpaper and cleans up temporary files

## 🛡️ Safety & Compatibility

### Safety Measures
- ✅ **Pre-installation Checks** - Validates system compatibility
- ✅ **Restore Point** - System restore point created before any changes
- ✅ **Error Handling** - Comprehensive error catching and user feedback
- ✅ **Logging** - Detailed logs for troubleshooting
- ✅ **Rollback Protection** - Safe registry modifications

### Compatibility
- **Windows 11 Home/Pro** - Primary target
- **Fresh Installations** - Recommended for best results
- **Administrator Rights** - Required for system modifications

## 📁 Project Structure

```
basilisk/
├── basilisk.py                 # Main application entry point
├── debloat_components/         # 7-step debloating process
├── ui_components/              # GUI components and styling
├── utilities/                  # Core utility functions
├── screens/                    # UI screens and overlays
├── scripts/                    # PowerShell scripts
├── configs/                    # Configuration files
├── media/                      # Assets (backgrounds, icons, fonts)
└── preinstall_components/      # Pre-installation checks
```

## 🔧 Technical Details

### PowerShell Scripts Used
- **ChrisTitusTech WinUtil** - Comprehensive Windows optimization
- **Raphi Win11Debloat** - Additional debloating and customization
- **Privacy.sexy** - Comprehensive privacy and security hardening
- **Custom Scripts** - Edge removal and Office Online cleanup

### Advanced Optimizations
- **Network Tweaks**: Disables Windows Delivery Optimization, tunes TCP/IP stack, disables NetBIOS, and optimizes network adapter settings for better speed and lower background usage.
- **Telemetry & Tracking Blocker**: Updates the Windows hosts file to block a curated list of Microsoft telemetry and ad servers, reducing unwanted data collection.
- **SSD & Hardware-Specific Optimizations**: Detects SSDs, enables TRIM, disables scheduled defrag, disables Superfetch, and applies other hardware-specific performance tweaks.

### Registry Modifications
- Taskbar alignment (left-aligned)
- Dark theme enforcement
- Game DVR disable
- Menu animation optimizations
- File extension visibility
- UI hover time adjustments

### System Optimization
- **Restore Point** - Basilisk creates a system restore point before any changes
- **Comprehensive Debloat** - Uses multiple tools for thorough optimization
- **UWP App Removal** - Directly removes pre-installed UWP apps
- **Temp File Cleanup** - Cleans up temporary files and system cache after completion

## 📝 Logging

Basilisk provides comprehensive logging for troubleshooting:
- **File Location**: `%TEMP%\basilisk\` directory
- **Log Levels**: DEBUG, INFO, WARNING, ERROR
- **Content**: Step-by-step execution details and error information

## 🤝 Contributing

We welcome contributions from the community! Here's how you can help:

### Development Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run in development mode: `python basilisk.py --developer-mode`

### Code Structure
- **Modular Design** - Each component is self-contained
- **Error Handling** - Comprehensive exception management
- **Type Hints** - Python type annotations for better code quality
- **Documentation** - Inline comments and docstrings

### Core External Tools & Scripts
**The project would never have been possible without the extensive research and work done by these developers of windows optimization software which serves as the core of basilisk.**
- [Talon by Raven Development Team](https://github.com/ravendevteam/talon)
- [ChrisTitusTech](https://github.com/christitustech) - [CTT WinUtil](https://github.com/christitustech/winutil)
- [Raphire](https://github.com/Raphire) - [Win11Debloat](https://github.com/Raphire/Win11Debloat)
- [undergroundwires](https://github.com/undergroundwires) - [privacy.sexy](https://github.com/undergroundwires/privacy.sexy)
- [Massgrave Activation Script](https://github.com/massgravel/Microsoft-Activation-Scripts)

## 📄 License

**Anyone and everyone is free to use or modify the project as long as there is no monetary benefits from it.**

## ⚠️ Disclaimer

This tool modifies system settings and registry values. While designed to be safe, it's recommended to:
- Use on fresh Windows 11 installations
- Basilisk automatically creates a system restore point before use
- Test in a virtual environment first
- Understand that some modifications may affect system functionality

The developers are not responsible for any data loss or system issues that may occur from using this tool.

---

<p align="center">
  <strong>Made with ❤️ by ctrlcat0x</strong>
</p> 
