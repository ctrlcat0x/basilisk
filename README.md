# Basilisk - Windows 11 Debloating Utility

<p align="center">
  <img src="banner.png" alt="Basilisk Banner" width="800">
</p>

> [!NOTE]
> All of our free software is designed to respect your privacy, while being as simple to use as possible. Our free software is licensed under the [BSD-3-Clause license](https://ravendevteam.org/files/BSD-3-Clause.txt). By using our software, you acknowledge and agree to the terms of the license.

**Basilisk** is a comprehensive Windows 11 debloating utility that automates the process of removing bloatware, optimizing system settings, and configuring a clean Windows environment in just a few clicks.

> [!CAUTION]
> Basilisk is designed to be used on **freshly installed Windows 11 systems**. Trying to use Basilisk on an already in-use system, or any older versions of Windows, is not guaranteed to work and can cause some apps to stop working properly and system corruption!

## 🚀 Features

- **Automated Debloating**: Removes Windows bloatware and unnecessary applications, including UWP apps via Basilisk's own advanced step
- **System Optimization**: Applies registry tweaks for better performance and visual improvements
- **Update Policy Configuration**: Configures Windows Update policies based on your edition
- **Custom Desktop Background**: Sets a custom desktop wallpaper
- **User-Friendly Interface**: Simple GUI with progress tracking
- **Comprehensive Logging**: Detailed logging for troubleshooting

## 📋 System Requirements

- **Operating System**: Windows 11 Home or Professional (fresh installation recommended)
- **Architecture**: x64
- **Python**: 3.12.4 or greater (for development)
- **Administrator Privileges**: Required for system modifications
- **Internet Connection**: Required for downloading scripts and system optimization

## 🏗️ Project Architecture

### Core Components

#### Main Application (`basilisk.py`)
The entry point of the application that orchestrates the entire debloating process:

- **Argument Parsing**: Supports developer mode and step skipping
- **Screen Management**: Launches UI screens for user interaction
- **Installation UI**: Creates overlay interface during installation
- **Process Orchestration**: Manages the 7-step debloating sequence

#### Debloating Steps (7-Step Process)

1. **Download Scripts** (`debloat_download_scripts.py`)
   - Downloads PowerShell scripts from Raven Development Team servers
   - Scripts: `edge_vanisher.ps1`, `uninstall_oo.ps1`, `update_policy_changer.ps1`, `update_policy_changer_pro.ps1`

2. **Execute Raven Scripts** (`debloat_execute_raven_scripts.py`)
   - Runs custom PowerShell scripts for initial debloating
   - Removes Edge browser and Office Online components

3. **Execute External Scripts** (`debloat_execute_external_scripts.py`)
   - Runs ChrisTitusTech WinUtil with custom configuration
   - Executes Raphi's Win11Debloat script with comprehensive settings
   - Applies extensive system optimizations

4. **Registry Tweaks** (`debloat_registry_tweaks.py`)
   - Applies visual and performance registry modifications
   - Configures taskbar alignment, theme settings, and UI optimizations
   - Disables Game DVR and other unnecessary features

5. **Advanced Optimizations** (`debloat_advanced_optimizations.py`)
   - Applies additional system debloat and hardening steps:
     - Enables Ultimate Performance power plan
     - Disables Windows Defender, telemetry, Cortana, and non-essential services
     - Removes pre-installed UWP apps (handled by Basilisk, not just external scripts)
     - Disables ads, tracking, search indexing, and more

6. **Configure Updates** (`debloat_configure_updates.py`)
   - Detects Windows edition (Home vs Pro/Enterprise)
   - Applies appropriate update policy configuration
   - Uses different scripts for different editions

7. **Apply Background** (`debloat_apply_background.py`)
   - Sets custom desktop wallpaper
   - Uses bundled `background.png` from media directory
   - **After this step, Basilisk automatically cleans up temporary files and system cache**

### User Interface Components

#### Screens (`screens/`)
- **Installation Progress** (`screen_installing.py`): Shows installation overlay with progress

#### UI Components (`ui_components/`)
- **Base UI** (`ui_base_full.py`): Main window framework with overlays
- **Text Components**: Title, header, and paragraph text widgets
- **Interactive Elements**: Buttons and image display components
- **Custom Styling**: Consistent visual design with Rockstar font

### Utility Functions (`utilities/`)

#### System Checks
- **Admin Check** (`util_admin_check.py`): Ensures administrator privileges
- **Windows Check** (`util_windows_check.py`): Validates Windows 11 Home/Pro
- **Defender Check** (`util_defender_check.py`): Manages Windows Defender settings

#### Core Utilities
- **Logger** (`util_logger.py`): Comprehensive logging system
- **Error Handling** (`util_error_popup.py`): User-friendly error displays
- **PowerShell Handler** (`util_powershell_handler.py`): PowerShell script execution
- **Registry Modifier** (`util_modify_registry.py`): Safe registry operations
- **Download Handler** (`util_download_handler.py`): File download management

#### Threading and SSL
- **Thread Handler** (`util_debloat_thread_handler.py`): Background process management
- **SSL Context** (`util_ssl.py`): Secure connection handling

### Configuration (`configs/`)
- **Default Configuration** (`default.json`): WinUtil tweaks configuration
- **WPFTweaks**: Comprehensive list of Windows optimization settings

### Media Assets (`media/`)
- **Images**: Desktop background (`background.png`), icons
- **Fonts**: Rockstar ExtraBold font for UI styling

## 🔧 Installation & Usage

### Pre-built Binary
1. Download the latest version from [debloat.win](https://debloat.win)
2. Temporarily whitelist your C: drive in Windows Defender
3. Run as Administrator
4. Follow the on-screen prompts

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

The build process uses Nuitka to create a standalone executable with:
- PyQt5 GUI framework
- All dependencies bundled
- Windows UAC admin requirement
- Custom icon and branding

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

## 🔍 Technical Details

### PowerShell Scripts Used
- **ChrisTitusTech WinUtil**: Comprehensive Windows optimization
- **Raphi Win11Debloat**: Additional debloating and customization
- **Custom Raven Scripts**: Edge removal and Office Online cleanup

### Registry Modifications
- Taskbar alignment (left-aligned)
- Dark theme enforcement
- Game DVR disable
- Menu animation optimizations
- File extension visibility
- UI hover time adjustments

### System Optimization
- **Restore Point**: Basilisk creates a system restore point before any changes for safety
- **Comprehensive Debloat**: Uses ChrisTitusTech WinUtil, Raphi Win11Debloat, and Basilisk's own advanced optimizations
- **UWP App Removal**: Basilisk directly removes pre-installed UWP apps as part of its advanced step
- **Temp File Cleanup**: After all debloat steps, Basilisk cleans up temporary files and system cache
- **Custom Raven scripts**: For Edge removal and Office Online cleanup

## 🛡️ Safety & Compatibility

### Safety Measures
- **Pre-installation Checks**: Validates system compatibility
- **Restore Point**: System restore point is created before any debloat steps
- **Error Handling**: Comprehensive error catching and user feedback
- **Logging**: Detailed logs for troubleshooting
- **Rollback Protection**: Safe registry modifications

### Compatibility
- **Windows 11 Home/Pro**: Primary target
- **Fresh Installations**: Recommended for best results
- **Administrator Rights**: Required for system modifications

## 📝 Logging

Basilisk provides comprehensive logging for troubleshooting:
- **File Location**: `%TEMP%\basilisk\` directory
- **Log Levels**: DEBUG, INFO, WARNING, ERROR
- **Content**: Step-by-step execution details and error information

## 🤝 Contributing

### Development Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Run in development mode: `python basilisk.py --developer-mode`

### Code Structure
- **Modular Design**: Each component is self-contained
- **Error Handling**: Comprehensive exception management
- **Type Hints**: Python type annotations for better code quality
- **Documentation**: Inline comments and docstrings

## 📄 License

This project is licensed under the BSD-3-Clause License. See the [license file](https://ravendevteam.org/files/BSD-3-Clause.txt) for details.

## 🙏 Acknowledgments

### Core Contributors
- [Raven Development Team](https://ravendevteam.org/)

### External Tools & Scripts
- [ChrisTitusTech](https://github.com/christitustech) - [CTT WinUtil](https://github.com/christitustech/winutil)
- [Raphire](https://github.com/Raphire) - [Win11Debloat](https://github.com/Raphire/Win11Debloat)

### Additional Contributors
- [mre31](https://github.com/mre31)
- [DTLegit](https://github.com/DTLegit)
- [zombiehunternr1](https://github.com/zombiehunternr1)
- [lilafian](https://github.com/lilafian)
- [winston113](https://github.com/winston113)
- [GabanKillasta](https://github.com/GabanKillasta)
- [urbanawakening](https://github.com/urbanawakening)
- [Mskitty301](https://github.com/Mskitty301)
- [SuperSonic3459](https://github.com/SuperSonic3459)
- [swordmasterliam](https://github.com/swordmasterliam)
- [Neoskimmer](https://github.com/Neoskimmer)
- [lukkaisito](https://github.com/lukkaisito)
- [alcainoism](https://github.com/alcainoism)
- [JanluOfficial](https://github.com/JanluOfficial)
- [Xirdrak](https://github.com/Xirdrak)
- [Alandlt15](https://github.com/Alandlt15)

### Assets
- [Icons by Icons8](https://icons8.com/)

## ⚠️ Disclaimer

This tool modifies system settings and registry values. While designed to be safe, it's recommended to:
- Use on fresh Windows 11 installations
- Basilisk automatically creates a system restore point before use
- Test in a virtual environment first
- Understand that some modifications may affect system functionality

The developers are not responsible for any data loss or system issues that may occur from using this tool.
