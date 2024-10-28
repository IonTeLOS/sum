# SUM - Simple Update Manager

![SUM Icon](update_icon.png)

**SUM** is a lightweight, intuitive, and powerful update manager designed to handle seamless updates for your standalone applications, particularly those developed with [PySide6](https://pypi.org/project/PySide6/). SUM empowers your applications to autonomously manage their updates by automatically downloading, installing, and verifying updates without disrupting the user experience.

## 🎯 Key Features

- **Automatic Update Checks:** Connect to your designated update server to check for newer versions.
- **Interactive GUI Mode:** SUM provides an easy-to-follow interface, offering your users control over update timing.
- **Seamless Installation:** Handles download, backup, and replacement of executables safely.
- **Rollback Functionality:** If an update fails, SUM automatically restores the previous version, minimizing downtime.
- **Flexible Compatibility:** Although optimized for PySide6 apps, SUM can manage updates for other standalone applications that do not require complex packaging systems (e.g., Debian packages).
- **Checksum Verification:** Confirms the integrity of each downloaded update by verifying its checksum before installation.
- **Cross-Platform:** SUM works on Linux, Windows, and macOS.

## 💡 Getting Started

### 🛠 Installation and Setup

SUM is designed to be a standalone updater that any application can call to handle its own updates. To use SUM, follow these steps:

1. **Build SUM as a Standalone Executable:**

   Place the `sum.py` script alongside any necessary files (`dep.sh`, `update_icon.png`) and create a standalone executable using [PyInstaller](https://www.pyinstaller.org/):

   ```bash
   pyinstaller --onefile --add-data "dep.sh:." --add-data "update_icon.png:." sum.py
This command packages sum.py into a single executable while including the dep.sh script and the update icon.

Integrate SUM into Your Application:

From within your application, call the SUM executable whenever you need to check for updates. Here's an example of how to do this in Python:

python
Copy code
import subprocess
import sys
from pathlib import Path

def check_for_updates():
    current_version = "1.0.0"
    app_location = str(Path(__file__).resolve())
    update_url = "https://my-awesome-server.com/update"

    # Path to the SUM executable
    sum_executable = Path("/path/to/sum_executable")  # Update this path accordingly

    # Command to run SUM
    command = [
        str(sum_executable),
        "--current_version", current_version,
        "--current_location", app_location,
        "--url", update_url,
        "--interactive"  # Optional: Enable GUI interactive mode
    ]

    # Execute SUM
    subprocess.run(command)

if __name__ == "__main__":
    check_for_updates()
    # Continue with the rest of your application
Replace "/path/to/sum_executable" with the actual path to your SUM executable. This setup allows your application to delegate the update process to SUM seamlessly.

📜 Command-Line Arguments
SUM accepts several command-line arguments to customize the update process. Here's a breakdown of each argument:

-v, --current_version (required)
The current version of the application to be updated, used to compare against the latest version available online.

-f, --current_location (required)
The file path to the current executable of the app to be updated, allowing SUM to locate and replace it if an update is available.

-u, --url (required)
URL to check for the latest version and update files. Must be HTTPS unless it's a local network address.

-n, --app-name
Custom name for the application, which SUM will use in logs and notifications. If not provided, SUM uses the executable's basename.

-i, --interactive
Enables the interactive GUI mode, making the update process more user-friendly with progress bars and prompts.

-e, --extras
Additional script commands to execute prior to the update process, allowing for pre-installation checks or custom configurations.

Copy code
## 📄 Update JSON Format

For SUM to correctly identify and handle updates, the JSON data hosted at your update URL must adhere to the following structure:

### 🗂️ JSON Structure

```json
{
    "version": "1.0.1",
    "platforms": {
        "linux": {
            "download_url": "https://example.com/download/linux/app_v1.0.1",
            "checksum": "abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890"
        },
        "windows": {
            "download_url": "https://example.com/download/windows/app_v1.0.1.exe",
            "checksum": "123abc456def78901234567890abcdef1234567890abcdef1234567890abcdef"
        },
        "darwin": {
            "download_url": "https://example.com/download/macos/app_v1.0.1",
            "checksum": "789def012abc34567890abcdef1234567890abcdef1234567890abcdef123456"
        }
    }
}
```

📌 Field Descriptions
version (string, required):
The latest version of your application. This should follow semantic versioning (e.g., "1.0.1").

platforms (object, required):
An object containing platform-specific update information.

linux (object, required):
Information specific to Linux platforms.

download_url (string, required):
The direct URL to download the updated executable for Linux.

checksum (string, optional):
The SHA-256 checksum of the downloadable file to verify its integrity.

📝 Example Explanation
version: Indicates that the latest available version of the application is "1.0.1".

platforms: Contains update information tailored for each supported platform.

linux.download_url: Users on Linux will download the updated application from "https://my-awsome-server.com/download/linux/app_v1.0.1".

linux.checksum: The SHA-256 checksum "abc123def4567890abcdef1234567890abcdef1234567890abcdef1234567890" ensures the downloaded file hasn't been tampered with.

Similarly for Windows and Darwin.

🔒 Security Considerations
HTTPS URLs: Ensure all download_url links use HTTPS to maintain secure download channels.

Checksum Verification: It's highly recommended to provide the checksum field for each platform to allow SUM to verify the integrity of the downloaded files, preventing potential tampering or corruption.

✅ Validation
Before deploying your update JSON, validate its structure to ensure SUM can parse it correctly. You can use online JSON validators or tools like jq to check for syntax errors.

```bash
jq . update.json
## Replace update.json with your actual JSON file name
```

🌟 Additional Notes
Extensibility: You can add additional platforms if needed by following the same structure.

Optional Fields: While checksum is optional, providing it enhances security by ensuring file integrity.

Ensure that the JSON file is accessible via the specified --url when running SUM.

🚀 How to Use SUM
Once SUM is built and integrated into your application, you can invoke it as needed. Here's an example command to run SUM from your application:

bash
Copy code
./sum --current_version "1.0.0" --current_location "/path/to/app" --url "https://example.com/update" --interactive
In interactive mode, SUM will prompt the user with a graphical dialog, providing the option to proceed with updates or dismiss the notification. If an update is found, SUM downloads and installs it in the background. The app also maintains a backup of the current executable and can automatically restore it if an update fails.

Example: Calling SUM from a PySide6 Application
Here's a more concrete example of how a PySide6 application can call SUM to handle its updates:
```
python
import subprocess
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication, QPushButton

def check_for_updates():
    current_version = "1.0.0"
    app_location = str(Path(sys.argv[0]).resolve())
    update_url = "https://my-awesome-server.com/update"

    # Path to the SUM executable
    sum_executable = Path("/path/to/sum_executable")  # Update this path accordingly

    # Command to run SUM
    command = [
        str(sum_executable),
        "--current_version", current_version,
        "--current_location", app_location,
        "--url", update_url,
        "--interactive"  # Optional: Enable GUI interactive mode
    ]

    # Execute SUM
    subprocess.run(command)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = QPushButton("Check for Updates")
    window.clicked.connect(check_for_updates)
    window.show()
    sys.exit(app.exec())
```

In this example:

Button Trigger: A button labeled "Check for Updates" is created. When clicked, it triggers the check_for_updates function.
Running SUM: The check_for_updates function constructs the command to run SUM with the necessary arguments and executes it using subprocess.run.
Seamless Integration: This allows your PySide6 application to delegate the update process to SUM without disrupting the main application flow.
⚠️ Compatibility Notes
SUM is optimized for PySide6 applications, but it can work with other single-file executables as well. However, it is not compatible with applications that use system package managers, like Debian’s .deb packages. SUM is best suited for independent executables that are not managed by system-level packaging tools.

Supported Platforms
Linux (Debian 11+)
Windows
macOS

🛡 Security Considerations
HTTPS Enforcement: SUM ensures that update URLs use HTTPS to maintain secure communication, except for local network addresses.
Checksum Verification: Each downloaded update is verified using SHA-256 checksums to ensure file integrity and prevent tampering.
🗂 Additional Dependencies
To ensure SUM’s functionality on various Linux distributions, it includes a dependency check script (dep.sh) that automatically installs required packages if missing. This script uses pkexec for privilege escalation if available; otherwise, it attempts to open x-terminal-emulator for password prompts.

dep.sh Overview
Checks for Required Libraries: Ensures that all necessary system libraries for running PySide6 applications are installed.
Automatic Installation: Installs missing dependencies using apt with elevated permissions.
Graceful Handling: Continues to run the application even if some dependencies fail to install, logging warnings accordingly.

📈 Logging and Monitoring
SUM maintains a rotating log file (software_updates.log) located in the same directory as the executable. This log records all update events, including successes, failures, and any rollback actions taken.

🌐 Project Links and Documentation
For more information, detailed documentation, and code examples, please visit our GitHub repository.

🤝 Contributing
Contributions are welcome! If you encounter issues or have suggestions for improvements, feel free to open an issue or submit a pull request on GitHub.

📜 License
SUM is released under the MIT License.

Thank you for using SUM! We’re excited to help you keep your applications up-to-date with ease and reliability.
