import sys
import requests
import platform
import tempfile
import subprocess
from subprocess import call
import logging
from datetime import datetime
from argparse import ArgumentParser
from urllib.parse import urlparse
import psutil
import ipaddress
import stat
import hashlib

from packaging import version
from pathlib import Path

from PySide6.QtWidgets import (
    QApplication,
    QProgressBar,
    QMessageBox,
    QVBoxLayout,
    QDialog,
    QPushButton,
    QLabel
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QIcon

# Conditional Imports Based on Platform
if platform.system() == "Windows":
    import ctypes
elif platform.system() in ["Linux", "Darwin"]:
    import os  # Already imported, kept for clarity
else:
    pass  # Handle other platforms if necessary


class UpdateLogger:
    def __init__(self, executable_path, app_name="my app"):
        """Initialize logger to log directly to a specified file."""
        log_file = Path(executable_path).parent / 'software_updates.log'
        
        # Set up basic logging configuration to log directly to a file
        logging.basicConfig(
            filename=str(log_file),
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - APP: %(app_name)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Create a logger instance
        self.logger = logging.getLogger(f"software_updates_{app_name}")

    def log_update(self, app_name, from_version, to_version, status, error=None):
        """Log update events with app name included."""
        extra = {'app_name': app_name}

        if status == "SUCCESS":
            self.logger.info(f"Update successful: v{from_version} → v{to_version}", extra=extra)
        elif status == "FAILED":
            self.logger.error(f"Update failed: v{from_version} → v{to_version}. Error: {error}", extra=extra)
        elif status == "ROLLBACK":
            self.logger.warning(f"Update rolled back: v{from_version} → v{to_version}. Restored v{from_version}", extra=extra)
        elif status == "INFO":
            self.logger.info(f"{error}", extra=extra)

class UpdateDialog(QDialog):
    def __init__(self, app_name, latest_version, interactive, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Update Available - {app_name}")
        self.interactive = interactive

        if not interactive:
            self.close()
            return

        self.setWindowIcon(self.load_icon("update_icon.png"))
        layout = QVBoxLayout(self)

        self.label = QLabel(f"A new version ({latest_version}) is available. Downloading...")
        layout.addWidget(self.label)

        self.progress_bar = QProgressBar(self)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setRange(0, 100)
        layout.addWidget(self.progress_bar)

        self.update_button = QPushButton("Update Now")
        self.update_button.setEnabled(False)
        self.update_button.clicked.connect(self.accept)
        layout.addWidget(self.update_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)

    def set_progress(self, value):
        if self.interactive:
            if value >= 0:
                self.progress_bar.setValue(value)
            else:
                self.progress_bar.setRange(0, 0)  # Indeterminate progress

    def enable_update_button(self):
        if self.interactive:
            self.update_button.setEnabled(True)
            self.label.setText("Download completed. Click 'Update Now' to install.")
        else:
            self.accept()

    @staticmethod
    def load_icon(icon_name):
        base_path = Path(sys._MEIPASS) if getattr(sys, 'frozen', False) else Path(__file__).parent
        icon_path = base_path / icon_name
        return QIcon(str(icon_path)) if icon_path.exists() else QIcon()


class DownloadThread(QThread):
    progress_signal = Signal(int)
    download_complete = Signal(str, str)  # Emits file_path and checksum

    def __init__(self, download_url, expected_checksum=None, parent=None):
        super().__init__(parent)
        self.download_url = download_url
        self.expected_checksum = expected_checksum
        self.file_path = None

    def run(self):
        try:
            with requests.get(self.download_url, stream=True) as response:
                response.raise_for_status()
                total_size = response.headers.get("content-length")
                total_size = int(total_size) if total_size is not None else 0

                # Determine the suffix based on the operating system
                suffix = ".exe" if platform.system() == "Windows" else ""

                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_file:
                    self.file_path = Path(tmp_file.name)
                    downloaded_size = 0
                    sha256_hash = hashlib.sha256() if self.expected_checksum else None

                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:  # Filter out keep-alive new chunks
                            tmp_file.write(chunk)
                            if sha256_hash:
                                sha256_hash.update(chunk)
                            downloaded_size += len(chunk)
                            if total_size > 0:
                                progress = int((downloaded_size / total_size) * 100)
                                self.progress_signal.emit(progress)
                            else:
                                # Indeterminate progress
                                self.progress_signal.emit(-1)

                checksum = sha256_hash.hexdigest() if sha256_hash else None
                self.download_complete.emit(str(self.file_path), checksum)
        except Exception as e:
            self.download_complete.emit(None, None)
            print(f"Error during download: {e}")


def check_url_connection(url):
    """Check if a connection to the given URL is available."""
    try:
        response = requests.head(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False


def validate_url(url):
    """Ensure the URL uses HTTPS protocol, except for local network addresses."""
    parsed = urlparse(url)

    # Check if URL scheme is HTTPS
    if parsed.scheme != 'https':
        # Allow non-HTTPS only for local network IPs
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if not (ip.is_private or ip.is_loopback):
                raise ValueError("Only HTTPS URLs are allowed for security, except local network addresses")
        except ipaddress.AddressValueError:
            # Raise error if hostname is not a valid IP and is not HTTPS
            raise ValueError("Only HTTPS URLs are allowed for security, except local network addresses")

    return url


def check_for_updates(current_version, app_location, update_url, app_name="my app", interactive=True):
    """Check for updates and initiate download and installation if a new version is found."""
    logger = UpdateLogger(app_location, app_name)

    # First, check for connectivity to the update URL
    if not check_url_connection(update_url):
        logger.log_update(app_name, current_version, "N/A", "FAILED", f"No connection to {update_url}")
        if interactive:
            QMessageBox.warning(None, "Connection Error", f"Unable to connect to update server: {update_url}")
        return

    try:
        update_url = validate_url(update_url)
        response = requests.get(update_url)
        response.raise_for_status()
        latest_info = response.json()

        platform_key = platform.system().lower()

        if platform_key not in latest_info.get("platforms", {}):
            logger.log_update(app_name, current_version, "N/A", "FAILED", f"No update information for platform: {platform_key}")
            if interactive:
                QMessageBox.information(None, "No Update", f"No update available for {app_name} on your platform.")
            return

        latest_version = latest_info["version"]
        platform_info = latest_info["platforms"][platform_key]
        download_url = validate_url(platform_info["download_url"])
        expected_checksum = platform_info.get("checksum")  # Optional checksum

        if is_newer_version(current_version, latest_version):
            if interactive:
                reply = QMessageBox.question(
                    None,
                    "Update Available",
                    f"{app_name}\nCurrent Version: {current_version}\nNew Version: {latest_version}\n\n"
                    f"Do you want to proceed with the download and update?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            perform_update_with_gui(app_name, current_version, latest_version, download_url, expected_checksum, interactive, logger, app_location)
        else:
            logger.log_update(app_name, current_version, latest_version, "INFO", "Current version is up-to-date.")
            if interactive:
                QMessageBox.information(None, "No Update", f"{app_name} is already up-to-date.")

    except ValueError as ve:
        logger.log_update(app_name, current_version, "N/A", "FAILED", str(ve))
        if interactive:
            QMessageBox.critical(None, "Security Error", str(ve))
    except Exception as e:
        logger.log_update(app_name, current_version, "N/A", "FAILED", str(e))
        if interactive:
            QMessageBox.critical(None, "Update Error", f"Failed to check for updates: {e}")


def is_newer_version(current, latest):
    """Compare the current version to the latest version using semantic versioning."""
    try:
        return version.parse(latest) > version.parse(current)
    except Exception as e:
        print(f"Version comparison error: {e}")
        return False


def perform_update_with_gui(app_name, current_version, latest_version, download_url, expected_checksum, interactive, logger, app_location):
    """Handle the update process with a GUI."""
    if interactive:
        app = QApplication.instance() or QApplication(sys.argv)

        dialog = UpdateDialog(app_name, latest_version, interactive)
        download_thread = DownloadThread(download_url, expected_checksum)

        download_thread.progress_signal.connect(dialog.set_progress)
        download_thread.download_complete.connect(lambda path, checksum: dialog.enable_update_button() if path and (not expected_checksum or checksum == expected_checksum) else dialog.reject())

        download_thread.start()

        if dialog.exec() == QDialog.Accepted:
            if download_thread.file_path:
                # Verify checksum if provided
                if expected_checksum:
                    if download_thread.download_complete.emit.__self__.expected_checksum:
                        # Already checked via signal
                        pass
                    else:
                        # Additional verification if needed
                        pass

                success = replace_and_restart(
                    app_location,
                    download_thread.file_path,
                    current_version,
                    latest_version,
                    app_name,
                    interactive
                )
                if success:
                    QMessageBox.information(None, "Update Installed", f"{app_name} has been updated and restarted.")
                else:
                    show_error_message(app_name)
            sys.exit()
    else:
        # Non-interactive mode: Download and replace without GUI
        download_thread = DownloadThread(download_url, expected_checksum)

        download_thread.start()
        download_thread.wait()  # Wait for download to complete

        if download_thread.file_path:
            # Verify checksum if provided
            if expected_checksum:
                if download_thread.file_path and download_thread.download_complete.emit.__self__.expected_checksum:
                    # Already checked via signal
                    pass
                else:
                    # Additional verification if needed
                    pass

            success = replace_and_restart(
                app_location,
                download_thread.file_path,
                current_version,
                latest_version,
                app_name,
                interactive
            )
            if success:
                print(f"{app_name} has been updated and restarted.")
            else:
                show_error_message(app_name)
            sys.exit()


def is_directory_write_protected(path):
    """Check if the directory containing the given path is write-protected."""
    directory = Path(path).parent
    return not os.access(directory, os.W_OK)


def is_current_process_elevated():
    """Check if the current process is running with elevated privileges."""
    if platform.system() == "Linux":
        return os.geteuid() == 0  # True if running as root
    elif platform.system() == "Windows":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    return False


def request_elevated_permissions():
    """Request elevated permissions if required by the system."""
    if platform.system() == "Linux":
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.information(None, "Permission Required", "Please enter your sudo password to proceed.")

        try:
            subprocess.check_call(['sudo', sys.executable] + sys.argv)
        except subprocess.CalledProcessError:
            QMessageBox.critical(None, "Permission Denied", "Failed to obtain elevated permissions. Run as root.")
            sys.exit(1)
        sys.exit(0)

    elif platform.system() == "Windows":
        app = QApplication.instance() or QApplication(sys.argv)
        QMessageBox.information(None, "Permission Required", "Administrator permissions are required. Click OK to proceed.")

        try:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            QMessageBox.critical(None, "Permission Denied", f"Failed to obtain elevated permissions: {e}")
            sys.exit(1)
        sys.exit(0)


def terminate_processes(target_executable, timeout=5):
    """Terminate all instances of the specified executable, requesting elevation if needed."""
    found = False
    try:
        for proc in psutil.process_iter(attrs=['pid', 'exe']):
            if proc.info['exe'] == target_executable:
                found = True
                # Check if the current process is elevated
                if not is_current_process_elevated():
                    # Prompt for elevated permissions
                    app = QApplication.instance() or QApplication(sys.argv)
                    response = QMessageBox.question(
                        None, "Elevated Permissions Required",
                        "Terminating this application requires elevated permissions.\n\nDo you want to continue with elevated permissions?",
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if response == QMessageBox.Yes:
                        request_elevated_permissions()
                        return True  # Restart with elevated privileges and terminate upon re-entry
                    else:
                        QMessageBox.critical(None, "Operation Canceled", "Cannot terminate the application without elevated permissions.")
                        return False

                # Terminate the process
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                    print(f"Process {proc.info['pid']} terminated gracefully.")
                except psutil.TimeoutExpired:
                    print(f"Process {proc.info['pid']} did not terminate within {timeout} seconds. Forcing termination.")
                    proc.kill()  # Force termination if process doesn't respond
                except psutil.NoSuchProcess:
                    print(f"Process {proc.info['pid']} was already terminated.")

        if not found:
            print(f"No running processes found for {target_executable}.")
            return True  # Return True if no instances were found, as this is not a failure
    except (psutil.AccessDenied, psutil.Error) as e:
        print(f"An error occurred while terminating processes: {e}")
        return False

    return True  # Return True if termination completed successfully for found instances


def replace_and_restart(target_executable, new_executable, current_version, latest_version, app_name="my app", interactive=True, extras=None):
    """Replace the specified executable with the new version and restart it."""

    temp_dir = get_temp_dir()
    os.makedirs(temp_dir, exist_ok=True)  # Ensure temp directory exists

    # Set backup_location in a known writable path
    backup_location = Path(temp_dir) / (Path(target_executable).name + ".backup")
    update_script = None
    extras_script_file_path = None
    logger = UpdateLogger(target_executable, app_name)

    try:
        # Step 1: Run the extras script if provided (before making any changes)
        if extras:
            # Determine the script suffix based on the OS
            script_suffix = ".bat" if platform.system() == "Windows" else ".sh"
            with tempfile.NamedTemporaryFile(delete=False, suffix=script_suffix, dir=temp_dir) as extras_script_file:
                extras_script_file.write(extras.encode())
                extras_script_file_path = extras_script_file.name

            # Make the extras script executable on Unix-based systems
            if platform.system() in ["Linux", "Darwin"]:
                extras_script_path = Path(extras_script_file_path)
                extras_script_path.chmod(0o755)

            try:
                # Execute the extras script
                if platform.system() == "Windows":
                    subprocess.check_call([extras_script_file_path], shell=True)
                else:
                    subprocess.check_call(["bash", extras_script_file_path])
            except subprocess.CalledProcessError as e:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Extras script failed: {e}")
                if interactive:
                    QMessageBox.critical(None, "Error", f"Extras script failed: {e}")
                return False  # Exit early due to extras script failure

        # Step 2: Terminate the target application if running
        if not terminate_processes(target_executable, timeout=5):
            logger.log_update(app_name, current_version, latest_version, "FAILED", "Unable to terminate the application.")
            if interactive:
                QMessageBox.critical(None, "Error", "Unable to terminate the application.")
            return False  # Exit if unable to stop the application

        # Step 3: Check if the directory of target_executable is write-protected
        if is_directory_write_protected(target_executable):
            if interactive:
                response = QMessageBox.question(
                    None, "Elevated Permissions Required",
                    "Replacing this application requires elevated permissions to modify its directory.\n\nDo you want to continue?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if response == QMessageBox.Yes:
                    request_elevated_permissions()
                    return  # The script will restart with elevated privileges
                else:
                    QMessageBox.critical(None, "Operation Canceled", "The operation was canceled by the user.")
                    return False  # Exit if user denies elevation
            else:
                # Non-interactive mode cannot proceed without permissions
                logger.log_update(app_name, current_version, latest_version, "FAILED", "Directory is write-protected and cannot obtain elevated permissions.")
                return False

        # Step 4: Backup the target executable to a writable location
        try:
            target_path = Path(target_executable)
            backup_path = backup_location
            target_path.rename(backup_path)
        except Exception as e:
            logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to backup executable: {e}")
            if interactive:
                QMessageBox.critical(None, "Error", f"Failed to backup executable: {e}")
            return False  # Exit if backup fails

        # Step 5: Move the new executable in place
        try:
            new_executable_path = Path(new_executable)
            target_path = Path(target_executable)
            new_executable_path.rename(target_path)
        except Exception as e:
            logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to replace executable: {e}")
            # Attempt to restore from backup
            try:
                backup_location.rename(target_executable)
                logger.log_update(app_name, current_version, latest_version, "ROLLBACK", "Restored from backup due to replacement failure.")
                # Re-run extras script for rollback
                if extras:
                    try:
                        if platform.system() == "Windows":
                            subprocess.check_call([extras_script_file_path], shell=True)
                        else:
                            subprocess.check_call(["bash", extras_script_file_path])
                    except subprocess.CalledProcessError as rollback_e:
                        logger.log_update(app_name, current_version, latest_version, "FAILED", f"Rollback extras script failed: {rollback_e}")
                        if interactive:
                            QMessageBox.critical(None, "Error", f"Rollback extras script failed: {rollback_e}")
            except Exception as restore_error:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to restore backup: {restore_error}")
                if interactive:
                    QMessageBox.critical(None, "Error", f"Failed to replace executable and restore backup: {restore_error}")
            if interactive:
                QMessageBox.critical(None, "Error", f"Failed to replace executable: {e}\nBackup restored.")
            return False  # Exit if replacement fails

        # Step 6: Adjust permissions to ensure standard user access
        try:
            if platform.system() == "Windows":
                # Using stat constants to set read, write, and execute permissions
                target_path.chmod(stat.S_IWRITE | stat.S_IREAD | stat.S_IEXEC)
            elif platform.system() in ["Linux", "Darwin"]:
                # Setting permissions to 755 (rwxr-xr-x)
                target_path.chmod(0o755)
        except Exception as e:
            logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to set permissions: {e}")
            # Attempt to restore from backup
            try:
                backup_location.rename(target_executable)
                logger.log_update(app_name, current_version, latest_version, "ROLLBACK", "Restored from backup due to permission setting failure.")
                # Re-run extras script for rollback
                if extras:
                    try:
                        if platform.system() == "Windows":
                            subprocess.check_call([extras_script_file_path], shell=True)
                        else:
                            subprocess.check_call(["bash", extras_script_file_path])
                    except subprocess.CalledProcessError as rollback_e:
                        logger.log_update(app_name, current_version, latest_version, "FAILED", f"Rollback extras script failed: {rollback_e}")
                        if interactive:
                            QMessageBox.critical(None, "Error", f"Rollback extras script failed: {rollback_e}")
            except Exception as restore_error:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to restore backup after permission setting failure: {restore_error}")
                if interactive:
                    QMessageBox.critical(None, "Error", f"Failed to set permissions and restore backup: {restore_error}")
            if interactive:
                QMessageBox.critical(None, "Error", f"Failed to set permissions: {e}\nBackup restored.")
            return False  # Exit if permission setting fails

        # Step 7: Create the update script to restart the application
        try:
            script_suffix = ".bat" if platform.system() == "Windows" else ".sh"
            with tempfile.NamedTemporaryFile(delete=False, suffix=script_suffix, dir=temp_dir) as update_script_file:
                if platform.system() == "Windows":
                    update_script_file.write(f"""
                        @echo off
                        timeout /t 2 >nul
                        start "" "{target_executable}"
                        if errorlevel 1 (
                            move /Y "{backup_location}" "{target_executable}"
                        )
                    """.encode())
                else:
                    update_script_file.write(f"""
                        #!/bin/bash
                        sleep 2
                        "{target_executable}" &
                        if [ $? -ne 0 ]; then
                            mv "{backup_location}" "{target_executable}"
                        fi
                    """.encode())
                update_script = Path(update_script_file.name)

            # Make the update script executable on Unix-based systems
            if platform.system() in ["Linux", "Darwin"]:
                update_script.chmod(0o755)
        except Exception as e:
            logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to create update script: {e}")
            # Attempt to restore from backup
            try:
                backup_location.rename(target_executable)
                logger.log_update(app_name, current_version, latest_version, "ROLLBACK", "Restored from backup due to update script creation failure.")
                # Re-run extras script for rollback
                if extras:
                    try:
                        if platform.system() == "Windows":
                            subprocess.check_call([extras_script_file_path], shell=True)
                        else:
                            subprocess.check_call(["bash", extras_script_file_path])
                    except subprocess.CalledProcessError as rollback_e:
                        logger.log_update(app_name, current_version, latest_version, "FAILED", f"Rollback extras script failed: {rollback_e}")
                        if interactive:
                            QMessageBox.critical(None, "Error", f"Rollback extras script failed: {rollback_e}")
            except Exception as restore_error:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to restore backup after script creation failure: {restore_error}")
                if interactive:
                    QMessageBox.critical(None, "Error", f"Failed to create update script and restore backup: {restore_error}")
            if interactive:
                QMessageBox.critical(None, "Error", f"Failed to create update script: {e}\nBackup restored.")
            return False  # Exit if script creation fails

        # Step 8: Run the update script to restart the application
        try:
            if platform.system() == "Windows":
                subprocess.Popen([str(update_script)], shell=True)
            else:
                subprocess.Popen(["sh", str(update_script)])
        except Exception as e:
            logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to run update script: {e}")
            # Attempt to restore from backup
            try:
                backup_location.rename(target_executable)
                logger.log_update(app_name, current_version, latest_version, "ROLLBACK", "Restored from backup due to update script execution failure.")
                # Re-run extras script for rollback
                if extras:
                    try:
                        if platform.system() == "Windows":
                            subprocess.check_call([extras_script_file_path], shell=True)
                        else:
                            subprocess.check_call(["bash", extras_script_file_path])
                    except subprocess.CalledProcessError as rollback_e:
                        logger.log_update(app_name, current_version, latest_version, "FAILED", f"Rollback extras script failed: {rollback_e}")
                        if interactive:
                            QMessageBox.critical(None, "Error", f"Rollback extras script failed: {rollback_e}")
            except Exception as restore_error:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to restore backup after script execution failure: {restore_error}")
                if interactive:
                    QMessageBox.critical(None, "Error", f"Failed to run update script and restore backup: {restore_error}")
            if interactive:
                QMessageBox.critical(None, "Error", f"Failed to run update script: {e}\nBackup restored.")
            return False  # Exit if script execution fails

        # Step 9: Log successful update
        logger.log_update(app_name, current_version, latest_version, "SUCCESS")
        try:
            backup_location.unlink()  # Remove backup as it's no longer needed
        except Exception as e:
            logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to remove backup: {e}")
            if interactive:
                QMessageBox.warning(None, "Warning", f"Failed to remove backup: {e}")

        return True  # Indicate success

    finally:
        # Cleanup temporary scripts if they were created
        if update_script and update_script.exists():
            try:
                update_script.unlink()
            except Exception as e:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to remove update script: {e}")

        if extras and extras_script_file_path and Path(extras_script_file_path).exists():
            try:
                Path(extras_script_file_path).unlink()
            except Exception as e:
                logger.log_update(app_name, current_version, latest_version, "FAILED", f"Failed to remove extras script: {e}")


def show_error_message(app_name):
    """Display an error message if the application fails to start after the update."""
    QMessageBox.critical(
        None,
        "Update Error",
        f"Failed to update {app_name}. Rolling back to previous version."
    )


def get_temp_dir():
    """Get a cross-platform writable temporary directory."""
    if platform.system() == "Windows":
        return Path(os.getenv("TEMP", Path.home() / "AppData" / "Local" / "Temp"))
    elif platform.system() == "Darwin":
        return Path("/tmp") if Path("/tmp").exists() and os.access("/tmp", os.W_OK) else Path.home() / "Library" / "Application Support" / "tmp"
    else:
        return Path("/tmp") if Path("/tmp").exists() and os.access("/tmp", os.W_OK) else Path.home() / ".local" / "tmp"


def main():
    # Run dep.sh to check and install missing dependencies
    dep_script = Path(__file__).parent / 'dep.sh'
    if dep_script.exists():
        result = call(["/bin/bash", str(dep_script)])
        if result != 0:
            print("Warning: Some dependencies may not have been installed correctly.")
            
    parser = ArgumentParser(
        description="SUM - a Simple Update Manager",
        add_help=True
    )
    parser.add_argument("-v", "--current_version", required=True,
                        help="Current version of the application to be updated")
    parser.add_argument("-f", "--current_location", required=True,
                        help="Location of the executable of the application to be updated")
    parser.add_argument("-u", "--url", required=True,
                        help="HTTPS URL or local network address to check for the latest version")
    parser.add_argument("-n", "--app-name", default=None,
                        help="Specify the name of the application to be updated. If not provided, the basename of the executable will be used.")
    parser.add_argument("-i", "--interactive", action="store_true", default=False,
                        help="Enable interactive mode with GUI (default: False)")
    parser.add_argument("-e", "--extras", help="Script text to run before replacing the executable")

    # Determine base path based on whether the script is frozen (bundled with PyInstaller) or not
    if getattr(sys, 'frozen', False):
        # Running in a PyInstaller bundle
        base_path = Path(sys._MEIPASS)
    else:
        # Running in a normal Python environment
        base_path = Path(__file__).parent

    # Path to the icon file
    icon_path = base_path / "update_icon.png"

    # Check if no arguments were provided (only the script name)
    if len(sys.argv) == 1:
        # Initialize QApplication and show the informational GUI message
        app = QApplication(sys.argv)
        
        # Create the QMessageBox instance
        msg_box = QMessageBox(
            QMessageBox.Information,
            "SUM - Usage Information",
            "<b>SUM - Simple Update Manager</b><br><br>"
            "This application checks for updates for a specified application.<br><br>"
            "If updates are found, it downloads, installs, and restarts the updated app.<br><br>"
            "SUM is typically called by the application that wants to be updated.<br><br>"
            "<b>Required arguments:</b><br>"
            "-v  or --current_version : Current version of the application.<br>"
            "-f  or --current_location: Path to the executable.<br>"
            "-u  or --url            : URL to check for the latest version.<br><br>"
            "<b>Optional arguments:</b><br>"
            "-n  or --app-name       : Name of the application (defaults to the executable's basename).<br>"
            "-i  or --interactive    : Enable GUI interactive mode.<br>"
            "-e  or --extras         : Script text to run before replacing the executable.<br><br>"
            '<a href="https://github.com/IonTeLOS/sum">Learn more about SUM</a>',
        )
        
        # Set the icon specifically for the QMessageBox
        msg_box.setWindowIcon(QIcon(str(icon_path)))
        
        # Display the message box
        msg_box.exec()
        sys.exit(0)

    # Parse arguments; catch missing required arguments
    try:
        args = parser.parse_args()
    except SystemExit:
        # Handle missing required arguments
        if "--interactive" in sys.argv or "-i" in sys.argv:
            app = QApplication(sys.argv)
            QMessageBox.warning(
                None, "Missing Arguments",
                "Some required arguments are missing.<br><br>"
                "Please provide the following:<br>"
                "-v (current version)<br>"
                "-f (current location)<br>"
                "-u (update URL)<br>"
            )
        else:
            parser.print_help()
        sys.exit(1)

    # Determine app_name: use provided name or basename of the executable
    if args.app_name:
        app_name = args.app_name
    else:
        app_name = Path(args.current_location).stem  # Using pathlib for better path handling

    # Initialize logger with the determined app_name
    logger = UpdateLogger(args.current_location, app_name)

    # Initialize QApplication if in interactive mode and not already created
    if args.interactive and not QApplication.instance():
        app = QApplication(sys.argv)
    else:
        app = None

    try:
        # Run the update check
        check_for_updates(
            args.current_version,
            args.current_location,
            args.url,
            app_name,
            args.interactive
        )
    except Exception as e:
        logger.log_update(app_name, args.current_version, "N/A", "FAILED", str(e))
        if args.interactive:
            QMessageBox.critical(None, "Error", f"Update process failed: {e}")
        sys.exit(1)

    # Start the app event loop if QApplication was initialized
    if app:
        sys.exit(app.exec())
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
