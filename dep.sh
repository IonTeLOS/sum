#!/bin/bash

# Define log file in a user-writable location
log_file="$HOME/sum_dep_install.log"

# Redirect all output to the log file and to the console
exec > >(tee -a "$log_file") 2>&1

echo "===== Dependency Installation Started at $(date) ====="

# List of required packages
required_packages=(
    "libxcb1"
    "libxcb-cursor0"
    "libxcb-render0"
    "libxcb-shm0"
    "libxcb-xfixes0"
    "libxcb-icccm4"
    "libxcb-image0"
    "libxcb-keysyms1"
    "libxcb-randr0"
    "libxcb-render-util0"
    "libxcb-shape0"
    "libxcb-sync1"
    "libxcb-xinerama0"
    "libxcb-util1"
    "libxcb-xkb1"
    "libxkbcommon-x11-0"
    "libfontconfig1"
    "libfreetype6"
    "libglib2.0-0"
    "libpng16-16"
    "libharfbuzz0b"
    "libdbus-1-3"
    "libx11-xcb1"
    "libqt5gui5"
    "libva2"  # Added VAAPI library
)

# Function to check if a package is installed
is_installed() {
    dpkg -s "$1" &>/dev/null
}

# Arrays to track missing and failed packages
missing_packages=()
failed_packages=()

# Check each required package
echo "Checking for missing packages..."
for pkg in "${required_packages[@]}"; do
    if ! is_installed "$pkg"; then
        missing_packages+=("$pkg")
        echo " - $pkg: MISSING"
    else
        echo " - $pkg: Installed"
    fi
done

# Proceed only if there are missing packages
if [ ${#missing_packages[@]} -gt 0 ]; then
    echo ""
    echo "The following packages are missing and will be installed if available:"
    for pkg in "${missing_packages[@]}"; do
        echo "  * $pkg"
    done
    echo ""

    # Function to install a single package
    install_package() {
        local package="$1"
        echo "Attempting to install $package..."
        
        # Attempt installation with pkexec
        if command -v pkexec &>/dev/null; then
            pkexec apt-get install -y "$package"
        # Fallback to x-terminal-emulator with sudo if pkexec is unavailable
        elif command -v x-terminal-emulator &>/dev/null; then
            x-terminal-emulator -e bash -c "sudo apt-get install -y '$package'"
        else
            echo "Error: Neither pkexec nor x-terminal-emulator is available."
            echo "Please install $package manually using:"
            echo "  sudo apt-get install -y $package"
            failed_packages+=("$package")
            return
        fi

        # Check if installation was successful
        if is_installed "$package"; then
            echo "Successfully installed $package."
        else
            echo "Warning: Failed to install $package."
            failed_packages+=("$package")
        fi
    }

    # Install each missing package one by one
    for pkg in "${missing_packages[@]}"; do
        install_package "$pkg"
        echo ""  # Add a blank line for readability
    done

    # Summary of installation results
    echo "===== Dependency Installation Summary ====="
    if [ ${#failed_packages[@]} -gt 0 ]; then
        echo "Some packages failed to install:"
        for pkg in "${failed_packages[@]}"; do
            echo "  - $pkg"
        done
        echo "Please check the log at $log_file for more details."
    else
        echo "All missing packages were installed successfully."
    fi
    echo "==========================================="
else
    echo "All required packages are already installed."
    echo "==========================================="
fi

echo ""
echo "===== Dependency Installation Completed at $(date) ====="

echo "Starting the application..."
