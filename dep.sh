#!/bin/bash

# Function to check if a package is installed
is_installed() {
    dpkg -s "$1" &>/dev/null
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    # Check if pkexec is available, otherwise use x-terminal-emulator
    if command -v pkexec &>/dev/null; then
        pkexec bash "$0"
        exit $?
    elif command -v x-terminal-emulator &>/dev/null; then
        x-terminal-emulator -e "sudo bash '$0'"
        exit $?
    else
        echo "Neither pkexec nor x-terminal-emulator is available. Please run this script with sudo."
        exit 1
    fi
fi

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
)

# Track if any packages are missing
missing_packages=()

# Check for each required package
for pkg in "${required_packages[@]}"; do
    if ! is_installed "$pkg"; then
        missing_packages+=("$pkg")
    fi
done

# If there are missing packages, attempt installation
if [ ${#missing_packages[@]} -gt 0 ]; then
    echo "The following packages are missing and will be installed if available:"
    echo "${missing_packages[@]}"
    apt update
    for pkg in "${missing_packages[@]}"; do
        if ! apt install -y "$pkg"; then
            echo "Warning: Package '$pkg' could not be installed. It may not be available in the repository."
        fi
    done
fi

# Run the application
echo "Starting the application..."
