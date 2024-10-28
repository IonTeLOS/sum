#!/bin/bash

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

# Function to check if a package is installed
is_installed() {
    dpkg -s "$1" &>/dev/null
}

# Track missing packages without requiring sudo initially
missing_packages=()

# Check each required package
for pkg in "${required_packages[@]}"; do
    if ! is_installed "$pkg"; then
        missing_packages+=("$pkg")
    fi
done

# Only request sudo if there are missing packages
if [ ${#missing_packages[@]} -gt 0 ]; then
    echo "The following packages are missing and will be installed if available:"
    echo "${missing_packages[@]}"

    # Check if pkexec is available for GUI prompt, fallback to terminal-based sudo
    if command -v pkexec &>/dev/null; then
        for pkg in "${missing_packages[@]}"; do
            pkexec bash -c "apt update && apt install -y $pkg" || echo "Warning: Failed to install $pkg"
        done
    elif command -v x-terminal-emulator &>/dev/null; then
        for pkg in "${missing_packages[@]}"; do
            x-terminal-emulator -e "sudo bash -c 'apt update && apt install -y $pkg'" || echo "Warning: Failed to install $pkg"
        done
    else
        echo "Neither pkexec nor x-terminal-emulator is available. Please install missing packages manually."
        exit 1
    fi
else
    echo "All required packages are already installed."
fi

# Run the application
echo "Starting the application..."
