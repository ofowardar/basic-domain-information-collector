import subprocess
import sys
import os

def install_packages():
    try:
        # Install packages from requirements.txt
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("All packages installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while installing packages: {e}")

def check_root():
    if os.geteuid() != 0:
        print("This script requires root privileges. Please run as root or use sudo.")
        sys.exit(1)
        
if __name__ == "__main__":
    check_root()
    install_packages()
