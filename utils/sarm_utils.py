import wmi
import random
import ctypes
import sys
import os
import shutil

# Function to get all volumes (mounted and unmounted)
def get_all_volumes_wmi():
    c = wmi.WMI()

    volumes = []

    # Get mounted volumes using Win32_LogicalDisk
    for logical_disk in c.Win32_LogicalDisk():
        volumes.append({
            'name': logical_disk.Caption,  # Drive letter (C:, D:, etc.)
            'mountpoint': logical_disk.Caption,  # Same as name in this case
            'fstype': logical_disk.FileSystem,  # File system type (NTFS, FAT32, etc.)
            'label': logical_disk.VolumeName if logical_disk.VolumeName else 'Unknown',  # Volume label
            'status': 'mounted'
        })

    # Get all volumes (including unmounted ones) using Win32_Volume
    for volume in c.Win32_Volume():
        if not volume.DriveLetter and volume.Label and volume.Label != 'Unknown':
            volumes.append({
                'name': volume.DeviceID,  # Volume path
                'mountpoint': 'Not Assigned',
                'fstype': volume.FileSystem if volume.FileSystem else 'Unknown',  # File system type
                'label': volume.Label if volume.Label else 'Unknown',  # Volume label
                'status': 'unmounted'
            })

    return volumes

# Function to check if the script is running as Administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Function to assign a random drive letter to a volume
def assign_drive_letter(volume_label):
    if not is_admin():
        print("Script requires administrator privileges. Elevating...")
        # Re-run the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    c = wmi.WMI()

    # Collect all currently assigned drive letters
    assigned_letters = {logical_disk.Caption for logical_disk in c.Win32_LogicalDisk()}
    
    # Generate a list of available drive letters from A to Z, excluding those already assigned
    available_letters = [chr(letter) + ':' for letter in range(65, 91) if chr(letter) + ':' not in assigned_letters]

    # If no letters are available, return with a message
    if not available_letters:
        print("No available drive letters to assign.")
        return

    # Get the unmounted volume by label
    for volume in c.Win32_Volume():
        if volume.Label == volume_label and not volume.DriveLetter:
            # Choose a random available drive letter
            random_letter = random.choice(available_letters)
            try:
                # Assign the chosen drive letter
                volume.DriveLetter = random_letter
                volume.Put_()
                print(f"Assigned drive letter {random_letter} to volume: {volume.Label}")
                return random_letter
            except Exception as e:
                print(f"Failed to assign drive letter: {e}")
                return
    print(f"Volume with label {volume_label} not found or already has a drive letter.")

# Function to unassign (remove) a drive letter from a volume
def unassign_drive_letter(volume_label):
    if not is_admin():
        print("Script requires administrator privileges. Elevating...")
        # Re-run the script with admin privileges
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    c = wmi.WMI()

    # Find the mounted volume by label
    for volume in c.Win32_Volume():
        if volume.Label == volume_label and volume.DriveLetter:
            try:
                # Unassign the drive letter
                volume.DriveLetter = None
                volume.Put_()
                print(f"Drive letter removed from volume: {volume.Label}")
                return
            except Exception as e:
                print(f"Failed to unassign drive letter: {e}")
                return
    print(f"Volume with label {volume_label} not found or does not have a drive letter.")

# Function to display unmounted volumes
def show_unassigned_volumes():
    volumes = get_all_volumes_wmi()
    unmounted_volumes = [v for v in volumes if v['status'] == 'unmounted']
    if unmounted_volumes:
        print("Unmounted volumes:")
        for volume in unmounted_volumes:
            print(f"Label: {volume['label']}, Path: {volume['name']}, FileSystem: {volume['fstype']}")
    else:
        print("No unmounted volumes found.")

# Function to clear temporary files
def clear_temp_files():
    if not is_admin():
        print("Script requires administrator privileges. Elevating...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    # Define the temp directories to clear
    temp_dirs = [
        os.getenv('TEMP'),
        r'C:\Windows\Temp',
        os.path.join(os.getenv('LOCALAPPDATA'), 'Temp')  # User's AppData\Local\Temp folder
    ]
    
    for temp_dir in temp_dirs:
        try:
            for filename in os.listdir(temp_dir):
                file_path = os.path.join(temp_dir, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                    print(f"Deleted: {file_path}")
                except Exception as e:
                    print(f"Failed to delete {file_path}: {e}")
        except Exception as e:
            print(f"Failed to access temp directory {temp_dir}: {e}")

# Main entry point to handle command-line arguments
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python my_drive.py <assign/unassign/clear_temp> <volume_label>")
        sys.exit(1)

    action = sys.argv[1]

    if action == "assign":
        if len(sys.argv) < 3:
            print("Please specify a volume label.")
        else:
            volume_label = sys.argv[2]
            letter_assigned = assign_drive_letter(volume_label)
            print(f"Drive letter assigned: {letter_assigned}")
    elif action == "unassign":
        if len(sys.argv) < 3:
            print("Please specify a volume label.")
        else:
            volume_label = sys.argv[2]
            unassign_drive_letter(volume_label)
    elif action == "clear_temp":
        clear_temp_files()
    else:
        print("Invalid action. Use 'assign', 'unassign', or 'clear_temp'.")
