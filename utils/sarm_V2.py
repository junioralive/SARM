import os
import tkinter as tk
from tkinter import messagebox, PhotoImage
from tkinterdnd2 import TkinterDnD, DND_FILES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
import subprocess
import tempfile
import atexit
import shutil
import psutil
import win32api 
from utils.sarm_utils import get_all_volumes_wmi
import customtkinter as ctk
import threading

# ------------------------ ---------------- ------------------------
# ------------------------ Global variables ------------------------
# ------------------------ ---------------- ------------------------

current_directory = None # Track the current directory
logs_visible = False # Track log visibility
temp_files = []  # Track temporary files
temp_dir = tempfile.mkdtemp(prefix="SARM_")  # Unique temporary directory for this session
hidden_labels = []  # Track all unhidden partitions to hide them on exit
safe_close_var = None # Variable to track safe close status
is_locked = True # Track if the application is locked
current_color_index = 0  # Starting color index for rotation
colors = ["#FF6347", "#32CD32"]  # Colors for rotation

# ------------------------ ---------------- ------------------------
# ------------------------ Password Manager ------------------------
# ------------------------ ---------------- ------------------------

# Argon2 key derivation function
def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt if not provided
    key = hash_secret_raw( # Derive a key using Argon2
        password.encode(),  # Password must be in bytes
        salt, 
        time_cost=2,  # Adjust time cost for security
        memory_cost=102400,  # Adjust memory cost for security
        parallelism=8,  # Adjust parallelism for security
        hash_len=32,  # Output length of the key (32 bytes for AES-256)
        type=Type.I  # Use Argon2i variant
    )
    return key, salt

# AES-GCM encryption for password storage
def aes_gcm_encrypt_password(password):
    try:
        nonce = os.urandom(12) # Generate a new nonce for each encryption
        salt = os.urandom(16) # Generate a new salt for each encryption
        key, salt = derive_key(password, salt) # Derive a key using Argon2
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()) # Create a new AES-GCM cipher
        encryptor = cipher.encryptor() # Create an encryptor object
        encrypted_password = salt + encryptor.update(password.encode()) + encryptor.finalize() # Encrypt the password
        password_tag = encryptor.tag # Get the GCM tag for authentication

        # Clear sensitive data after use
        password = None 
        key = None
        return encrypted_password, nonce, password_tag
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

# AES-GCM decryption for password retrieval
def aes_gcm_decrypt_password(encrypted_password, password, nonce, tag):
    try:
        salt = encrypted_password[:16] # Extract the salt from the encrypted password
        key, _ = derive_key(password, salt) # Derive a key using Argon2 
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()) # Create a new AES-GCM cipher
        decryptor = cipher.decryptor() # Create a decryptor object 
        decrypted_password = decryptor.update(encrypted_password[16:]) + decryptor.finalize() # Decrypt the password

        # Clear sensitive data after decryption
        password = None
        key = None
        return decrypted_password.decode() 
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
        return None

# Set password securely
def set_password():
    entered_password = password_entry.get() # Get the entered password
    if len(entered_password) >= 8:  # Ensure password is at least 8 characters
        encrypted_password, nonce, password_tag = aes_gcm_encrypt_password(entered_password) # Encrypt the password
        # Store these securely for later decryption
        save_password_data(encrypted_password, nonce, password_tag) # Save the encrypted password data
        messagebox.showinfo("Info", "Password has been securely set.") 
        entered_password = None  # Clear the password from memory
    else:
        messagebox.showerror("Error", "Password must be at least 8 characters long.")

# Get and decrypt the password
def get_password():
    encrypted_password, nonce, tag = retrieve_password_data() # Retrieve the encrypted password data
    
    # If password data is not set, return None
    if encrypted_password is None or nonce is None or tag is None: 
        return None

    entered_password = password_entry.get() # Get the entered password
    if len(entered_password) >= 8: # Ensure password is at least 8 characters
        decrypted_password = aes_gcm_decrypt_password(encrypted_password, entered_password, nonce, tag) # Decrypt the password
        return decrypted_password 
    else:
        messagebox.showerror("Error", "Incorrect password.")
        return None

# Save encrypted password data securely (in-memory storage)
def save_password_data(encrypted_password, nonce, tag):
    global password_data
    password_data = (encrypted_password, nonce, tag)

# Retrieve encrypted password data (from memory)
def retrieve_password_data():
    try:
        return password_data  # Return data stored in memory
    except NameError:
        # messagebox.showerror("Error", "No password has been set. Please set the password first.")
        return None, None, None
    
#------------------------ ------------------------ ------------------------
# ------------------------ Encryption - Decryption ------------------------
# ------------------------ ------------------------ -----------------------

# AES-GCM encryption for files
def aes_gcm_encrypt(file_path, dest_folder, password):
    try:
        key, salt = derive_key(password) # Argon2 key derivation
        iv = os.urandom(12)  # Generate a new IV for each file
        encryptor = Cipher( # Create a new AES-GCM cipher
            algorithms.AES(key), 
            modes.GCM(iv), 
            backend=default_backend() 
        ).encryptor() # Create an encryptor object

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = encryptor.update(file_data) + encryptor.finalize() # Encrypt the file data

        # Store salt, IV, and encrypted data in the output file
        encrypted_file = salt + iv + encryptor.tag + encrypted_data # Combine all data into a single encrypted file
        file_name = os.path.basename(file_path) # Get the original file name
        encrypted_file_path = os.path.join(dest_folder, file_name)  # Use original file name (no extension)

        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(encrypted_file) 

        add_log(f"File encrypted and saved to {encrypted_file_path}") 
        refresh_file_list() 
        # Clear sensitive data from memory
        file_data = None
        encrypted_data = None
        key = None
        
    except Exception as e:
        add_log(f"Failed to encrypt file {file_path}: {str(e)}")

# AES-GCM decryption for files
def aes_gcm_decrypt(file_path, password):
    try:
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Extract salt, IV, and GCM tag
        salt = encrypted_data[:16]  # Extract the salt
        iv = encrypted_data[16:28]  # Extract the IV
        tag = encrypted_data[28:44]  # Extract the GCM tag
        ciphertext = encrypted_data[44:]  # The actual encrypted data

        key, _ = derive_key(password, salt)  # Argon2 key derivation
        decryptor = Cipher( # Create a new AES-GCM cipher
            algorithms.AES(key), 
            modes.GCM(iv, tag), 
            backend=default_backend() 
        ).decryptor() # Create a decryptor object

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize() # Decrypt the file data
        refresh_file_list()
        return decrypted_data
    except Exception as e:
        messagebox.showerror(f"Failed to decrypt file: {str(e)}")
        return None
    
# ------------------------ ---------------------------- ------------------------
# ------------------------ File Encryption - Decryption ------------------------
# ------------------------ ---------------------------- ------------------------

# Function to recursively gather all files within a directory (including subdirectories)
def gather_files_recursively(directory):
    all_files = [] 
    for root, _, files in os.walk(directory): 
        for file in files:
            all_files.append(os.path.join(root, file))
    return all_files

# Encrypt a single file and store it in the correct relative folder structure
def encrypt_file(file_path, dest_folder, relative_path=""):
    password = get_password() # Get the password for encryption
    if not password: 
        messagebox.showerror("Error", "Please set the password first!")
        return
    try:
        relative_dest_folder = os.path.join(dest_folder, relative_path) # Create the relative destination folder
        if not os.path.exists(relative_dest_folder): 
            os.makedirs(relative_dest_folder) # Create the relative destination folder if it doesn't exist
        aes_gcm_encrypt(file_path, relative_dest_folder, password)  # Pass only file_path, dest_folder, and password
    except Exception as e:
        add_log(f"Failed to encrypt file {file_path}: {str(e)}")

# Decrypt a file, view it.
def decrypt_and_open_file(file_path):
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    try:
        # Read the encrypted data and verify its structure
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Verify that the file is at least large enough to contain the required components
        if len(encrypted_data) < 44:  # 16 bytes (salt) + 12 bytes (IV) + 16 bytes (tag) + ciphertext
            messagebox.showerror("Error", "The file is not in the correct encrypted format.")
            return

        # Extract salt, IV, and GCM tag
        salt = encrypted_data[:16]
        iv = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]

        # Derive key and decrypt
        key, _ = derive_key(password, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        original_file_name = os.path.basename(file_path)
        temp_file_path = os.path.join(temp_dir, original_file_name)

        with open(temp_file_path, "wb") as temp_file:
            temp_file.write(decrypted_data)

        # Clear sensitive data from memory
        decrypted_data = None
        key = None
        
        temp_files.append(temp_file_path)
        os.startfile(temp_file_path)

        # confirm_done = messagebox.askyesno("Confirmation", "Are you done with the file? It will be deleted after you confirm.")
        # if confirm_done:
        #     cleanup_temp_file(temp_file_path)  # Clean up the single temporary file

    except ValueError as e:
        # Handle decryption issues (e.g., bad decryption key)
        messagebox.showerror("Decryption Error", f"Decryption failed: {str(e)}")
    except Exception as e:
        # General error handler for other issues
        messagebox.showerror("Error", f"Failed to decrypt and open file: {str(e)}")

# Encrypt a folder with its structure and save it in the correct current directory
def encrypt_folder_with_structure(folder_path, dest_folder):
    all_files = [] # Track all files in the folder
    root_folder_name = os.path.basename(folder_path.rstrip(os.sep))  # Root folder name to preserve structure
    for root, dirs, files in os.walk(folder_path): 
        relative_path = os.path.relpath(root, folder_path)  # Calculate relative path to preserve structure
        for file in files:
            file_path = os.path.join(root, file) # Full file path
            relative_path_with_root = os.path.join(root_folder_name, relative_path)  # Preserve folder structure
            all_files.append((file_path, relative_path_with_root)) # Store the file path and relative path

    total_files = len(all_files) # Total number of files to process
    if total_files == 0:
        return

    # Process each file and encrypt it, preserving the folder structure
    process_files(all_files, dest_folder, total_files) 

# Process files for encryption
def process_files(files, dest_folder, total_files, processed_count=0):
    progress_bar['value'] = 0
    if processed_count >= total_files:
        add_log("All files have been encrypted.")
        progress_bar['value'] = 100
        status_label.configure(text="Encryption Complete")
        return

    current_file, relative_path = files[processed_count]
    encrypt_file(current_file, dest_folder, relative_path)  # Encrypt the file with the relative path preserved

    processed_count += 1
    progress_value = (processed_count / total_files) * 100
    progress_bar['value'] = progress_value

    add_log(f"Processing file {processed_count} of {total_files}: {os.path.basename(current_file)}")
    status_label.configure(text=f"Processing: {os.path.basename(current_file)}")

    # Continue processing the next file after a delay to keep the UI responsive
    root.after(100, process_files, files, dest_folder, total_files, processed_count)

# Decrypt all files in the current directory, creating a master folder in temp if needed
def decrypt_all_files_in_current_directory():
    global decrypt_in_progress # Track decryption progress
    password = get_password() # Get the password for decryption
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    try:
        # Determine the decryption target path based on the checkbox state
        target_folder = tempfile.mkdtemp(dir=temp_dir) if decrypt_to_temp.get() else current_directory

        # Open the target folder immediately after creation if decrypting to temp
        if decrypt_to_temp.get():
            os.startfile(target_folder) # Open the target folder

        # Collect all files within the directory and subdirectories
        files_to_decrypt = gather_files_recursively(current_directory) 

        if not files_to_decrypt:
            messagebox.showinfo("Info", "No files found in the current directory.")
            decrypt_to_temp_checkbox.configure(state=tk.NORMAL)  # Re-enable the checkbox
            return

        status_label.configure(text="Decryption in Progress...")
        progress_bar['value'] = 0

        # Start decrypting files with the correct target folder
        decrypt_files_with_master_folder(files_to_decrypt, current_directory, 0, target_folder, decrypt_to_temp.get())

    except Exception as e:
        messagebox.showerror("Error", f"Failed to start decryption: {str(e)}")
    finally:
        decrypt_to_temp_checkbox.configure(state=tk.NORMAL) # Re-enable the checkbox
        decrypt_in_progress = False # Reset decryption progress flag

# Updated decrypt_files_with_master_folder function to skip directories and handle permission errors
def decrypt_files_with_master_folder(files, root_dir, processed_count=0, target_dir=None, decrypt_to_temp_state=False):
    # Create a unique temp folder within temp_dir if target_dir is not provided
    if target_dir is None:
        target_dir = tempfile.mkdtemp(dir=temp_dir)  # Create a unique temp folder within temp_dir

    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    total_files = len(files)
    if total_files == 0:
        add_log("No files to decrypt.")
        progress_bar.set(0)
        status_label.configure(text="No files to decrypt")
        return

    # Check if all files have been processed
    if processed_count >= total_files:
        add_log("All files have been decrypted.")
        progress_bar.set(1)  # Set progress to 100%
        status_label.configure(text="Decryption Complete")
        return

    # Process the current file and move to the next
    file_path = files[processed_count]
    relative_path = os.path.relpath(file_path, root_dir)
    decrypted_file_path = os.path.join(target_dir, relative_path)

    try:
        # Maintain directory structure in the target directory
        os.makedirs(os.path.dirname(decrypted_file_path), exist_ok=True)

        # Read the encrypted data and decrypt it
        with open(file_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        # Extract salt, IV, and tag from the encrypted file
        salt = encrypted_data[:16]
        iv = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]

        # Derive the key using the extracted salt and password
        key, _ = derive_key(password, salt)

        # Perform decryption
        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Save the decrypted file in the target directory
        with open(decrypted_file_path, "wb") as dec_file:
            dec_file.write(decrypted_data)

        add_log(f"Decrypted file saved to {decrypted_file_path}")

        # Update the progress bar
        progress_value = ((processed_count + 1) / total_files) * 100
        progress_bar.set(progress_value / 100)  # Scale progress to 0-1 for customtkinter
        root.update_idletasks()  # Force UI refresh to show progress

        # Continue decrypting the next file
        root.after(100, decrypt_files_with_master_folder, files, root_dir, processed_count + 1, target_dir, decrypt_to_temp_state)

    except Exception as e:
        # If decryption fails, log the error and move to the next file
        add_log(f"Failed to decrypt file {file_path}: {str(e)}")
        root.after(100, decrypt_files_with_master_folder, files, root_dir, processed_count + 1, target_dir, decrypt_to_temp_state)

# Function to encrypt multiple selected files or folders in the current directory
def encrypt_selected_files():
    selected_items = [file_listbox.get(i).strip("/") for i in file_listbox.curselection()]
    if not selected_items:
        messagebox.showerror("Error", "Please select files or folders to encrypt.")
        return

    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    for selected_item in selected_items:
        file_path = os.path.join(current_directory, selected_item)
        if os.path.isdir(file_path):
            # Encrypt the entire folder structure
            encrypt_folder_with_structure(file_path, current_directory)
            add_log(f"Folder encrypted with structure preserved: {file_path}")
        elif os.path.isfile(file_path):
            # Encrypt a single file
            try:
                encrypt_file(file_path, current_directory)
                add_log(f"Encrypted file saved as {file_path}")
            except Exception as e:
                add_log(f"Failed to encrypt file {file_path}: {str(e)}")
        else:
            messagebox.showerror("Error", f"The selected item '{selected_item}' is not a valid file or folder.")

# Encrypt files with progress indicator
def encrypt_files_with_structure(files, root_dir, processed_count=0):
    total_files = len(files)
    if total_files == 0:
        return

    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    if processed_count >= total_files:
        add_log("All files have been encrypted.")
        update_progress_bar(100)
        status_label.configure(text="Encryption Complete")
        return

    # Process the current file and move to the next
    file_path = files[processed_count]
    relative_path = os.path.relpath(file_path, root_dir)
    encrypted_file_path = os.path.join(root_dir, relative_path)

    try:
        os.makedirs(os.path.dirname(encrypted_file_path), exist_ok=True)
        
        # Encrypt the file
        aes_gcm_encrypt(file_path, os.path.dirname(encrypted_file_path), password)
        add_log(f"Encrypted file saved as {encrypted_file_path}")
        
        processed_count += 1
        progress_value = (processed_count / total_files) * 100
        update_progress_bar(progress_value)

        # Continue encrypting the next file
        root.after(100, encrypt_files_with_structure, files, root_dir, processed_count)

    except Exception as e:
        add_log(f"Failed to encrypt file {file_path}: {str(e)}")
        root.after(100, encrypt_files_with_structure, files, root_dir, processed_count)

# Process files for encryption with progress
def process_files_for_encryption(files, dest_folder, processed_count=0):
    total_files = len(files)
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    if processed_count >= total_files:
        add_log("All files have been encrypted.")
        update_progress_bar(100)
        status_label.configure(text="Encryption Complete")
        return

    current_file = files[processed_count]
    try:
        # Encrypt the file
        aes_gcm_encrypt(current_file, dest_folder, password)
        add_log(f"Encrypted file: {os.path.basename(current_file)}")

        processed_count += 1
        progress_value = (processed_count / total_files) * 100
        update_progress_bar(progress_value)

        # Continue processing the next file
        root.after(100, process_files_for_encryption, files, dest_folder, processed_count)

    except Exception as e:
        add_log(f"Failed to encrypt file {current_file}: {str(e)}")
        root.after(100, process_files_for_encryption, files, dest_folder, processed_count)

# Modified function to encrypt all files in the current directory and subdirectories
def encrypt_all_files_in_current_directory():
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    try:
        # Collect all files within the directory and subdirectories
        files_to_encrypt = gather_files_recursively(current_directory)

        if not files_to_encrypt:
            messagebox.showinfo("Info", "No files found in the current directory.")
            return

        status_label.configure(text="Encryption in Progress...")
        progress_bar['value'] = 0

        # Start encrypting files with progress
        encrypt_files_with_structure(files_to_encrypt, current_directory)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to start encryption: {str(e)}")

# Function to decrypt multiple selected files or folders in the current directory
def decrypt_selected_files():
    selected_items = [file_listbox.get(i).strip("/") for i in file_listbox.curselection()]
    if not selected_items:
        messagebox.showerror("Error", "Please select files or folders to decrypt.")
        return

    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    for selected_item in selected_items:
        file_path = os.path.join(current_directory, selected_item)
        if os.path.isdir(file_path):
            # Decrypt the entire folder structure
            decrypt_all_files_in_folder(file_path)
            add_log(f"Folder decrypted with structure preserved: {file_path}")
        elif os.path.isfile(file_path):
            # Decrypt a single file
            try:
                decrypted_data = aes_gcm_decrypt(file_path, password)
                if decrypted_data is not None:
                    decrypted_file_path = os.path.join(current_directory, f"{selected_item}")
                    with open(decrypted_file_path, "wb") as dec_file:
                        dec_file.write(decrypted_data)
                    add_log(f"Decrypted file saved to {decrypted_file_path}")
            except Exception as e:
                add_log(f"Failed to decrypt file {file_path}: {str(e)}")
        else:
            messagebox.showerror("Error", f"The selected item '{selected_item}' is not a valid file or folder.")

# Function to decrypt all files in a folder recursively
def decrypt_all_files_in_folder(folder_path):
    # Gather all files in the folder and decrypt them, preserving folder structure
    files_to_decrypt = gather_files_recursively(folder_path)
    if files_to_decrypt:
        decrypt_files_with_master_folder(files_to_decrypt, folder_path, target_dir=folder_path)
    else:
        add_log(f"No files to decrypt in folder: {folder_path}")

# Process files in a separate thread for drag-and-drop handling
def process_files_in_thread(files, dest_folder):
    total_files = len(files)
    processed_count = 0

    # Retrieve the password securely
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    for file_path in files:
        if not os.path.exists(file_path):
            add_log(f"Error: Path '{file_path}' does not exist.")
            continue

        try:
            if os.path.isdir(file_path):
                encrypt_folder_with_structure(file_path, dest_folder)
                add_log(f"Folder '{file_path}' encrypted successfully.")
            elif os.path.isfile(file_path):
                encrypt_file(file_path, dest_folder)
                add_log(f"File '{file_path}' encrypted successfully.")
            else:
                add_log(f"Skipping '{file_path}' as it's not a valid file or folder.")
        except Exception as e:
            add_log(f"Error processing '{file_path}': {str(e)}")

        # Update progress after each file
        processed_count += 1
        progress_value = (processed_count / total_files) * 100
        update_progress_bar(progress_value)

# ------------------------ ----------------- ------------------------
# ------------------------ Utility Functions ------------------------
# ------------------------ ----------------- ------------------------

# Function to list available drives with both drive letter and label
def get_available_drives():
    partitions = psutil.disk_partitions()
    drives = []

    for partition in partitions:
        if 'removable' in partition.opts or 'rw' in partition.opts:
            try:
                # Get volume label and format as "Label (Drive Letter)" if label exists
                drive_label = win32api.GetVolumeInformation(partition.device)[0]
                display_name = f"{drive_label} ({partition.device.strip(':')})" if drive_label else partition.device.strip(":")
                drives.append(display_name)
            except Exception as e:
                # If label retrieval fails, just use the drive letter
                drives.append(partition.device.strip(":"))
                print(f"Error retrieving label for drive {partition.device}: {e}")
    
    return drives

def get_unassigned_volumes():
    # Use WMI method to retrieve all volumes
    volumes = get_all_volumes_wmi()
    # Filter volumes that are unmounted
    unmounted_volumes = [v for v in volumes if v.get('status') == 'unmounted']
    # Return only volume labels for the dropdown display
    return [volume.get('label', 'Unknown') for volume in unmounted_volumes]  # Use 'Unknown' if label not found

def handle_unassigned_volume_selection(event):
    selected_label = unassigned_volume_combobox.get()
    if selected_label:
        hidden_labels.append(selected_label)
        try:
            subprocess.Popen(["python", "utils/sarm_utils.py", "assign", selected_label], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            messagebox.showinfo("Info", f"Assigning drive letter to {selected_label}.")
            populate_drive_dropdown()
            populate_unassigned_volumes()
            unassigned_volume_combobox.set("Hidden Volume")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to assign drive letter: {e}")

# CustomTkinter ComboBox configuration and population functions
def populate_drive_dropdown():
    global drive_combobox
    drive_display = get_available_drives()

    if drive_display:
        drive_combobox.configure(values=drive_display)
    else:
        drive_combobox.configure(values=["No drives available"])
    drive_combobox.set("Select Drive")

def populate_unassigned_volumes():
    global unassigned_volume_combobox
    unassigned_volumes = get_unassigned_volumes()

    if unassigned_volumes:
        unassigned_volume_combobox.configure(values=unassigned_volumes)
    else:
        unassigned_volume_combobox.configure(values=["No hidden volumes found"])
    unassigned_volume_combobox.set("Hidden Volume")

def handle_drive_selection(event):
    global current_directory
    selected_drive = drive_combobox.get()

    if selected_drive and "No drives available" not in selected_drive:
        # Extract the drive letter from the selection text
        drive_letter = selected_drive.split("(")[-1].split(")")[0] if "(" in selected_drive and ")" in selected_drive else selected_drive
        current_directory = f"{drive_letter}"

        if os.path.exists(current_directory):
            refresh_file_list()  # Trigger refresh after setting directory
        else:
            messagebox.showerror("Error", f"The selected drive '{current_directory}' is not accessible.")
            current_directory = None
    else:
        messagebox.showerror("Error", "Please select a valid drive.")

# Function to set the path based on user input
def set_custom_path():
    global current_directory
    entered_path = path_entry.get()
    if os.path.exists(entered_path):
        current_directory = entered_path
        refresh_file_list()
    else:
        messagebox.showerror("Error", "Invalid path. Please enter a valid folder path.")

# Clean up temporary file after it's opened
def cleanup_temp_file(temp_file_path):
    # Check if the file is in the list of temp files
    if temp_file_path in temp_files and os.path.exists(temp_file_path):
        try:
            os.remove(temp_file_path)
            temp_files.remove(temp_file_path)
            add_log(f"Decrypted file '{temp_file_path}' has been removed from temp storage.")
        except Exception as e:
            add_log(f"Failed to remove temp file '{temp_file_path}': {str(e)}")

# Clean up all temp files and directories on application close
def cleanup_all_temp_files():
    global temp_dir
    try:
        # Only remove if the directory path matches temp_dir
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)  # Delete the entire temp directory
            add_log(f"Temporary directory {temp_dir} has been removed.")
        else:
            add_log(f"Skipped deletion for {temp_dir} as it's not in the designated temp folder.")
    except PermissionError as e:
        add_log(f"Permission error when removing {temp_dir}: {str(e)}")
    except Exception as e:
        add_log(f"Failed to remove temp directory {temp_dir}: {str(e)}")

# Securely clear password-related data from memory
def clear_sensitive_data():
    global password_data, password_entry
    password_data = (None, None, None)  # Clear password data from memory
    password_entry.delete(0, tk.END)  # Clear password input field
    add_log("Sensitive data has been cleared.")

# Clear all temporary files and sensitive variables
def clear_all_data():
    try:
        cleanup_all_temp_files()  # Remove all temporary files and directory
        clear_sensitive_data()  # Clear sensitive data (passwords, etc.)

        # If Tkinter root exists and has not been destroyed, add logs
        if 'root' in globals() and root is not None:
            try:
                if root.winfo_exists():
                    add_log("All sensitive data and temp files have been cleared.")
            except tk.TclError:
                # Tkinter has been destroyed, so we skip it
                pass
    except Exception as e:
        try:
            if 'root' in globals() and root is not None:
                add_log(f"Failed to clear all data: {str(e)}")
        except tk.TclError:
            pass
    
# ------------------------ ------------ ------------------------
# ------------------------ GUI Function ------------------------
# ------------------------ ------------ ------------------------

# Single definition of `handle_dragged_files`
def handle_dragged_files(event):
    files = root.tk.splitlist(event.data)

    if not current_directory:
        messagebox.showerror("Error", "Please select a drive or enter a path first.")
        return

    # Start encryption in a new thread to avoid blocking the main thread
    threading.Thread(target=process_files_in_thread, args=(files, current_directory)).start()

# Refresh the file list to show files and folders in the selected drive or directory
def refresh_file_list():
    global current_directory
    if not current_directory or not os.path.exists(current_directory):
        messagebox.showerror("Error", "Please select a valid drive or directory.")
        return

    file_listbox.delete(0, tk.END)
    if current_directory != drive_combobox.get():
        file_listbox.insert(tk.END, "Go back ⮌")
        file_listbox.itemconfig(tk.END, {'fg': 'red'})

    try:
        for item in os.listdir(current_directory):
            if item in ["System Volume Information", "$RECYCLE.BIN"]:
                continue
            display_name = f"{item}/" if os.path.isdir(os.path.join(current_directory, item)) else item
            file_listbox.insert(tk.END, display_name)
    except Exception as e:
        messagebox.showerror("Error", f"Could not read directory contents: {e}")

# Function to refresh the current path, hidden volumes, and drive dropdown while preserving the current working drive and directory
def refresh_all():
    global current_directory
    # Save the current selections
    selected_drive = drive_combobox.get()
    selected_hidden_volume = unassigned_volume_combobox.get()

    # Refresh the drive and hidden volume dropdowns
    populate_drive_dropdown()
    populate_unassigned_volumes()

    # Restore the previous selections if available
    if selected_drive in drive_combobox.cget("values"):
        drive_combobox.set(selected_drive)
    if selected_hidden_volume in unassigned_volume_combobox.cget("values"):
        unassigned_volume_combobox.set(selected_hidden_volume)

    # Refresh the file list in the current directory if it's set
    if current_directory and os.path.exists(current_directory):
        refresh_file_list()
    else:
        current_directory = None  # Reset if directory doesn't exist
        
# Function to update the progress bar in small increments
def update_progress_bar(progress):
    progress_bar.set(progress / 100)  # Scale progress to a 0-1 range for customtkinter
    root.update_idletasks()  # Force update the UI immediately

# Change directory when clicking on a folder
def change_directory(folder_name):
    global current_directory
    if folder_name == "Go back ⮌":
        go_up_directory()
    else:
        current_directory = os.path.join(current_directory, folder_name) if current_directory else os.path.join("P:/", folder_name)
    refresh_file_list()

# Go up to the parent directory
def go_up_directory():
    global current_directory
    if current_directory:
        current_directory = os.path.dirname(current_directory)
        refresh_file_list()

# Handle file selection from the file list (folders open, files decrypt)
def handle_file_selection(event):
    selected_item = file_listbox.get(tk.ACTIVE).strip("/")

    full_path = os.path.join(current_directory if current_directory else "P:/", selected_item)

    if selected_item == "Go back ⮌":
        go_up_directory()
    elif os.path.isdir(full_path):
        change_directory(selected_item)
    elif os.path.isfile(full_path):
        decrypt_and_open_file(full_path)
    else:
        messagebox.showerror("Error", "Please select a valid file.")

# Handle double-click event to ensure smooth folder and file navigation
def handle_double_click(event):
    handle_file_selection(event)

# Add log messages to the status listbox or print if Tkinter is destroyed
def add_log(message):
    # Check if Tkinter is still active (root exists and hasn't been destroyed)
    if root.winfo_exists():
        status_listbox.insert(tk.END, message)
        status_listbox.yview(tk.END)
    else:
        print(message)  # Log to console if the GUI is closed

# Toggle visibility of the log window
def toggle_logs():
    global logs_visible
    if logs_visible:
        status_listbox.grid_forget()
    else:
        status_listbox.grid(row=8, column=0, columnspan=4, padx=20, pady=10, sticky='nsew')
    logs_visible = not logs_visible

# Function to toggle between single and multiple selection modes
def toggle_selection_mode():
    if multi_select_var.get():
        file_listbox.configure(selectmode=tk.MULTIPLE)
    else:
        file_listbox.configure(selectmode=tk.SINGLE)

# Function to toggle lock/unlock display and update color
def toggle_lock_animation():
    global is_locked, current_color_index

    # Choose the lock/unlock emoji based on current state
    lock_emoji = "🔒" if is_locked else "🔓"
    app_label.configure(text=f"SARM {lock_emoji}", text_color=colors[current_color_index])

    # Toggle the lock state and rotate the color
    is_locked = not is_locked
    current_color_index = (current_color_index + 1) % len(colors)  # Cycle through colors

    # Repeat the toggle every 700ms for continuous animation
    root.after(700, toggle_lock_animation)

# Define the new `on_closing` function to handle the "Safe Close" checkbox
def on_closing():
    try:
        clear_all_data()  # Clear all temp files and sensitive data
        for label in hidden_labels:
            # Unassign the drive letter by calling the 'unassign' action with the label
            subprocess.Popen(
                ["python", "utils/sarm_utils.py", "unassign", label], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            add_log(f"Unassigned drive letter from {label}")
        hidden_labels.clear()  # Clear the list after unassignment
        if safe_close_var and safe_close_var.get():
            subprocess.Popen(
                ["python", "utils/sarm_utils.py", "clear_temp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
    except Exception as e:
        print(f"Error during cleanup: {e}")
    finally:
        root.destroy()  # Ensure the Tkinter window is closed properly

# Register cleanup function with atexit to handle abnormal terminations
atexit.register(clear_all_data)

# ------------------------ --------------- ------------------------
# ------------------------ GUI Application ------------------------
# ------------------------ --------------- ------------------------

def sarm_gui():
    global root, password_entry, file_listbox, status_listbox, progress_bar, status_label, safe_close_var, app_label
    global current_directory, path_entry, drive_combobox, unassigned_volume_combobox, multi_select_var, decrypt_to_temp, decrypt_to_temp_checkbox
    
    # Initialize customtkinter
    ctk.set_appearance_mode("dark")  # Set dark theme
    ctk.set_default_color_theme("blue")  # Set color theme
    root = TkinterDnD.Tk()
    root.title("SARM")
    root.configure(bg='#2E2E2E')

    # Set the favicon
    try:
        icon_path = "utils/media/sarm_favicon.png"  # Adjust path if needed
        favicon = PhotoImage(file=icon_path)
        root.iconphoto(False, favicon)
    except Exception as e:
        print(f"Error setting favicon: {e}")

    # First row (App name label and password input)
    key_frame = ctk.CTkFrame(root)
    key_frame.grid(row=0, column=0, padx=20, pady=10, columnspan=4)

    # App name label with dynamic color-changing effect
    app_label = ctk.CTkLabel(key_frame, text="SARM", font=("Helvetica", 16, "bold"), text_color='#57b9ff')
    app_label.grid(row=0, column=0, padx=10, sticky="w")

    # # Start the animation
    # toggle_lock_animation()

    # Password entry field
    password_entry = ctk.CTkEntry(key_frame, width=200, placeholder_text="Enter password", show="*")
    password_entry.grid(row=0, column=1, padx=10)

    # Set password button
    set_password_button = ctk.CTkButton(key_frame, text="Set Password", command=set_password, width=100)
    set_password_button.grid(row=0, column=2, padx=10)

    # Second row (hidden drive dropdown, drive dropdown, path entry, set path button)
    second_row_frame = ctk.CTkFrame(root)
    second_row_frame.grid(row=1, column=0, padx=20, pady=10, columnspan=4, sticky='nsew')

    # Hidden volume dropdown
    unassigned_volume_combobox = ctk.CTkComboBox(second_row_frame, values=[], width=120, command=handle_unassigned_volume_selection, state="readonly")
    unassigned_volume_combobox.set("Hidden Volume")
    unassigned_volume_combobox.grid(row=0, column=0, padx=(10, 5))
    populate_unassigned_volumes()

    # Drive dropdown (main drive)
    drive_combobox = ctk.CTkComboBox(second_row_frame, values=get_available_drives(), width=120, command=handle_drive_selection, state="readonly")
    drive_combobox.set("Select Drive")
    drive_combobox.grid(row=0, column=1, padx=(5, 10))

    # Path entry box
    path_entry = ctk.CTkEntry(second_row_frame, width=200, placeholder_text="Enter path")
    path_entry.grid(row=0, column=2, padx=10)

    # Set path button
    set_path_button = ctk.CTkButton(second_row_frame, text="Set Path", command=set_custom_path, width=100)
    set_path_button.grid(row=0, column=3, padx=10)

    # Refresh button
    refresh_button = ctk.CTkButton(second_row_frame, text="Refresh", command=refresh_all, width=100)
    refresh_button.grid(row=0, column=4, padx=10)
    
    # File frame
    file_frame = ctk.CTkFrame(root)
    file_frame.grid(row=2, column=0, padx=20, pady=10, sticky='nsew', columnspan=4)

    decrypt_button = ctk.CTkButton(file_frame, text="Decrypt Path", command=decrypt_all_files_in_current_directory)
    decrypt_button.grid(row=2, column=0, padx=10, pady=5, sticky='ew')

    encrypt_path_button = ctk.CTkButton(file_frame, text="Encrypt Path", command=encrypt_all_files_in_current_directory)
    encrypt_path_button.grid(row=2, column=1, padx=10, pady=5, sticky='ew')

    decrypt_button = ctk.CTkButton(file_frame, text="Decrypt", command=decrypt_selected_files)
    decrypt_button.grid(row=2, column=2, padx=10, pady=5, sticky='ew')

    encrypt_button = ctk.CTkButton(file_frame, text="Encrypt", command=encrypt_selected_files)
    encrypt_button.grid(row=2, column=3, padx=10, pady=5, sticky='ew')

    # Add a checkbox for enabling multiple selection mode
    multi_select_var = ctk.BooleanVar(value=False)
    multi_select_checkbox = ctk.CTkCheckBox(root, text="Multi-Selection", variable=multi_select_var, command=toggle_selection_mode)
    multi_select_checkbox.grid(row=5, column=0, padx=20, pady=5, sticky='w')

    # Add checkbox for decryption path selection
    decrypt_to_temp = ctk.BooleanVar(value=True)  # Default is to decrypt to temp
    decrypt_to_temp_checkbox = ctk.CTkCheckBox(root, text="Temp Folder", variable=decrypt_to_temp)
    decrypt_to_temp_checkbox.grid(row=5, column=1, padx=20, pady=5, sticky='w')

    # Add the Safe Close checkbox
    safe_close_var = ctk.BooleanVar(value=False)  # Default is unchecked for safe close
    safe_close_checkbox = ctk.CTkCheckBox(root, text="Safe Mode", variable=safe_close_var)
    safe_close_checkbox.grid(row=5, column=2, padx=20, pady=5, sticky='w')

    # Listbox for files using tkinter Listbox
    file_listbox = tk.Listbox(file_frame, height=20, width=120, bg='#333333', fg='white', selectmode=tk.SINGLE)
    file_listbox.grid(row=0, column=0, padx=0, pady=10, sticky='nsew', columnspan=4)
    file_listbox.bind('<Double-1>', handle_double_click)

    drag_drop_label = ctk.CTkLabel(file_frame, text="Drag files or folders above")
    drag_drop_label.grid(row=1, column=0, padx=10, pady=10, sticky='ew', columnspan=4)

    root.drop_target_register(DND_FILES)
    root.dnd_bind('<<Drop>>', handle_dragged_files)

    # Status listbox for logs
    status_listbox = tk.Listbox(root, height=5, width=100, bg='#333333', fg='white')
    status_listbox.grid_forget()

    # Progress bar
    progress_bar = ctk.CTkProgressBar(root, orientation='horizontal', width=400)
    progress_bar.grid(row=3, column=0, padx=20, pady=10, columnspan=4, sticky='ew')
    progress_bar.set(0)  # Set initial progress to 0

    # Status label
    status_label = ctk.CTkLabel(root, text="")
    status_label.grid(row=4, column=0, padx=20, pady=10, columnspan=4, sticky='ew')

    log_button = ctk.CTkButton(root, text="Show Logs", command=toggle_logs)
    log_button.grid(row=7, column=0, padx=10, pady=10, columnspan=4, sticky='ew')

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()
    
# if __name__ == "__main__":
#     sarm_gui()
