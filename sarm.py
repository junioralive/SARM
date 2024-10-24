import os
import tkinter as tk
from tkinter import messagebox, ttk, Frame
from tkinterdnd2 import TkinterDnD, DND_FILES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
import subprocess
import tempfile
import atexit
import shutil

# Global variables
current_directory = None
logs_visible = False
temp_files = []  # List to track temporary files
temp_dir = tempfile.mkdtemp()  # Create a unique temporary directory for this session

# ------------------------ Utility Functions ------------------------

# Function to run the batch script with admin privileges
def run_batch_script(action):
    # Get the absolute path to the batch file in the current folder (same as the .exe)
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sarm.bat")

    if not os.path.exists(script_path):
        print(f"Error: {script_path} not found!")
        return

    try:
        # Use PowerShell to run the batch script with administrator privileges
        command = f'powershell -Command "Start-Process cmd -ArgumentList \'/c {script_path} {action}\' -Verb runAs"'
        subprocess.Popen(command, shell=True)
    except Exception as e:
        print(f"Error running the batch script: {e}")

# Function to derive a key using Argon2
def derive_key(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt if not provided
    key = hash_secret_raw(
        password.encode(),  # Password must be in bytes
        salt,
        time_cost=2,  # Adjust time cost for security
        memory_cost=102400,  # Adjust memory cost for security
        parallelism=8,  # Adjust parallelism for security
        hash_len=32,  # Output length of the key (32 bytes for AES-256)
        type=Type.I  # Use Argon2i variant
    )
    return key, salt

# Clean up temporary file after it's opened
def cleanup_temp_file(temp_file_path):
    if os.path.exists(temp_file_path):
        try:
            os.remove(temp_file_path)
            temp_files.remove(temp_file_path)
            add_log(f"Decrypted file has been removed from temp storage.")
        except Exception as e:
            add_log(f"Failed to remove temp file: {str(e)}")

# Function to handle clearing all temporary files and sensitive data
def clear_temp_files():
    try:
        clear_all_data()  # Call the new function to clear everything
        messagebox.showinfo("Success", "All temporary files and sensitive data have been cleared.")
    except Exception as e:
        add_log(f"Failed to clear all data: {str(e)}")
        messagebox.showerror("Error", f"Failed to clear all data: {str(e)}")

# Clean up all temp files and directories on application close
def cleanup_all_temp_files():
    global temp_dir
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)  # Delete the entire temp directory
            add_log(f"Temporary directory {temp_dir} has been removed.")
    except PermissionError as e:
        add_log(f"Permission error when removing {temp_dir}: {str(e)}")
    except Exception as e:
        add_log(f"Failed to remove temp directory {temp_dir}: {str(e)}")

def unlock_drive():
    run_batch_script("unhide")

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


# ------------------------ Password Encryption ------------------------

# AES-GCM encryption for password storage
def aes_gcm_encrypt_password(password):
    try:
        nonce = os.urandom(12)
        salt = os.urandom(16)
        key, salt = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_password = salt + encryptor.update(password.encode()) + encryptor.finalize()
        password_tag = encryptor.tag
        
        # Clear sensitive data after use
        password = None
        key = None
        return encrypted_password, nonce, password_tag
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")


# AES-GCM decryption for password retrieval
def aes_gcm_decrypt_password(encrypted_password, password, nonce, tag):
    try:
        salt = encrypted_password[:16]
        key, _ = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_password[16:]) + decryptor.finalize()

        # Clear sensitive data after decryption
        password = None
        key = None
        return decrypted_password.decode()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
        return None

# Set password securely
def set_password():
    entered_password = password_entry.get()
    if len(entered_password) >= 8:  # Ensure password is at least 8 characters
        encrypted_password, nonce, password_tag = aes_gcm_encrypt_password(entered_password)
        # Store these securely for later decryption
        save_password_data(encrypted_password, nonce, password_tag)
        messagebox.showinfo("Info", "Password has been securely set.")
        entered_password = None  # Clear the password from memory
    else:
        messagebox.showerror("Error", "Password must be at least 8 characters long.")

# Get and decrypt the password
def get_password():
    encrypted_password, nonce, tag = retrieve_password_data()
    
    # If password data is not set, return None
    if encrypted_password is None or nonce is None or tag is None:
        return None

    entered_password = password_entry.get()
    if len(entered_password) >= 8:
        decrypted_password = aes_gcm_decrypt_password(encrypted_password, entered_password, nonce, tag)
        return decrypted_password
    else:
        messagebox.showerror("Error", "Incorrect password.")
        return None


# Save encrypted password data securely (in-memory storage for demo purposes)
def save_password_data(encrypted_password, nonce, tag):
    global password_data
    password_data = (encrypted_password, nonce, tag)

# Retrieve encrypted password data (from secure storage or memory)
def retrieve_password_data():
    try:
        return password_data  # Return data stored in memory
    except NameError:
        messagebox.showerror("Error", "No password has been set. Please set the password first.")
        return None, None, None


# ------------------------ File Encryption ------------------------

# AES-GCM encryption for files
def aes_gcm_encrypt(file_path, dest_folder, password):
    try:
        key, salt = derive_key(password)  # Argon2 key derivation
        iv = os.urandom(12)  # Generate a new IV for each file
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = encryptor.update(file_data) + encryptor.finalize()

        # Store salt, IV, and encrypted data in the output file
        encrypted_file = salt + iv + encryptor.tag + encrypted_data
        file_name = os.path.basename(file_path)
        encrypted_file_path = os.path.join(dest_folder, file_name)  # Use original file name (no extension)

        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(encrypted_file)

        add_log(f"File encrypted and saved to {encrypted_file_path}")
        
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
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt file: {str(e)}")
        return None  # Return None if decryption fails

# ------------------------ File Encryption and Decryption ------------------------

# Encrypt a single file and store it in the correct relative folder structure
def encrypt_file(file_path, dest_folder, relative_path=""):
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return
    try:
        relative_dest_folder = os.path.join(dest_folder, relative_path)
        if not os.path.exists(relative_dest_folder):
            os.makedirs(relative_dest_folder)
        aes_gcm_encrypt(file_path, relative_dest_folder, password)  # Pass only file_path, dest_folder, and password
    except Exception as e:
        add_log(f"Failed to encrypt file {file_path}: {str(e)}")

# Encrypt a folder with its structure and save it in the correct current directory
def encrypt_folder_with_structure(folder_path, dest_folder):
    all_files = []
    root_folder_name = os.path.basename(folder_path.rstrip(os.sep))  # Root folder name to preserve structure
    for root, dirs, files in os.walk(folder_path):
        relative_path = os.path.relpath(root, folder_path)  # Calculate relative path to preserve structure
        for file in files:
            file_path = os.path.join(root, file)
            relative_path_with_root = os.path.join(root_folder_name, relative_path)  # Preserve folder structure
            all_files.append((file_path, relative_path_with_root))

    total_files = len(all_files)
    if total_files == 0:
        return

    # Process each file and encrypt it, preserving the folder structure
    process_files(all_files, dest_folder, total_files)

# Decrypt files with progress indicator, assuming all files are encrypted
def decrypt_files_with_progress(files, temp_dir, processed_count=0):
    progress_bar['value'] = 0
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    if processed_count >= len(files):
        add_log("All files have been decrypted.")
        progress_bar['value'] = 100
        status_label.config(text="Decryption Complete")

        # Ask for confirmation to delete the temp folder after the last file is decrypted
        confirm_done = messagebox.askyesno("Confirmation", "Are you done with the files? The folder will be deleted.")
        if confirm_done:
            try:
                shutil.rmtree(temp_dir)  # Delete the folder
                add_log(f"Temporary directory {temp_dir} has been removed.")
            except Exception as e:
                add_log(f"Failed to remove temp directory: {str(e)}")
        return

    # Process the current file and move to the next
    file_path = files[processed_count]
    original_file_name = os.path.basename(file_path)
    temp_file_path = os.path.join(temp_dir, original_file_name)

    try:
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

        # Save the decrypted file to the temp directory
        with open(temp_file_path, "wb") as temp_file:
            temp_file.write(decrypted_data)

        add_log(f"Decrypted file: {original_file_name}")
        progress_value = ((processed_count + 1) / len(files)) * 100
        progress_bar['value'] = progress_value

        # Open the temp file folder after each file is decrypted
        if processed_count == 0:
            os.startfile(temp_dir)  # Open the folder after the first decryption

        # Continue decrypting the next file
        root.after(100, decrypt_files_with_progress, files, temp_dir, processed_count + 1)

    except Exception as e:
        # If decryption fails, log the error and move to the next file
        add_log(f"Failed to decrypt file {file_path}: {str(e)}")
        root.after(100, decrypt_files_with_progress, files, temp_dir, processed_count + 1)

# Decrypt all files in the current directory, assuming all files are encrypted
def decrypt_all_files_in_current_directory():
    password = get_password()
    if not password:
        messagebox.showerror("Error", "Please set the password first!")
        return

    try:
        # Create a new temporary directory
        temp_dir = tempfile.mkdtemp()
        files_to_decrypt = [os.path.join(current_directory, item) for item in os.listdir(current_directory)]

        if len(files_to_decrypt) == 0:
            messagebox.showinfo("Info", "No files found in the current directory.")
            return

        status_label.config(text="Decryption in Progress...")
        progress_bar['value'] = 0

        # Start decrypting files with progress
        decrypt_files_with_progress(files_to_decrypt, temp_dir)

    except Exception as e:
        messagebox.showerror("Error", f"Failed to start decryption: {str(e)}")

# Decrypt a file, view it, and then ensure no trace is left
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

        # Create a temporary file and open it using system default apps
        temp_dir = tempfile.gettempdir()
        # Save the decrypted file without the .aesgcm extension
        original_file_name = os.path.basename(file_path)
        temp_file_path = os.path.join(temp_dir, original_file_name)

        with open(temp_file_path, "wb") as temp_file:
            temp_file.write(decrypted_data)

        # Clear sensitive data from memory
        decrypted_data = None
        key = None
        
        temp_files.append(temp_file_path)
        os.startfile(temp_file_path)

        confirm_done = messagebox.askyesno("Confirmation", "Are you done with the file? It will be deleted after you confirm.")
        if confirm_done:
            cleanup_temp_file(temp_file_path)

    except ValueError as e:
        # Handle decryption issues (e.g., bad decryption key)
        messagebox.showerror("Decryption Error", f"Decryption failed: {str(e)}")
    except Exception as e:
        # General error handler for other issues
        messagebox.showerror("Error", f"Failed to decrypt and open file: {str(e)}")

# Process files for encryption
def process_files(files, dest_folder, total_files, processed_count=0):
    progress_bar['value'] = 0
    if processed_count >= total_files:
        add_log("All files have been encrypted.")
        progress_bar['value'] = 100
        status_label.config(text="Encryption Complete")
        return

    current_file, relative_path = files[processed_count]
    encrypt_file(current_file, dest_folder, relative_path)  # Encrypt the file with the relative path preserved

    processed_count += 1
    progress_value = (processed_count / total_files) * 100
    progress_bar['value'] = progress_value

    add_log(f"Processing file {processed_count} of {total_files}: {os.path.basename(current_file)}")
    status_label.config(text=f"Processing: {os.path.basename(current_file)}")

    # Continue processing the next file after a delay to keep the UI responsive
    root.after(100, process_files, files, dest_folder, total_files, processed_count)

# ------------------------ GUI Functions ------------------------

# Refresh the file list to show files and folders in the selected drive or directory, hiding system folders
def refresh_file_list():
    global current_directory
    drive_path = "P:/"  # Default drive

    file_listbox.delete(0, tk.END)  # Clear previous files

    if current_directory:
        file_listbox.insert(tk.END, "Go back ⮌")  # Option to go back to parent directory
        file_listbox.itemconfig(tk.END, {'fg': 'red'})  # Set Go back ⮌ to red

    directory_to_list = current_directory if current_directory else drive_path

    try:
        for item in os.listdir(directory_to_list):
            if item in ["System Volume Information", "$RECYCLE.BIN"]:  # Hide system folders
                continue
            full_path = os.path.join(directory_to_list, item)
            display_name = f"{item}/" if os.path.isdir(full_path) else item
            file_listbox.insert(tk.END, display_name)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read directory contents: {str(e)}")

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

# Handle drag and drop files or folders for encryption
def handle_dragged_files(event):
    files = root.tk.splitlist(event.data)
    drive_path = current_directory if current_directory else "P:/"

    for file_path in files:
        if os.path.isdir(file_path):
            encrypt_folder_with_structure(file_path, drive_path)
        elif os.path.isfile(file_path):
            encrypt_file(file_path, drive_path)

# Toggle visibility of the log window
def toggle_logs():
    global logs_visible
    if logs_visible:
        status_listbox.grid_forget()
    else:
        status_listbox.grid(row=8, column=0, columnspan=2, padx=20, pady=10, sticky='nsew')
    logs_visible = not logs_visible

# Cleanup function on app close to ensure no sensitive data is left
def on_closing():
    try:
        clear_all_data()  # Clear all temp files and sensitive data
        run_batch_script("hide")  # Re-hide the partition if needed
    except Exception as e:
        print(f"Error during cleanup: {e}")
    finally:
        root.destroy()  # Ensure the Tkinter window is closed properly

# Register cleanup function with atexit to handle abnormal terminations
atexit.register(clear_all_data)


# ------------------------ GUI Application ------------------------
def create_gui():
    global root, password_entry, file_listbox, status_listbox, progress_bar, status_label, current_directory

    run_batch_script("unhide")

    root = TkinterDnD.Tk()
    root.title("Drive Encryption & Decryption")
    root.configure(bg='#2E2E2E')
    text_color = '#FFFFFF'
    button_color = '#444444'
    entry_bg_color = '#333333'
    entry_fg_color = '#FFFFFF'

    key_frame = Frame(root, bg='#2E2E2E')
    key_frame.grid(row=0, column=0, padx=20, pady=10, columnspan=2)

    file_frame = Frame(root, bg='#2E2E2E')
    file_frame.grid(row=2, column=0, padx=20, pady=10, sticky='nsew', columnspan=2)

    password_entry = tk.Entry(key_frame, width=30, font=("Arial", 12), bg=entry_bg_color, fg=entry_fg_color, relief='ridge', bd=2, show="*")
    password_entry.grid(row=0, column=0, padx=10)

    set_password_button = tk.Button(key_frame, text="Set Password", command=set_password, bg=button_color, fg=text_color, relief='ridge', bd=2)
    set_password_button.grid(row=0, column=1, padx=10)

    unlock_button = tk.Button(key_frame, text="Unlock", command=unlock_drive, bg=button_color, fg=text_color, relief='ridge', bd=2)
    unlock_button.grid(row=0, column=2, padx=10)
    
    # lock_button = tk.Button(key_frame, text="Lock", command=loc, bg=button_color, fg=text_color, relief='ridge', bd=2)
    # lock_button.grid(row=0, column=3, padx=10)
    
    decrypt_button = tk.Button(file_frame, text="Decrypt", command=decrypt_all_files_in_current_directory, bg=button_color, fg=text_color, relief='ridge', bd=2)
    decrypt_button.grid(row=2, column=0, padx=10, pady=5, sticky='ew')

    # Place the 'Clear Temp' button below the drag and drop label
    clear_temp_button = tk.Button(file_frame, text="Clear Temp", command=clear_temp_files, bg=button_color, fg=text_color, relief='ridge', bd=2)
    clear_temp_button.grid(row=2, column=1, padx=10, pady=5, sticky='ew')

    file_listbox = tk.Listbox(file_frame, height=20, width=120, bg='#333333', fg=text_color, relief='ridge', bd=2)
    file_listbox.grid(row=0, column=0, padx=0, pady=10, sticky='nsew', columnspan=2)
    file_listbox.bind('<Double-1>', handle_double_click)

    drag_drop_label = tk.Label(file_frame, text="Drag files or folders here", font=("Arial", 12), bg='#2E2E2E', fg=text_color)
    drag_drop_label.grid(row=1, column=0, padx=10, pady=10, sticky='ew', columnspan=2)

    root.drop_target_register(DND_FILES)
    root.dnd_bind('<<Drop>>', handle_dragged_files)

    status_listbox = tk.Listbox(root, height=5, width=100, bg='#333333', fg=text_color, relief='ridge', bd=2)
    status_listbox.grid_forget()

    progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=400, mode='determinate')
    progress_bar.grid(row=3, column=0, padx=20, pady=10, columnspan=2, sticky='ew')

    status_label = tk.Label(root, text="", font=("Arial", 10), bg='#2E2E2E', fg=text_color)
    status_label.grid(row=4, column=0, padx=20, pady=10, columnspan=2, sticky='ew')

    log_button = tk.Button(root, text="Show Logs", command=toggle_logs, bg=button_color, fg=text_color, relief='ridge', bd=2)
    log_button.grid(row=7, column=0, padx=10, pady=10, columnspan=2, sticky='ew')

    root.protocol("WM_DELETE_WINDOW", on_closing)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
