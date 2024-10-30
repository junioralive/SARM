# SARM

![sarm_bn](utils/media/sarm.jpeg)

## Project Overview

**SARM** (Secure Access and Real-time Management) is a robust encryption and file management tool designed to provide real-time protection for sensitive files across all types of storage devices, including local drives, external hard drives, USBs, and more. It utilizes **AES-GCM encryption** to ensure the security of files, offering seamless real-time decryption for access without retaining decrypted copies. This tool is currently available for **Windows** in its **beta phase**, with plans to expand to a **cross-platform** solution in the future.

SARM addresses critical privacy and security needs by ensuring that decrypted files are not left stored on any drive after they are accessed, making it ideal for handling highly sensitive data. All encryption and decryption processes are performed **in real-time**, maintaining security while providing smooth, transparent access.

## DEMO

Uploading Soon...

## Features

- **Real-time Encryption & Decryption**: Encrypts files and folders upon storage, with instant decryption when accessed, ensuring no decrypted copies remain.
- **AES-GCM Encryption**: Provides advanced encryption standards to secure data and ensure file integrity.
- **Argon2 Key Derivation**: Utilizes Argon2i for strong password protection.
- **Drag-and-Drop File Encryption**: Enables quick encryption of files and folders, preserving their original structure.
- **Minimalistic Dark-Themed UI**: Clean interface with hidden logs for a focused user experience.
- **Temporary File Cleanup**: Automatically removes all temporary files, ensuring no trace of decrypted data remains.
- **Multi-Select File Support**: Option to enable or disable multi-file selection for encryption/decryption.
- **Custom Decryption Path**: Choose to decrypt files to a temporary folder or their original path using a checkbox.
- **Safe Mode**: A feature that ensures all temporary files are securely deleted from the computer.
- **Full System Encryption Support**: Supports encryption and decryption of both local and external drives.

## Why SARM?

In an era of rampant data breaches, SARM ensures secure data management by preventing decrypted copies of files from being stored on any disk. It is designed to offer **real-time decryption** with **zero decrypted file storage**, ensuring sensitive files are never exposed.

With features like file encryption and comprehensive drive support, SARM serves users who require a robust, low-intervention solution for secure file management.

[![Image Preview](https://github.com/user-attachments/assets/6840fc61-0fbf-4573-9dbd-774a387543ba)](https://github.com/user-attachments/assets/6840fc61-0fbf-4573-9dbd-774a387543ba)

## Usage Guide

### Prerequisites

- **Operating System**: Windows
- **Python**: Ensure Python is installed on your system. You can download it from the [official Python website](https://www.python.org/downloads/).
- **Storage Devices**: Local or external

### Installation

1. **Clone the Repository**:
   Open a command prompt and run the following command to clone the repository:
   ```bash
   git clone https://github.com/junioralive/SARM.git
   ```

2. **Navigate to the Directory**:
   Change to the directory where the repository is cloned:
   ```bash
   cd SARM
   ```

3. **Install Required Packages**:
   Ensure you have `requirements.txt` in your repository. Run the following command to install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**:
   Execute the application using the following command:
   ```bash
   python sarm_app.py
   ```

### Admin Permissions

- **Admin Permissions Required**: Admin access is necessary for:
  - **Hiding and Unhiding Volumes**: This involves modifying system settings that require elevated privileges.
  - **Clearing Temporary Files**: Ensuring all temporary files, including system-level files, are securely deleted.

### Encrypting Files/Folders

1. **Drag and Drop**: Simply drag and drop files or folders into the SARM window to encrypt them.
2. **Single File/Folder Encryption**: Select a specific file or folder, then click **"Encrypt"** to initiate encryption. Encrypted files will be saved to the designated storage location.
3. **Multi-Select Encryption**: Enable the **multi-select option** to select multiple files or folders. Click **"Encrypt"** to encrypt all selected items at once.

Here's the updated decryption section with the details about the temporary folder option:

### Decrypting Files/Folders

1. **Single File/Folder Decryption**: Select a specific encrypted file or folder, then click **"Decrypt"** for real-time decryption, ensuring no decrypted files remain on disk. SARM will automatically remove the decrypted file after access.

2. **Multi-Select Decryption**: Enable the **multi-select option** to select multiple encrypted files or folders, then click **"Decrypt"** to decrypt all selected items at once.

3. **Temporary Folder Option**:
   - If the **Temp Folder checkbox** is ticked, files will be decrypted to a temporary folder.
   - If unticked, files will be decrypted to their original path when clicking the decrypt path button.

### Additional Options

- **Multi-Select File Support**: Enable or disable multi-file selection for encryption/decryption using the checkbox.
- **Temp Folder**: Choose whether to decrypt files to a temporary folder or their original path (Temp by default).
- **Safe Mode**: Enable to delete all temporary files for maximum security.

## Planned Features

- **Cross-Platform Support**: Expanding to **Linux** and **macOS**.

## How to Contribute

Contributions are welcome. To contribute:

1. **Fork the repository**.
2. **Create a new branch** for your feature.
3. **Make your changes** and test them.
4. **Submit a pull request** with a detailed description.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Contact

[![Discord Server](https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/cwDTVKyKJz)
[![GitHub Project](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/junioralive/box-stream)
[![Email](https://img.shields.io/badge/Email-D44638?style=for-the-badge&logo=gmail&logoColor=white)](mailto:support@junioralive.in)
