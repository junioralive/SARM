# SARM

## Project Overview

**SARM** is a robust encryption and partition management tool designed to provide real-time protection for sensitive files stored on external drives. The application focuses on **AES-GCM encryption** to ensure files remain secure, with real-time decryption allowing seamless access. It allows users to **hide** and **unhide** a specific drive partition ("Alive") to further protect confidential data. Currently available for **Windows**, SARM is in its **beta phase**, with plans to evolve into a **cross-platform** solution and introduce web-based access.

This project aims to address key privacy and security challenges by ensuring no decrypted copies of files are stored after access, making it ideal for users handling highly sensitive data. All encryption and decryption processes occur in **real-time**, preserving data confidentiality while providing secure and transparent access.

## Features

- **Real-time Encryption & Decryption**: Encrypt files and folders upon storage, decrypt them in real-time when accessed, without leaving decrypted copies behind.
- **Partition Hiding & Unhiding**: Protect the partition by hiding it when not in use, preventing unauthorized access.
- **AES-GCM Encryption**: Uses advanced encryption standards for securing data and ensuring file integrity.
- **Argon2 Key Derivation**: Ensures strong and secure password protection using Argon2i, a leading password-hashing algorithm.
- **Drag-and-Drop File Encryption**: Easily encrypt files and entire folders with preserved structure through a simple drag-and-drop interface.
- **Minimalistic Dark-Themed UI**: Features a clean, modern interface with hidden logs, enabling a focused user experience.
- **Temporary File Cleanup**: Automatically removes all temporary files, ensuring no data traces are left behind.
- **Cross-Platform Support** (Planned): While currently limited to Windows, SARM is designed with future cross-platform compatibility (macOS, Linux) in mind.
- **Samba Server Integration** (Planned): A one-click solution to deploy a Samba server that will allow secure web-based access to your encrypted drive.

## Why SARM?

In a digital world where data breaches are increasingly common, secure data storage has become more crucial than ever. Traditional encryption tools often fall short by leaving decrypted versions of files on disk, posing potential privacy risks. **SARM** was developed to address this issue with a clear focus on **real-time decryption** and **zero decrypted file storage**, ensuring that sensitive files are never left exposed, even temporarily.

SARM provides a solution for users who need both **file encryption** and **partition security** with minimal intervention. Its ability to hide and unhide partitions, along with robust encryption, makes it a powerful tool for secure file management.

## Usage Guide

### Prerequisites

- **Windows** OS
- **Python 3.x** installed with all dependencies listed in the `requirements.txt` file
- An **external drive** partitioned as "Alive" (details below)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/SARM.git
   cd SARM
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python sarm.py
   ```

### Creating the "Alive" Partition

SARM operates on an external drive partition named **"Alive"**. Here’s how to set it up:

1. **Create a new partition** using Windows Disk Management:
   - Open Disk Management (search for it in the Start menu).
   - Right-click on unallocated space, select "New Simple Volume", and follow the prompts.
   - Format the partition as **exFAT** for future cross-platform compatibility.
   - Assign a drive letter, preferably **P:**, to this partition.
   - Rename the partition to **"Alive"**.

Alternatively, you can use the following command line instructions:

```bash
diskpart
select disk 1  # Select the external disk
create partition primary
format fs=exfat quick
assign letter=P
```

### Hiding the Partition

To hide the "Alive" partition (and its contents), use the batch script provided by SARM:

```bash
SARM> toggle_alive.bat hide
```

This will remove the drive letter from the partition, effectively hiding it from the operating system.

### Unhiding the Partition

To access the hidden partition and its encrypted contents, run:

```bash
SARM> toggle_alive.bat unhide
```

This will reassign the drive letter **P:** to the partition, making it accessible.

### Encrypting Files/Folders

1. **Drag and drop** the files or folders into the SARM window.
2. Click **"Encrypt"** to start encrypting your files. The encrypted files will be saved to the "Alive" partition.

### Decrypting Files

1. Select the encrypted file you want to access.
2. Click **"Decrypt"**, and the file will be decrypted and opened in real-time, without leaving a decrypted copy on disk.
3. Once you are done, the decrypted file will be automatically removed.

### Cleaning Temporary Files

If needed, you can manually clear all temporary files by clicking the **"Clear Temp"** button in the application. This ensures that no decrypted data remains after use.

## Planned Features

SARM is still in its beta phase, and several features are planned for future versions:

- **Cross-Platform Support**: Expanding to **Linux** and **macOS** to ensure full compatibility across different operating systems.
- **Executable Version**: While this version does not include an executable for easier distribution (to keep the tool discreet), future versions will feature a user-friendly executable release.
- **One-Click Samba Server**: A key future feature will be the ability to set up a **Samba server** with one click, allowing users to share the "Alive" partition over the web. All decryption will occur in real-time, ensuring the security of data during access.
- **Enhanced UI & Features**: Continuing to refine the user interface and add more comprehensive feedback for users, such as detailed progress logs and status notifications.

## Why SARM is Powerful

SARM is built to address key challenges of secure file management in the modern era:

1. **Real-Time Decryption**: No decrypted copies are ever stored on disk, drastically reducing the risk of unauthorized access.
2. **Partition Hiding**: By hiding the entire partition, sensitive data is kept entirely out of view.
3. **Robust Encryption Standards**: Utilizing AES-GCM and Argon2i for state-of-the-art encryption and password protection, SARM provides security that is resistant to brute force and tampering.
4. **Future Web Integration**: Planned integration with Samba will make the "Alive" partition accessible online, with real-time decryption, ensuring data privacy even during remote access.

## How to Contribute

Contributions to SARM are highly encouraged. To contribute:

1. **Fork the repository**.
2. **Create a new branch** for your feature.
3. **Make your changes** and test thoroughly.
4. **Submit a pull request** with a detailed description of your changes and why they should be merged.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for more details.
