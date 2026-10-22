🎃 Pumpkin Carver

Python-based file carving and data recovery for corrupted or inaccessible storage volumes.

Pumpkin Carver is a data recovery project designed to extract images, videos, and documents from disk images using file signature detection and carving techniques.

The project contains two implementations: an original modular prototype and an integrated application with a graphical interface.

📁 Project Structure

Pumpkin-Carver/
├── CLI_per_role_source_code/
│   ├── Imager.py
│   ├── Video_Carving_only.py
│   └── Image&Document_carving.py
│
├── UI_AllInOne_source_code/
│   ├── pumpkin_carver_integrated.py
│   └── pumpkin_carver_integrated_v2.py
│
└── README.md


⚙️ Requirements & Environment Setup

1. Python Requirements

Python 3.10 or newer installed and added to your system PATH.

Windows is required for Imager.py (due to Windows volume access APIs). Other carving scripts are cross-platform.

Sufficient disk space for creating disk images and storing recovered files.

2. Python Packages Installation

Install the required packages depending on your use case:

For modular carving scripts (Pillow for image validation):

python -m pip install Pillow


For the integrated application (flet, Pillow, psutil):

python -m pip install flet Pillow psutil


🎬 FFmpeg Guidelines & Installation

For optional video analysis, validation, and repair features, FFmpeg (including ffprobe) must be installed on your system and accessible via your system PATH.

Installation Instructions by Operating System

🪟 Windows

Download FFmpeg: Download the official build from ffmpeg.org (e.g., precompiled builds from gyan.dev as a .zip).

Extract: Extract the downloaded archive to a permanent folder on your system (e.g., C:\ffmpeg or C:\Program Files\ffmpeg).

Add to System PATH:

Press the Windows Key and type Environment Variables, then select Edit the system environment variables.

Click the Environment Variables... button.

Under System variables, find and select the variable named Path, then click Edit.

Click New and add the path to the bin folder inside your FFmpeg directory (e.g., C:\ffmpeg\bin).

Click OK on all windows to save changes.

Verify Installation: Open a new Command Prompt or PowerShell window and run:

ffmpeg -version
ffprobe -version


🍎 macOS

Using Homebrew (recommended):

brew install ffmpeg


Verify Installation: Open Terminal and run:

ffmpeg -version
ffprobe -version


🐧 Linux (Ubuntu / Debian / Fedora / Arch)

Ubuntu / Debian:

sudo apt update
sudo apt install ffmpeg


Fedora:

sudo dnf install ffmpeg


Arch Linux:

sudo pacman -S ffmpeg


Verify Installation: Run:

ffmpeg -version
ffprobe -version


🚀 Option 1 — Run the Modular Prototype

The modular version separates disk imaging from file recovery.

Step 1 — Create a disk image

Open a terminal in the project directory and run:

cd CLI_per_role_source_code
python Imager.py


Follow the prompts to select the source Windows volume, choose an output directory on a different physical drive, specify the .img filename, and wait for completion. (Supports progress tracking and resume).

Step 2 — Recover images and documents

python "Image&Document_carving.py" "D:\Images\volume.img" -o "E:\Recovered\Images"


(Supports JPG, PNG, GIF, BMP, and PDF carving).

Step 3 — Recover videos

python Video_Carving_only.py "D:\Images\volume.img" -o "E:\Recovered\Videos"


(Supports MP4, MKV, MOV, AVI, and other media formats).

🖥️ Option 2 — Run the Integrated Application

Step 1 — Navigate to the integrated directory

cd UI_AllInOne_source_code


Step 2 — Launch the application

Version 1:

python pumpkin_carver_integrated.py


Version 2:

python pumpkin_carver_integrated_v2.py


Step 3 — Select a recovery workflow & execute

Choose from Setup Carving, Full Carving, or Extraction from an existing image.

Select source volume/image, output directory, and file categories.

Start operation, monitor progress, and review generated recovery reports.

⚡ Features

Disk imaging with read-only source access

File carving based on file signatures

Image, video, and document recovery

Integrated graphical interface (Flet)

Parallel processing for carving

SHA-256 hashing and duplicate detection

Recovery progress tracking and resume support

Recovery reports in supported implementations

Optional image validation and FFmpeg-powered video analysis

🛡️ Important Notes

Never save recovered files onto the affected source drive.

Whenever possible, work from a disk image rather than repeatedly accessing a damaged device.

File carving cannot guarantee complete recovery when data is overwritten or fragmented.

This project is not a certified forensic tool for judicial use.

🎯 Project Goal

Pumpkin Carver evolved from a modular proof of concept into an integrated recovery application, simplifying file carving and improving processing performance.

Recover data. Preserve integrity. Keep carving. 🎃

📄 Licence

Ce projet est sous licence MIT - voir le fichier LICENSE pour plus de détails.
