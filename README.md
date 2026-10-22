<div align="center">

# 🎃 Pumpkin Carver

**Enterprise-Grade Disk Imaging & Data Recovery Solution**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()

*A robust Python-based file carving and data recovery project designed to extract images, videos, and documents from corrupted or inaccessible storage volumes using file signature detection.*

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Project Architecture](#-project-architecture)
- [Environment Requirements & Setup](#-environment-requirements--setup)
- [FFmpeg Guidelines & Installation](#-ffmpeg-guidelines--installation)
- [Usage Guides](#-usage-guides)
  - [Option 1: Modular CLI Prototype](#option-1--modular-cli-prototype)
  - [Option 2: Integrated Graphical Application](#option-2--integrated-graphical-application)
- [Key Features](#-key-features)
- [Important Security & Best Practices](#-important-security--best-practices)
- [Project Goal](#-project-goal)
- [Licence](#-licence)

---

## 🎯 Overview

**Pumpkin Carver** is a digital forensic and data recovery solution designed to recover lost data from raw disk images (`.img`). By leveraging file signature detection and carving techniques, it can reconstruct images, videos, and documents even when the underlying filesystem or partition table is damaged.

The project provides two flexible workflows depending on your requirements:
1. **Modular CLI Tools:** Lightweight, role-specific scripts for granular control or automation.
2. **Integrated Graphical User Interface (GUI):** A unified application combining acquisition, extraction, and reporting.

---

## 📁 Project Architecture

```text
Pumpkin-Carver/
├── 📄 README.md
├── 📄 LICENSE
├── 📂 CLI_per_role_source_code/       # Command-line tools (CLI)
│   ├── 📜 Imager.py                  # Low-level disk acquisition module (Windows)
│   ├── 📜 Video_Carving_only.py      # Specialized video carving script
│   └── 📜 Image&Document_carving.py  # Image and document carving script
│
└── 📂 UI_AllInOne_source_code/        # Integrated graphical application (GUI)
    ├── 📜 pumpkin_carver_integrated.py    # Integrated Application v1
    └── 📜 pumpkin_carver_integrated_v2.py # Integrated Application v2 (Recommended)
```

---

## ⚙️ Environment Requirements & Setup

### System Prerequisites
| Component | Requirement | Notes |
| :--- | :--- | :--- |
| **Python** | 3.10 or newer | Required for all scripts and interfaces |
| **OS (Imager)** | Windows 10/11 | Required for low-level volume access in `Imager.py` |
| **OS (Carving)** | Cross-platform | Works on Windows, macOS, and Linux |
| **Storage Space** | Dedicated target drive | Sufficient space on a separate physical disk for images & outputs |

### Python Packages Installation

```bash
# For modular carving scripts (Image validation with Pillow)
python -m pip install Pillow

# For the integrated application (GUI + Utilities)
python -m pip install flet Pillow psutil
```

---

## 🎬 FFmpeg Guidelines & Installation

For optional video analysis, validation, and repair features, **FFmpeg** (including `ffprobe`) must be installed on your system and added to your system PATH.

### Installation Instructions by Operating System

#### 🪟 Windows
1. Download the official build from [ffmpeg.org](https://ffmpeg.org/download.html) (e.g., precompiled builds from gyan.dev as a `.zip`).
2. Extract the archive to a permanent folder (e.g., `C:\Program Files\ffmpeg`).
3. Add the `bin` directory to your System PATH:
   - Press `Win + R`, type `sysdm.cpl`, and hit Enter.
   - Go to the **Advanced** tab ➔ Click **Environment Variables**.
   - Under **System variables**, select `Path` ➔ Click **Edit**.
   - Click **New** and paste the path to the `bin` folder (e.g., `C:\Program Files\ffmpeg\bin`).
   - Click **OK** on all windows.
4. Verify installation in a new Command Prompt:
   ```cmd
   ffmpeg -version
   ffprobe -version
   ```

#### 🍎 macOS
```bash
# Using Homebrew (recommended)
brew install ffmpeg

# Verify installation
ffmpeg -version
ffprobe -version
```

#### 🐧 Linux (Debian / Ubuntu / RHEL / Arch)
```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y ffmpeg

# Fedora / RHEL
sudo dnf install ffmpeg

# Arch Linux
sudo pacman -S ffmpeg

# Verify installation
ffmpeg -version
```

---

## 🚀 Usage Guides

### Option 1 — Modular CLI Prototype

The modular version decouples disk imaging from file carving for granular control.

#### Step 1 — Acquire Disk Image (`Imager.py`)
```bash
cd CLI_per_role_source_code
python Imager.py
```
Follow the interactive prompts to:
1. Select the target source Windows volume.
2. Select an output directory located on a **different physical drive**.
3. Define the destination `.img` filename.
4. Monitor the acquisition progress (supports resuming interrupted acquisitions).

#### Step 2 — Carve Images and Documents
```bash
python "Image&Document_carving.py" "D:\Images\volume.img" -o "E:\Recovered\Images"
```
*Supported formats: JPG, PNG, GIF, BMP, and PDF.*

#### Step 3 — Carve Videos
```bash
python Video_Carving_only.py "D:\Images\volume.img" -o "E:\Recovered\Videos"
```
*Supported formats: MP4, MKV, MOV, AVI, and other media containers.*

> Both carving scripts support flags for parallel processing, output limits, and resuming interrupted runs.

---

### Option 2 — Integrated Graphical Application

The integrated application combines volume acquisition and file carving into a unified user interface.

```bash
cd UI_AllInOne_source_code

# Launch Version 2 (Recommended)
python pumpkin_carver_integrated_v2.py
```

#### Supported Workflows:
1. **Setup Carving:** Acquire a raw disk image of a selected volume.
2. **Full Carving:** Acquire a volume image and immediately carve selected file categories.
3. **Extraction from an existing image:** Carve files directly from a pre-existing `.img` file.

#### Execution Steps:
1. Launch the application and select your desired workflow.
2. Choose the source volume or existing `.img` file.
3. Configure target file categories, output directories, and recovery options.
4. Start execution and monitor live progress reports.
5. Review extracted files sorted automatically into category folders (Photos, Videos, Audio, Documents, Archives).

---

## ⚡ Key Features

- **Read-Only Source Access:** Ensures zero write operations on source media during imaging.
- **Signature-Based Carving:** Leverages headers and footers (magic bytes) to extract data without relying on filesystems.
- **Parallel Processing:** Multi-threaded engine for accelerated carving speed.
- **Deduplication & Integrity:** SHA-256 hash generation for duplicate filtering and integrity checks.
- **State Persistence:** Progress tracking with resume capabilities for interrupted tasks.
- **Reporting:** Structured recovery logging and reports for post-recovery auditing.
- **Deep Media Analysis:** Optional Pillow-based image verification and FFmpeg-driven video validation.

---

## 🛡️ Important Security & Best Practices

> [!WARNING]
> **Golden Rule of Data Recovery:**
> **NEVER** write or save recovered files onto the affected source volume/drive. Always use a separate physical disk as the output destination to prevent overwriting unrecovered data.

- **Work on Images:** Always acquire a raw disk image (`.img`) first and execute carving against the image rather than interacting directly with failing hardware.
- **Carving Limitations:** Carving effectiveness depends on file fragmentation and sector continuity. Files that are highly fragmented or partially overwritten may be unrecoverable or corrupted.
- **Forensic Disclaimer:** This software is designed for personal data recovery and technical analysis; it is not a certified judicial forensic tool.

---

## 🎯 Project Goal

Pumpkin Carver evolved from a modular proof of concept into an integrated recovery application, with a focus on simplifying file carving and improving processing performance.

The objective is to provide a practical, transparent Python-based alternative for recovering valuable digital files when conventional filesystem access is no longer viable.

**Recover data. Preserve integrity. Keep carving. 🎃**

---

## 📄 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

<div align="center">
  <sub>Pumpkin Carver — Data Recovery Project</sub>
</div>
