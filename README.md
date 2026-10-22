# 🎃 Pumpkin Carver

**Python-based file carving and data recovery for corrupted or inaccessible storage volumes.**

Pumpkin Carver is a data recovery project designed to extract images, videos, and documents from disk images using file signature detection and carving techniques.

The project contains two implementations: an original modular prototype and an integrated application with a graphical interface.

## 📁 Project Structure

```text
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
```

## ⚙️ Requirements

- Python 3.10 or newer
- Windows for `Imager.py`
- Python packages: `flet`, with `Pillow` and `psutil` optional for additional features in the integrated application
- Sufficient disk space for disk images and recovered files

For the modular carving scripts, install Pillow to enable image validation and additional image-processing features:

```bash
python -m pip install Pillow
```

For the integrated application:

```bash
python -m pip install flet Pillow psutil
```

For optional video analysis and repair, install FFmpeg, including `ffprobe`, and ensure both executables are available on your system PATH.

## 🚀 Option 1 — Run the Modular Prototype

The modular version separates disk imaging from file recovery.

### Step 1 — Create a disk image

Open a terminal in the project directory and run:

```bash
cd CLI_per_role_source_code
python Imager.py
```

Follow the prompts to:

1. Select the source Windows volume.
2. Choose an output directory on a different physical drive.
3. Specify the `.img` filename.
4. Wait for the imaging process to finish.

The imager supports progress tracking and resuming interrupted acquisitions.

### Step 2 — Recover images and documents

Run the carving script with your disk image and a recovery destination:

```bash
python "Image&Document_carving.py" "D:\Images\volume.img" -o "E:\Recovered\Images"
```

Replace the example paths with your actual disk image and recovery destination.

This script supports JPG, PNG, GIF, BMP, and PDF carving.

### Step 3 — Recover videos

Run:

```bash
python Video_Carving_only.py "D:\Images\volume.img" -o "E:\Recovered\Videos"
```

The script targets supported video formats, including MP4, MKV, MOV, and AVI, alongside the media formats defined in its implementation.

Both carving scripts support options for parallel processing, output limits, and resuming interrupted recovery runs.

## 🖥️ Option 2 — Run the Integrated Application

The integrated version combines imaging and file carving in a graphical application.

### Step 1 — Navigate to the integrated directory

```bash
cd UI_AllInOne_source_code
```

### Step 2 — Launch the application

**Version 1**

```bash
python pumpkin_carver_integrated.py
```

**Version 2**

```bash
python pumpkin_carver_integrated_v2.py
```

Choose either version to launch its graphical interface.

### Step 3 — Select a recovery workflow

The integrated application provides three main workflows:

- **Setup Carving:** Create a disk image of a selected volume.
- **Full Carving:** Image a volume and then carve the selected file categories.
- **Extraction from an existing image:** Recover files directly from an existing disk image without acquiring the volume again.

### Step 4 — Configure and start recovery

1. Select the desired workflow.
2. Choose the source volume or existing disk image.
3. Select the output directory and file categories.
4. Configure recovery options as needed.
5. Start the operation and monitor the progress.
6. Review the extracted files and generated recovery reports.

Recovered files are organized into category folders, including photos, videos, audio, documents, and archives.

## ⚡ Features

- Disk imaging with read-only source access
- File carving based on file signatures
- Image, video, and document recovery
- Integrated graphical interface
- Parallel processing for carving
- SHA-256 hashing and duplicate detection
- Recovery progress tracking and resume support
- Recovery reports in supported implementations
- Optional image validation and video analysis

## 🛡️ Important Notes

- **Never save recovered files onto the affected source drive.**
- Whenever possible, work from a disk image rather than repeatedly accessing a damaged device.
- File carving cannot guarantee complete recovery, especially when data has been overwritten or files are fragmented.
- A recovered file may be incomplete or corrupted even if it has been extracted successfully.
- This project is not a certified forensic tool for judicial use.

## 🎯 Project Goal

Pumpkin Carver evolved from a modular proof of concept into an integrated recovery application, with a focus on simplifying file carving and improving processing performance.

The objective is to provide a practical Python-based alternative for recovering valuable digital files when conventional filesystem access is no longer sufficient.

**Recover data. Preserve integrity. Keep carving. 🎃**
