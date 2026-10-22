#!/usr/bin/env python3
"""
Windows Volume Imager

Creates a read-only image of a selected Windows logical volume.
Supports resumable imaging, configurable output paths, retry handling,
and atomic progress-state updates.

Requirements:
    - Windows
    - Python 3.10+
    - Administrator privileges may be required

Important:
    - The source is opened for reading only.
    - Store the image on a different physical device.
    - This images a logical volume, not necessarily the entire physical disk.
"""

from __future__ import annotations

import ctypes
import json
import os
import shutil
import sys
import time

from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


# ============================================================
# Configuration
# ============================================================

@dataclass(frozen=True, slots=True)
class ImagerConfig:
    """Runtime configuration for the imaging operation."""

    chunk_size: int = 8 * 1024 * 1024
    max_retries: int = 3
    retry_delay_seconds: float = 1.5
    checkpoint_interval: int = 128 * 1024 * 1024
    minimum_free_space_bytes: int = 100 * 1024 * 1024

    default_output_directory: Path = (
        Path.home() / "Downloads" / "VolumeImages"
    )


CONFIG = ImagerConfig()


# ============================================================
# Windows API
# ============================================================

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_OVERLAPPED = 0x40000000
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
ERROR_IO_PENDING = 997

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

CreateFileW = kernel32.CreateFileW
CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
CreateFileW.restype = wintypes.HANDLE

DeviceIoControl = kernel32.DeviceIoControl
DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
DeviceIoControl.restype = wintypes.BOOL

ReadFile = kernel32.ReadFile
ReadFile.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID,
]
ReadFile.restype = wintypes.BOOL

GetOverlappedResult = kernel32.GetOverlappedResult
GetOverlappedResult.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.BOOL,
]
GetOverlappedResult.restype = wintypes.BOOL

CreateEventW = kernel32.CreateEventW
CreateEventW.argtypes = [
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.BOOL,
    wintypes.LPCWSTR,
]
CreateEventW.restype = wintypes.HANDLE

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

GetLogicalDrives = kernel32.GetLogicalDrives
GetLogicalDrives.argtypes = []
GetLogicalDrives.restype = wintypes.DWORD

GetVolumeInformationW = kernel32.GetVolumeInformationW
GetVolumeInformationW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR,
    wintypes.DWORD,
]
GetVolumeInformationW.restype = wintypes.BOOL


# ============================================================
# Exceptions and data models
# ============================================================

class ImagingError(RuntimeError):
    """Raised when the imaging operation cannot safely continue."""


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    """Identifies a logical volume and its reported size."""

    drive: str
    size_bytes: int
    serial_number: int | None


@dataclass(frozen=True, slots=True)
class ImagePaths:
    """Paths associated with an image and its progress state."""

    image: Path
    state: Path


@dataclass(frozen=True, slots=True)
class ResumeState:
    """Persisted state required to resume an imaging operation."""

    drive: str
    total_bytes: int
    chunk_size: int
    serial_number: int | None
    completed_bytes: int


# ============================================================
# Formatting and input
# ============================================================

def format_bytes(value: int) -> str:
    """Format a byte count as a human-readable binary unit."""

    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(value)

    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024

    return f"{size:.2f} TiB"


def prompt_path(message: str, default: Path) -> Path:
    """Prompt for a filesystem path with a default value."""

    value = input(f"{message} [{default}]: ").strip()
    return Path(value.strip('"')).expanduser() if value else default


def prompt_drive() -> str:
    """Display available drive letters and request a source volume."""

    if os.name != "nt":
        raise ImagingError("This program requires Windows.")

    drive_mask = GetLogicalDrives()

    available = [
        f"{chr(65 + index)}:"
        for index in range(26)
        if drive_mask & (1 << index)
    ]

    print("\nAvailable logical drives:")
    for drive in available:
        print(f"  {drive}")

    while True:
        value = input("\nSource drive letter: ").strip().upper()

        if len(value) == 1:
            value += ":"

        if value in available:
            return value

        print("Invalid selection. Choose an available drive letter.")


def prompt_output_paths(drive: str) -> ImagePaths:
    """Request the output directory and image filename."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_name = f"volume_{drive[0]}_{timestamp}.img"

    output_directory = prompt_path(
        "Output directory",
        CONFIG.default_output_directory,
    )

    output_directory.mkdir(parents=True, exist_ok=True)

    default_image_path = output_directory / default_name
    requested_path = prompt_path(
        "Image filename or path",
        default_image_path,
    )

    if requested_path.is_absolute():
        image_path = requested_path
    else:
        image_path = output_directory / requested_path

    if image_path.suffix.lower() != ".img":
        image_path = image_path.with_suffix(".img")

    if image_path.name in ("", ".", ".."):
        raise ImagingError("Invalid image filename.")

    state_path = image_path.with_suffix(
        image_path.suffix + ".progress.json"
    )

    return ImagePaths(image=image_path, state=state_path)


# ============================================================
# Source volume access
# ============================================================

def windows_error(message: str) -> OSError:
    """Create an OSError using the most recent Windows error code."""

    code = ctypes.get_last_error()
    return OSError(code, f"{message}: {ctypes.FormatError(code).strip()}")


def open_volume(drive: str, overlapped: bool = False) -> int:
    """Open a logical volume with read-only access."""

    flags = FILE_ATTRIBUTE_NORMAL

    if overlapped:
        flags |= FILE_FLAG_OVERLAPPED

    handle = CreateFileW(
        rf"\\.\{drive}",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        flags,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        raise windows_error(f"Unable to open source volume {drive}")

    return handle


def get_volume_size(handle: int) -> int:
    """Retrieve the reported size of an opened volume."""

    length = ctypes.c_longlong()
    returned = wintypes.DWORD()

    success = DeviceIoControl(
        handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        None,
        0,
        ctypes.byref(length),
        ctypes.sizeof(length),
        ctypes.byref(returned),
        None,
    )

    if not success:
        raise windows_error("Unable to determine volume size")

    if length.value <= 0:
        raise ImagingError("The volume reported an invalid size.")

    return length.value


def get_volume_serial(drive: str) -> int | None:
    """Retrieve the filesystem volume serial number when available."""

    serial = wintypes.DWORD()
    maximum_component_length = wintypes.DWORD()
    filesystem_flags = wintypes.DWORD()

    volume_name = ctypes.create_unicode_buffer(261)
    filesystem_name = ctypes.create_unicode_buffer(261)

    success = GetVolumeInformationW(
        f"{drive}\\",
        volume_name,
        len(volume_name),
        ctypes.byref(serial),
        ctypes.byref(maximum_component_length),
        ctypes.byref(filesystem_flags),
        filesystem_name,
        len(filesystem_name),
    )

    return serial.value if success else None


def inspect_volume(drive: str) -> VolumeInfo:
    """Inspect the source volume and return its identifying information."""

    handle = open_volume(drive)

    try:
        size_bytes = get_volume_size(handle)
    finally:
        CloseHandle(handle)

    return VolumeInfo(
        drive=drive,
        size_bytes=size_bytes,
        serial_number=get_volume_serial(drive),
    )


# ============================================================
# Offset-based asynchronous reads
# ============================================================

class OVERLAPPED(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """Windows OVERLAPPED structure for explicit-offset reads."""

    _fields_ = [
        ("internal", ctypes.c_size_t),
        ("internal_high", ctypes.c_size_t),
        ("offset", wintypes.DWORD),
        ("offset_high", wintypes.DWORD),
        ("h_event", wintypes.HANDLE),
    ]


def read_at(handle: int, offset: int, size: int) -> bytes:
    """Read exactly one requested chunk at a specific byte offset."""

    event = CreateEventW(None, True, False, None)

    if not event:
        raise windows_error("Unable to create read event")

    overlapped = OVERLAPPED(
        0,
        0,
        offset & 0xFFFFFFFF,
        (offset >> 32) & 0xFFFFFFFF,
        event,
    )
    buffer = ctypes.create_string_buffer(size)
    bytes_read = wintypes.DWORD()

    try:
        success = ReadFile(
            handle,
            buffer,
            size,
            ctypes.byref(bytes_read),
            ctypes.byref(overlapped),
        )

        if not success:
            error_code = ctypes.get_last_error()

            if error_code != ERROR_IO_PENDING:
                raise OSError(
                    error_code,
                    f"Read failed at offset {offset}: "
                    f"{ctypes.FormatError(error_code).strip()}",
                )

            if not GetOverlappedResult(
                handle,
                ctypes.byref(overlapped),
                ctypes.byref(bytes_read),
                True,
            ):
                raise windows_error(f"Read failed at offset {offset}")

        if bytes_read.value != size:
            raise OSError(
                f"Short read at offset {offset}: "
                f"expected {size} bytes, received {bytes_read.value}"
            )

        return buffer.raw[:bytes_read.value]

    finally:
        CloseHandle(event)


# ============================================================
# Progress persistence and resume validation
# ============================================================

def save_state(paths: ImagePaths, state: ResumeState) -> None:
    """Persist progress using a temporary file and atomic replacement."""

    temporary_path = paths.state.with_name(
        paths.state.name + ".tmp"
    )

    payload = {
        "version": 1,
        "drive": state.drive,
        "total_bytes": state.total_bytes,
        "chunk_size": state.chunk_size,
        "serial_number": state.serial_number,
        "completed_bytes": state.completed_bytes,
    }

    try:
        with temporary_path.open("w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, paths.state)

    finally:
        if temporary_path.exists():
            temporary_path.unlink()


def load_state(paths: ImagePaths) -> ResumeState:
    """Load and validate the saved progress metadata."""

    try:
        payload: Any = json.loads(
            paths.state.read_text(encoding="utf-8")
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ImagingError(
            f"Unable to load progress metadata: {exc}"
        ) from exc

    if not isinstance(payload, dict):
        raise ImagingError("Progress metadata must contain a JSON object.")

    if payload.get("version") != 1:
        raise ImagingError("Unsupported progress file version.")

    try:
        serial = payload.get("serial_number")
        state = ResumeState(
            drive=str(payload["drive"]),
            total_bytes=int(payload["total_bytes"]),
            chunk_size=int(payload["chunk_size"]),
            serial_number=None if serial is None else int(serial),
            completed_bytes=int(payload["completed_bytes"]),
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise ImagingError(
            f"Invalid progress metadata fields: {exc}"
        ) from exc

    if (
        state.total_bytes <= 0
        or state.chunk_size <= 0
        or state.completed_bytes < 0
        or state.completed_bytes > state.total_bytes
        or state.completed_bytes % state.chunk_size != 0
    ):
        raise ImagingError("Progress metadata contains invalid offsets.")

    return state


def initialize_or_resume(
    paths: ImagePaths,
    volume: VolumeInfo,
) -> int:
    """Initialize a new image or validate a previous imaging session."""

    image_exists = paths.image.exists()
    state_exists = paths.state.exists()

    if image_exists != state_exists:
        raise ImagingError(
            "The image and progress file must both exist or both be absent. "
            "No automatic recovery will be attempted."
        )

    if not image_exists:
        free_space = shutil.disk_usage(paths.image.parent).free
        required_space = (
            volume.size_bytes + CONFIG.minimum_free_space_bytes
        )

        if free_space < required_space:
            raise ImagingError(
                f"Insufficient destination space. "
                f"Required: {format_bytes(required_space)}; "
                f"available: {format_bytes(free_space)}."
            )

        # Exclusive creation prevents overwriting an existing image.
        with paths.image.open("xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())

        state = ResumeState(
            drive=volume.drive,
            total_bytes=volume.size_bytes,
            chunk_size=CONFIG.chunk_size,
            serial_number=volume.serial_number,
            completed_bytes=0,
        )

        save_state(paths, state)
        return 0

    state = load_state(paths)

    if (
        state.drive != volume.drive
        or state.total_bytes != volume.size_bytes
        or state.chunk_size != CONFIG.chunk_size
        or state.serial_number != volume.serial_number
    ):
        raise ImagingError(
            "The saved session does not match the current source "
            "or imaging configuration. Refusing to resume."
        )

    image_size = paths.image.stat().st_size

    if image_size < state.completed_bytes:
        raise ImagingError(
            "The image is shorter than the last committed checkpoint."
        )

    # Bytes beyond the saved checkpoint may not have been committed.
    # The imaging loop will truncate them before continuing.
    print(f"Existing image: {format_bytes(image_size)}")
    print(f"Committed data: {format_bytes(state.completed_bytes)}")

    return state.completed_bytes


# ============================================================
# Imaging engine
# ============================================================

def write_all(stream: Any, data: bytes) -> None:
    """Write all bytes or raise an error if progress cannot continue."""

    remaining = memoryview(data)

    while remaining:
        written = stream.write(remaining)

        if written is None or written <= 0:
            raise OSError("Unable to write image data.")

        remaining = remaining[written:]


def image_volume(
    volume: VolumeInfo,
    paths: ImagePaths,
) -> None:
    """Create or resume a volume image."""

    completed = initialize_or_resume(paths, volume)

    if completed == volume.size_bytes:
        print("The image is already complete.")
        return

    print(f"\nSource volume : {volume.drive}")
    print(f"Source size   : {format_bytes(volume.size_bytes)}")
    print(f"Image path    : {paths.image}")
    print(f"Resume offset : {format_bytes(completed)}")

    if input("\nType YES to continue: ").strip() != "YES":
        print("Operation cancelled.")
        return

    handle = None
    next_checkpoint = (
        completed // CONFIG.checkpoint_interval + 1
    ) * CONFIG.checkpoint_interval

    try:
        with paths.image.open("r+b", buffering=0) as output:
            output.truncate(completed)
            output.seek(completed)

            while completed < volume.size_bytes:
                requested_size = min(
                    CONFIG.chunk_size,
                    volume.size_bytes - completed,
                )

                data = None
                last_error = None

                for attempt in range(1, CONFIG.max_retries + 1):
                    if handle is not None:
                        CloseHandle(handle)
                        handle = None

                    try:
                        check_handle = open_volume(volume.drive)

                        try:
                            current_size = get_volume_size(check_handle)
                        finally:
                            CloseHandle(check_handle)

                        if current_size != volume.size_bytes:
                            raise ImagingError(
                                "The source volume size has changed."
                            )

                        handle = open_volume(
                            volume.drive,
                            overlapped=True,
                        )

                        data = read_at(
                            handle,
                            completed,
                            requested_size,
                        )
                        break

                    except (OSError, ImagingError, ValueError, ctypes.ArgumentError) as exc:
                        last_error = exc
                        print(
                            f"\nRead error at {format_bytes(completed)} "
                            f"(attempt {attempt}/{CONFIG.max_retries}): "
                            f"{exc}"
                        )

                        if handle is not None:
                            CloseHandle(handle)
                            handle = None

                        if attempt < CONFIG.max_retries:
                            time.sleep(CONFIG.retry_delay_seconds)

                if data is None:
                    output.flush()
                    os.fsync(output.fileno())

                    save_state(
                        paths,
                        ResumeState(
                            drive=volume.drive,
                            total_bytes=volume.size_bytes,
                            chunk_size=CONFIG.chunk_size,
                            serial_number=volume.serial_number,
                            completed_bytes=completed,
                        ),
                    )

                    raise ImagingError(
                        f"Maximum read retries exceeded at "
                        f"{format_bytes(completed)}. "
                        f"Resume the operation after checking the source. "
                        f"Last error: {last_error}"
                    )

                write_all(output, data)
                completed += len(data)

                if (
                    completed >= next_checkpoint
                    or completed == volume.size_bytes
                ):
                    output.flush()
                    os.fsync(output.fileno())

                    save_state(
                        paths,
                        ResumeState(
                            drive=volume.drive,
                            total_bytes=volume.size_bytes,
                            chunk_size=CONFIG.chunk_size,
                            serial_number=volume.serial_number,
                            completed_bytes=completed,
                        ),
                    )

                    percentage = (
                        100.0 * completed / volume.size_bytes
                    )

                    print(
                        f"\rProgress: {percentage:6.2f}% | "
                        f"{format_bytes(completed)} / "
                        f"{format_bytes(volume.size_bytes)}",
                        end="",
                        flush=True,
                    )

                    next_checkpoint = (
                        completed // CONFIG.checkpoint_interval + 1
                    ) * CONFIG.checkpoint_interval

        print(f"\n\nImage completed successfully: {paths.image}")

    finally:
        if handle is not None:
            CloseHandle(handle)


# ============================================================
# Application entry point
# ============================================================

def main() -> int:
    """Run the interactive imaging application."""

    if os.name != "nt":
        print("Error: this application requires Windows.")
        return 1

    try:
        drive = prompt_drive()
        paths = prompt_output_paths(drive)

        source_drive = f"{drive[0]}:\\"
        destination_root = paths.image.parent.resolve()

        # Prevent writing the image onto the selected source volume.
        if destination_root.drive.upper() == source_drive[:2].upper():
            raise ImagingError(
                "The destination is on the selected source volume. "
                "Choose a different destination drive."
            )

        volume = inspect_volume(drive)

        print("\nVolume information")
        print("------------------")
        print(f"Drive         : {volume.drive}")
        print(f"Size          : {format_bytes(volume.size_bytes)}")
        print(f"Volume serial : {volume.serial_number}")
        print(f"Image         : {paths.image}")
        print(f"Progress file : {paths.state}")

        image_volume(volume, paths)
        return 0

    except (ImagingError, OSError, ValueError) as exc:
        print(f"\nImaging failed: {exc}")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user. Saved progress can be used to resume.")
        sys.exit(130)
