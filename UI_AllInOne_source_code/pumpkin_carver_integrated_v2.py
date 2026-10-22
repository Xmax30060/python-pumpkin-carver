#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pumpkin Carver — fichier unique (interface Flet + moteur de récupération).

Parcours intégrés :
  * Setup Carving : acquisition d'une image d'un volume (lecture seule, reprise automatique,
    attente de réinsertion si le support se déconnecte).
  * Full Carving  : acquisition de l'image puis carving des types choisis.
  * Extraction depuis une image : carving d'une image disque existante.

Les fichiers récupérés sont rangés par catégorie (Photos, Vidéos, Audio, Documents, Archives).
La source n'est jamais écrite. Dépendances : flet (requis) ; Pillow, psutil, ffmpeg/ffprobe et Hyperscan facultatifs.
Ce logiciel n'est pas un outil forensique certifié pour un usage judiciaire.
"""
from __future__ import annotations

import argparse
import asyncio
import bisect
import csv
import hashlib
import html
import importlib
import json
import multiprocessing as mp
import os
import queue
import re
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from typing import Callable, cast

try:
    # Chargement dynamique : Hyperscan reste facultatif et Pylance ne signale pas
    # un import manquant lorsque le paquet n’est pas installé dans cet environnement.
    _hyperscan = importlib.import_module("hyperscan")
except (ImportError, OSError):
    _hyperscan = None
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import flet as ft

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #

APP_NAME = "Pumpkin Carver"
APP_ICON = "🎃"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "config.json"
DEFAULT_CONFIG = {"first_time": True, "username": "Utilisateur", "theme": "dark", "langue": "fr"}

MIB = 1024 * 1024
GIB = 1024 * MIB
CHUNK_ACQ = 8 * MIB
VIDEO_BIG = 500 * MIB
_WIN = os.name == "nt"

CATEGORIES_EXTENSIONS = {
    "Images": ["jpg", "png", "gif", "bmp", "tif", "webp"],
    "Vidéos": ["mp4", "mkv", "mov", "avi"],
    "Audio": ["mp3", "wav", "flac", "ogg", "m4a"],
    "Documents": ["pdf", "doc"],
    "Archives": ["zip", "rar", "7z"],
}
FOLDER_FOR = {
    "jpg": "Photos", "png": "Photos", "gif": "Photos", "bmp": "Photos", "tif": "Photos", "webp": "Photos",
    "mp4": "Vidéos", "mkv": "Vidéos", "mov": "Vidéos", "avi": "Vidéos",
    "mp3": "Audio", "wav": "Audio", "flac": "Audio", "ogg": "Audio", "m4a": "Audio",
    "pdf": "Documents", "doc": "Documents",
    "zip": "Archives", "rar": "Archives", "7z": "Archives",
}
IMAGE_EXTS = {"jpg", "png", "gif", "bmp", "tif", "webp"}
VIDEO_EXTS = {"mp4", "mkv", "mov", "avi"}
ALL_EXTS = set(FOLDER_FOR)

MP4_BRANDS = (b"ftypisom", b"ftypiso2", b"ftypiso5", b"ftypmp41", b"ftypmp42",
              b"ftypavc1", b"ftypM4V ", b"ftypdash", b"ftypMSNV")
# (extension, signature, recul) — recul = octets à remonter avant la signature trouvée.
SIGNATURES = (
    ("jpg", b"\xff\xd8\xff", 0),
    ("png", b"\x89PNG\r\n\x1a\n", 0),
    ("pdf", b"%PDF-", 0),
    ("gif", b"GIF87a", 0),
    ("gif", b"GIF89a", 0),
    ("bmp", b"BM", 0),
    ("tif", b"II*\x00", 0),
    ("tif", b"MM\x00*", 0),
    ("webp", b"WEBP", 8),
    ("avi", b"AVI ", 8),
    ("wav", b"WAVE", 8),
    ("mkv", b"\x1a\x45\xdf\xa3", 0),
    *[("mp4", b, 4) for b in MP4_BRANDS],
    ("m4a", b"ftypM4A ", 4),
    ("mov", b"ftypqt  ", 4),
    ("mp3", b"ID3", 0),
    ("flac", b"fLaC", 0),
    ("ogg", b"OggS", 0),
    ("doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0),
    ("zip", b"PK\x03\x04", 0),
    ("rar", b"Rar!\x1a\x07", 0),
    ("7z", b"7z\xbc\xaf\x27\x1c", 0),
)
RIFF_SUBTYPE = {"avi": b"AVI ", "wav": b"WAVE", "webp": b"WEBP"}
OVERLAP = max(len(s) for _, s, _ in SIGNATURES) - 1
MAX_SIZES = {"jpg": 256 * MIB, "png": 512 * MIB, "pdf": 512 * MIB, "gif": 128 * MIB,
             "bmp": 256 * MIB, "tif": 512 * MIB, "mp3": 64 * MIB, "flac": 1 * GIB, "ogg": 1 * GIB,
             "wav": 2 * GIB, "m4a": 2 * GIB, "doc": 512 * MIB, "zip": 4 * GIB, "rar": 4 * GIB,
             "7z": 4 * GIB, "mp4": 2 * GIB, "mkv": 2 * GIB, "mov": 2 * GIB, "avi": 2 * GIB, "webp": 64 * MIB}
JPEG_MARK = re.compile(rb"\xff[\xd9\xda]")
REPORT_FIELDS = ["folder", "file", "type", "offset_hex", "offset_decimal", "size_bytes", "sha256", "note",
                 "validation", "width", "height", "saved", "excluded_reason", "repair_file", "error",
                 "video_analysis", "duration_sec", "bitrate_kbps", "anomaly", "anomaly_reason",
                 "corrected_file", "corrected_sha256"]


class PumpkinError(Exception):
    """Erreur attendue, affichée proprement à l'utilisateur."""


class ImagingError(PumpkinError):
    pass


class CarvingError(PumpkinError):
    pass


def _hidden() -> dict:
    return {"creationflags": 0x08000000} if _WIN else {}


# --------------------------------------------------------------------------- #
# Configuration et utilitaires
# --------------------------------------------------------------------------- #

def load_config() -> dict:
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**DEFAULT_CONFIG, **data}
    except (OSError, ValueError):
        pass
    return dict(DEFAULT_CONFIG)


def save_config(cfg: dict) -> None:
    try:
        CONFIG_FILE.write_text(json.dumps(cfg, indent=4, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def format_bytes(value) -> str:
    if value is None:
        return "inconnue"
    size = float(value)
    for unit in ("o", "Ko", "Mo", "Go"):
        if abs(size) < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} To"


def _size_label(value) -> str:
    try:
        return format_bytes(int(float(value)))
    except (TypeError, ValueError):
        return "—"


def hardware_profile() -> dict:
    """Estime des réglages prudents à partir du matériel disponible."""
    logical = max(1, os.cpu_count() or 1)
    physical = logical
    available_gib = 4.0
    total_gib = None
    try:
        import psutil
        physical = max(1, psutil.cpu_count(logical=False) or logical)
        vm = psutil.virtual_memory()
        available_gib = max(1.0, vm.available / GIB)
        total_gib = vm.total / GIB
    except Exception:
        pass
    # Réserve de la RAM pour Windows, Flet et les caches du système.
    ram_limited_workers = max(1, int(max(1.0, available_gib - 1.0) * 2))
    workers = max(1, min(physical, 32, ram_limited_workers))
    scan_chunk_mib = max(32, min(128, int(available_gib * 2)))
    acq_chunk_mib = max(8, min(64, int(available_gib * 2)))
    return {"logical_cpus": logical, "physical_cpus": physical, "available_gib": available_gib,
            "total_gib": total_gib, "workers": workers, "chunk_mib": scan_chunk_mib,
            "acq_chunk_mib": acq_chunk_mib}


def default_options() -> dict:
    return {"auto_optimize": True, "workers": 0, "chunk_mib": 64,
            "min_size": 1024, "max_files": 0, "dedup": True, "repair": True, "contact_sheet": True,
            "exclude_thumbs": False, "dry_run": False, "analyze_only": False,
            "salvage_min_kib": 4, "salvage_max_mib": 64, "recovery_profile": 0.0}


def apply_recovery_profile(raw: dict, level: float) -> dict:
    """Préremplit les options selon le compromis récupération/vitesse (0=exhaustif, 100=rapide)."""
    level = max(0.0, min(100.0, float(level)))
    out = dict(raw)
    out["recovery_profile"] = level
    if level < 34:  # Priorité aux données, y compris doublons et petits fichiers
        out.update(auto_optimize=True, workers=0, chunk_mib=64, min_size=0, max_files=0,
                   dedup=False, repair=True, exclude_thumbs=False, contact_sheet=False,
                   salvage_min_kib=1, salvage_max_mib=256)
    elif level < 67:  # Compromis raisonnable
        out.update(auto_optimize=True, workers=0, chunk_mib=96, min_size=512, max_files=0,
                   dedup=True, repair=True, exclude_thumbs=False, contact_sheet=True,
                   salvage_min_kib=4, salvage_max_mib=64)
    else:  # Débit et temps de traitement privilégiés
        out.update(auto_optimize=True, workers=0, chunk_mib=128, min_size=4096, max_files=0,
                   dedup=True, repair=False, exclude_thumbs=True, contact_sheet=False,
                   salvage_min_kib=8, salvage_max_mib=32)
    return out


def parse_options(raw: dict) -> dict:
    """Valide les paramètres avancés saisis (texte ou booléens)."""
    labels = {"workers": "Threads", "chunk_mib": "Taille des blocs", "min_size": "Taille minimale",
              "max_files": "Maximum de fichiers", "salvage_min_kib": "JPEG tronqué min",
              "salvage_max_mib": "JPEG tronqué max"}
    bounds = {"workers": (0, 64), "chunk_mib": (4, 512), "min_size": (0, 10**9),
              "max_files": (0, 10**9), "salvage_min_kib": (1, 10**6), "salvage_max_mib": (1, 10**5)}
    out: dict = {}
    for key, (lo, hi) in bounds.items():
        try:
            v = int(str(raw.get(key, "")).strip())
        except ValueError:
            raise PumpkinError(f"« {labels[key]} » doit être un nombre entier.")
        if not lo <= v <= hi:
            raise PumpkinError(f"« {labels[key]} » doit être entre {lo} et {hi}.")
        out[key] = v
    for key in ("auto_optimize", "dedup", "repair", "contact_sheet", "exclude_thumbs", "dry_run", "analyze_only"):
        out[key] = bool(raw.get(key))
    if out["dry_run"] and out["analyze_only"]:
        raise PumpkinError("La simulation et l'analyse seule sont deux modes différents : choisissez-en un.")
    return out


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_") or "support"


def discover_volumes() -> list[dict]:
    """Volumes montés. La taille peut être inconnue : le volume reste sélectionnable."""
    volumes: list[dict] = []
    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                total, free = usage.total, usage.free
            except OSError:
                total = free = None
            label = f"{part.device} • {part.mountpoint}" + (f" • {part.fstype}" if part.fstype else "")
            volumes.append({"label": label, "device": part.device or part.mountpoint,
                            "mountpoint": part.mountpoint, "total": total, "free": free})
    except ImportError:
        if _WIN:
            for letter in string.ascii_uppercase:
                root = f"{letter}:\\"
                if os.path.exists(root):
                    volumes.append({"label": root, "device": root, "mountpoint": root,
                                    "total": None, "free": None})
    seen, result = set(), []
    for v in volumes:
        if v["device"] not in seen:
            seen.add(v["device"])
            result.append(v)
    return result


# --------------------------------------------------------------------------- #
# Acquisition d'image (lecture seule, reprise, attente de réinsertion)
# --------------------------------------------------------------------------- #

def _win_api():
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                                    wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                    wintypes.LPVOID]
    k32.DeviceIoControl.restype = wintypes.BOOL
    k32.SetFilePointerEx.argtypes = [wintypes.HANDLE, ctypes.c_longlong, wintypes.LPVOID, wintypes.DWORD]
    k32.SetFilePointerEx.restype = wintypes.BOOL
    k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    k32.ReadFile.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    return ctypes, wintypes, k32


class RawSource:
    """Accès en lecture seule à un volume (Windows) ou un périphérique (Unix)."""

    def __init__(self, device: str):
        self.device = device
        self._h = None
        self._fd = None
        if _WIN:
            self._ct, self._wt, self._k32 = _win_api()
            ct = self._ct
            path = "\\\\.\\" + device.rstrip("\\/")
            h = self._k32.CreateFileW(path, 0x80000000, 0x3, None, 3, 0, None)
            if h is None or h == ct.c_void_p(-1).value:
                raise ImagingError(f"Impossible d'ouvrir {path} : lancez en administrateur "
                                   f"({ct.FormatError(ct.get_last_error())}).")
            self._h = h
            length = ct.c_longlong()
            returned = self._wt.DWORD()
            if not self._k32.DeviceIoControl(h, 0x0007405C, None, 0, ct.byref(length),
                                             ct.sizeof(length), ct.byref(returned), None):
                self.close()
                raise ImagingError("Taille du volume illisible.")
            self.size = length.value
        else:
            try:
                self._fd = os.open(device, os.O_RDONLY)
            except OSError as e:
                raise ImagingError(f"Impossible d'ouvrir {device} (droits root requis ?) : {e}")
            self.size = os.lseek(self._fd, 0, os.SEEK_END)

    def read_at(self, offset: int, n: int) -> bytes:
        if _WIN:
            ct = self._ct
            if not self._k32.SetFilePointerEx(self._h, offset, None, 0):
                raise OSError("positionnement impossible")
            buf = ct.create_string_buffer(n)
            got = self._wt.DWORD()
            if not self._k32.ReadFile(self._h, buf, n, ct.byref(got), None):
                raise OSError(ct.FormatError(ct.get_last_error()))
            return buf.raw[:got.value]
        if self._fd is None:
            raise OSError("Source de lecture non ouverte.")
        pread = getattr(os, "pread", None)
        if callable(pread):
            # Typage explicite : certaines versions de typeshed exposent pread comme object.
            pread_fn = cast(Callable[[int, int, int], bytes], pread)
            return pread_fn(self._fd, n, offset)
        # Repli pour les systèmes sans pread (lecture séquentielle uniquement).
        os.lseek(self._fd, offset, os.SEEK_SET)
        return os.read(self._fd, n)

    def close(self) -> None:
        if _WIN and self._h:
            self._k32.CloseHandle(self._h)
            self._h = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                self._fd = None


def _wait_for_device(device: str, total: int, done: int, log, progress, cancel: threading.Event):
    """Attend la réinsertion du support (gère même un changement de lettre sous Windows)."""
    log("Support déconnecté. En attente de la réinsertion du disque… "
        f"(progression sauvegardée à {format_bytes(done)})")
    while not cancel.is_set():
        progress(done / total, f"En attente de la réinsertion du disque (reprise à {format_bytes(done)})")
        time.sleep(2)
        
        target_device = device
        # Recherche intelligente si la lettre a changé sous Windows
        try:
            volumes = discover_volumes()
            matching = [v for v in volumes if v["total"] == total]
            if matching:
                target_device = matching[0]["device"]
        except Exception:
            pass

        try:
            cand = RawSource(target_device)
        except ImagingError:
            continue
            
        if cand.size == total:
            log(f"Disque de nouveau détecté ({target_device}). Reprise à {format_bytes(done)}.")
            return cand
        cand.close()
    return None


def acquire_image(device: str, image_path: Path, log, progress, cancel: threading.Event,
                  chunk_size: int | None = None) -> dict:
    acq_chunk = max(MIB, int(chunk_size or CHUNK_ACQ))
    src = RawSource(device)
    try:
        total = src.size
        if total <= 0:
            raise ImagingError("Taille du support nulle.")
        state_path = image_path.with_name(image_path.name + ".progress.json")
        image_path.parent.mkdir(parents=True, exist_ok=True)
        done = 0
        if image_path.exists():
            if not state_path.exists():
                raise ImagingError(f"{image_path.name} existe sans fichier de progression. "
                                   "Supprimez-le ou choisissez un autre dossier.")
            st = json.loads(state_path.read_text(encoding="utf-8"))
            if st.get("device") != device or int(st.get("total", -1)) != total:
                raise ImagingError("La progression enregistrée ne correspond pas à ce support. Arrêt par prudence.")
            done = min(int(st.get("done", 0)), image_path.stat().st_size, total)
            done -= done % acq_chunk
            log(f"Reprise de l'acquisition à {format_bytes(done)}.")
        else:
            free = shutil.disk_usage(image_path.parent).free
            if free < total + 100 * MIB:
                raise ImagingError(f"Espace libre insuffisant : {format_bytes(free)} pour {format_bytes(total)}.")
            image_path.touch()

        with open(image_path, "r+b") as out:
            out.truncate(done)
            out.seek(done)

            def save():
                out.flush()
                os.fsync(out.fileno())
                state_path.write_text(json.dumps({"device": device, "total": total, "done": done}),
                                      encoding="utf-8")

            save()
            
            # <-- AJOUT : Forcer l'affichage immédiat de la progression (idéal pour la reprise ou le démarrage)
            progress(done / total, f"Acquisition : {format_bytes(done)} / {format_bytes(total)}")

            while done < total:
                if cancel.is_set():
                    save()
                    return {"status": "cancelled", "done": done, "total": total,
                            "message": f"Acquisition arrêtée à {format_bytes(done)}. Relancez pour reprendre."}
                want = min(acq_chunk, total - done)
                try:
                    data = src.read_at(done, want)
                    if not data:
                        raise OSError("lecture vide (support absent ?)")
                except Exception as e:
                    save()
                    log(f"Lecture impossible à {format_bytes(done)} : {e}")
                    src.close()
                    new = _wait_for_device(device, total, done, log, progress, cancel)
                    if new is None:
                        save()
                        return {"status": "cancelled", "done": done, "total": total,
                                "message": f"Acquisition arrêtée à {format_bytes(done)}. Relancez pour reprendre."}
                    src = new
                    continue
                out.write(data)
                done += len(data)
                if done % (128 * MIB) < acq_chunk or done == total:
                    save()
                progress(done / total, f"Acquisition : {format_bytes(done)} / {format_bytes(total)}")
            save()
        return {"status": "done", "done": done, "total": total}
    finally:
        src.close()


# --------------------------------------------------------------------------- #
# Carving : scan des signatures (multi-processus, recouvrement correct)
# --------------------------------------------------------------------------- #

_HS_CACHE_KEY = None
_HS_CACHE_DB = None
_HS_CACHE_META = None


def _hyperscan_matcher(signatures):
    """Compile une base Hyperscan une fois par processus et par ensemble de signatures."""
    global _HS_CACHE_KEY, _HS_CACHE_DB, _HS_CACHE_META, _hyperscan
    module = _hyperscan
    if module is None:
        return None
    key = tuple(signatures)
    if _HS_CACHE_KEY != key:
        expressions = []
        meta = {}
        for ident, (ext, sig, lead) in enumerate(signatures, 1):
            # Échappement regex : recherche littérale des octets, sans interprétation.
            expressions.append((ident, re.escape(sig), 0))
            meta[ident] = (ext, sig, lead)
        try:
            db = module.Database(mode=module.HS_MODE_BLOCK)
            db.compile(expressions=expressions)
        except Exception:
            # Une version native incompatible ne doit jamais empêcher une récupération.
            _hyperscan = None
            return None
        _HS_CACHE_KEY, _HS_CACHE_DB, _HS_CACHE_META = key, db, meta
    if _HS_CACHE_DB is None or _HS_CACHE_META is None:
        return None
    return _HS_CACHE_DB, _HS_CACHE_META


def _scan_range(job):
    """Scanne une plage en une lecture, avec Hyperscan si installé et repli sûr sinon."""
    path, start, stop, chunk, fsize, signatures, overlap = job
    read_size = min(fsize - start, (stop - start) + overlap)
    with open(path, "rb", buffering=8 * MIB) as f:
        f.seek(start)
        data = f.read(read_size)
    found = []
    matcher = _hyperscan_matcher(signatures)
    if matcher is not None:
        db, meta = matcher
        def on_match(ident, from_, to, flags, context):
            ext, sig, lead = meta[ident]
            i = to - len(sig)
            if i < stop - start and start + i - lead >= 0:
                found.append((start + i - lead, ext))
        try:
            db.scan(data, match_event_handler=on_match)
        except Exception:
            found.clear()
            matcher = None
    if matcher is None:
        # Repli sans dépendance externe. Une lecture du bloc, puis recherche par signature.
        for ext, sig, lead in signatures:
            i = data.find(sig)
            while i >= 0:
                if i < stop - start and start + i - lead >= 0:
                    found.append((start + i - lead, ext))
                i = data.find(sig, i + 1)
    return found


def scan_image(path: Path, workers: int, chunk: int, progress, cancel: threading.Event,
               log=None, exts=None):
    """Scan CPU optimisé. Le GPU est volontairement désactivé : son chemin expérimental
    était plus lent/instable sur certaines cartes et ne doit pas ralentir la récupération."""
    size = path.stat().st_size
    if size == 0:
        return [], 0

    # Ne cherche que les signatures correspondant aux types choisis dans l'interface.
    selected = set(exts) if exts else set(ALL_EXTS)
    signatures = tuple(item for item in SIGNATURES if item[0] in selected)
    if not signatures:
        return [], size
    overlap = max(len(sig) for _, sig, _ in signatures) - 1
    total_jobs = (size + chunk - 1) // chunk
    workers = max(1, min(int(workers), total_jobs))

    found: set[tuple[int, str]] = set()
    done = 0

    # Pour les petites images, éviter le coût de démarrage des processus Windows.
    if total_jobs == 1 or workers == 1:
        for start in range(0, size, chunk):
            if cancel.is_set():
                break
            stop = min(size, start + chunk)
            found.update(_scan_range((str(path), start, stop, chunk, size, signatures, overlap)))
            done += 1
            progress(done / total_jobs, f"Analyse CPU : {100 * done // total_jobs} %")
        return sorted(found), size

    # Soumission progressive : limite la mémoire consommée par les tâches en attente.
    pool = ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context("spawn"))
    next_start = 0
    in_flight = set()
    max_pending = max(workers, workers * 2)
    try:
        while next_start < size or in_flight:
            while next_start < size and len(in_flight) < max_pending and not cancel.is_set():
                stop = min(size, next_start + chunk)
                job = (str(path), next_start, stop, chunk, size, signatures, overlap)
                in_flight.add(pool.submit(_scan_range, job))
                next_start = stop
            if cancel.is_set() and not in_flight:
                break
            completed = next(iter(as_completed(in_flight)), None) if in_flight else None
            if completed is None:
                break
            in_flight.remove(completed)
            found.update(completed.result())
            done += 1
            progress(done / total_jobs, f"Analyse CPU : {100 * done // total_jobs} %")
            if cancel.is_set():
                for fut in in_flight:
                    fut.cancel()
                break
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return sorted(found), size


# --------------------------------------------------------------------------- #
# Longueur des fichiers par format
# --------------------------------------------------------------------------- #

def _find_first(f, start, limit, needle, block=4 * MIB):
    cur = start
    while cur < limit:
        f.seek(cur)
        b = f.read(min(block, limit - cur))
        if len(b) < len(needle):
            return None
        i = b.find(needle)
        if i >= 0:
            return cur + i
        cur += len(b) - len(needle) + 1
    return None


def _jpeg_length(f, off, size, next_off, eng):
    limit = min(size, off + MAX_SIZES["jpg"])
    pos = off + 2
    in_scan = False
    while pos + 4 <= limit:
        f.seek(pos)
        head = f.read(4)
        if len(head) < 4 or head[0] != 0xFF:
            break
        m = head[1]
        if m == 0xFF:
            pos += 1
            continue
        if m == 0xD9:
            return pos + 2 - off, "fin"
        if m in (0x01, 0xD8) or 0xD0 <= m <= 0xD7:
            pos += 2
            continue
        seglen = struct.unpack(">H", head[2:4])[0]
        if seglen < 2:
            break
        pos += 2 + seglen
        if m == 0xDA:
            in_scan = True
            break
    if in_scan:
        cursor = pos
        while cursor < limit:
            f.seek(cursor)
            block = f.read(min(4 * MIB, limit - cursor))
            if len(block) < 2:
                break
            mt = JPEG_MARK.search(block)
            if mt is None:
                cursor += len(block) - 1
                continue
            p = cursor + mt.start()
            if block[mt.start() + 1] == 0xD9:
                return p + 2 - off, "fin"
            f.seek(p + 2)
            lb = f.read(2)
            if len(lb) < 2:
                break
            cursor = p + 2 + struct.unpack(">H", lb)[0]
    if not eng["salvage"]:
        return None
    avail = min(size - off, MAX_SIZES["jpg"])
    smin, smax = eng["salvage_min"], eng["salvage_max"]
    if next_off is not None and smin <= next_off - off <= smax:
        return next_off - off, "tronquée"
    if next_off is None and smin <= min(avail, smax):
        return min(avail, smax), "tronquée"
    return None


def _png_length(f, off, size):
    limit = min(size, off + MAX_SIZES["png"])
    cur = off + 8
    for _ in range(200000):
        if cur + 12 > limit:
            return None
        f.seek(cur)
        h = f.read(8)
        if len(h) < 8:
            return None
        n = struct.unpack(">I", h[:4])[0]
        if cur + 12 + n > limit:
            return None
        cur += 12 + n
        if h[4:8] == b"IEND":
            return cur - off, "fin"
    return None


def _gif_length(f, off, size):
    p = _find_first(f, off + 6, min(size, off + MAX_SIZES["gif"]), b"\x3b")
    return (p + 1 - off, "fin") if p is not None and p + 1 - off >= 14 else None


def _bmp_length(f, off, size):
    f.seek(off)
    h = f.read(26)
    if len(h) < 26 or h[:2] != b"BM":
        return None
    fsize = struct.unpack("<I", h[2:6])[0]
    pix = struct.unpack("<I", h[10:14])[0]
    dib = struct.unpack("<I", h[14:18])[0]
    if fsize < 26 or fsize > min(MAX_SIZES["bmp"], size - off):
        return None
    if dib not in (12, 40, 52, 56, 64, 108, 124) or pix < 14 + dib or pix >= fsize:
        return None
    return fsize, "fin"


def _pdf_length(f, off, size):
    limit = min(size, off + MAX_SIZES["pdf"])
    last, cur = None, off
    while True:
        p = _find_first(f, cur, limit, b"%%EOF")
        if p is None:
            break
        last = p + 5
        cur = p + 5
    return (last - off, "fin") if last else None


def _riff_length(f, off, size, ext):
    f.seek(off)
    h = f.read(12)
    if len(h) < 12 or h[:4] != b"RIFF" or h[8:12] != RIFF_SUBTYPE[ext]:
        return None
    total = struct.unpack("<I", h[4:8])[0] + 8
    if total < 12 or off + total > size:
        return None
    return total, "fin"


def _zip_length(f, off, size):
    limit = min(size, off + MAX_SIZES["zip"])
    p = _find_first(f, off, limit, b"PK\x05\x06")
    return (p + 22 - off, "fin") if p is not None else None


def _measure(f, off, ext, size, next_same, eng):
    if ext == "jpg":
        return _jpeg_length(f, off, size, next_same, eng)
    if ext == "png":
        return _png_length(f, off, size)
    if ext == "gif":
        return _gif_length(f, off, size)
    if ext == "bmp":
        return _bmp_length(f, off, size)
    if ext == "pdf":
        return _pdf_length(f, off, size)
    if ext in RIFF_SUBTYPE:
        return _riff_length(f, off, size, ext)
    if ext == "zip":
        return _zip_length(f, off, size)
    limit = min(size - off, MAX_SIZES.get(ext, 256 * MIB))
    if next_same is not None and 0 < next_same - off <= limit:
        return next_same - off, "borne suivante"
    return (limit, "fin d'image") if limit > 0 else None


# --------------------------------------------------------------------------- #
# Plages occupées, validation, réparation, vidéo
# --------------------------------------------------------------------------- #


def _base_record(folder: str, name: str, ext: str, off: int, length: int,
                 digest: str, note: str) -> dict:
    """Construit une entrée de manifeste avec tous les champs attendus par les rapports."""
    return {
        "folder": folder,
        "file": name,
        "type": ext,
        "offset_hex": hex(off),
        "offset_decimal": off,
        "size_bytes": length,
        "sha256": digest,
        "note": note,
        "validation": "not_checked",
        "width": None,
        "height": None,
        "saved": True,
        "excluded_reason": "",
        "repair_file": "",
        "error": "",
        "video_analysis": "",
        "duration_sec": None,
        "bitrate_kbps": None,
        "anomaly": False,
        "anomaly_reason": "",
        "corrected_file": "",
        "corrected_sha256": "",
    }


def _image_checks(record: dict, target: Path, out_dir: Path, opts: dict) -> None:
    """Valide les images si Pillow est disponible, sans rendre Pillow obligatoire."""
    try:
        from PIL import Image, ImageFile
    except ImportError:
        record["validation"] = "not_checked"
        record["error"] = "Pillow absent : validation d’image non effectuée."
        return

    try:
        # Vérification stricte d’abord : une image tronquée ne doit pas être annoncée
        # comme pleinement valide simplement parce qu’une miniature peut s’ouvrir.
        ImageFile.LOAD_TRUNCATED_IMAGES = False
        with Image.open(target) as im:
            im.verify()
        with Image.open(target) as im:
            record["width"], record["height"] = im.size
            im.load()
        record["validation"] = "valid"
    except Exception as exc:
        record["validation"] = "invalid"
        record["error"] = f"Validation image : {type(exc).__name__}: {exc}"[:500]
        record["anomaly"] = True
        record["anomaly_reason"] = "Image illisible ou potentiellement tronquée"


def _probe_video(target: Path) -> dict | None:
    """Retourne les métadonnées ffprobe, ou None si l’outil n’est pas disponible."""
    exe = shutil.which("ffprobe")
    if not exe:
        return None
    try:
        result = subprocess.run(
            [exe, "-v", "error", "-show_entries",
             "format=duration,bit_rate:stream=codec_type,width,height,duration,bit_rate",
             "-of", "json", str(target)],
            capture_output=True, text=True, timeout=30, check=False,
            **_hidden(),
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        data = json.loads(result.stdout)
        return data if isinstance(data, dict) else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def _analyze_video(target: Path, length: int) -> dict:
    """Analyse prudente des métadonnées vidéo ; n’infère pas de défaut sans preuve."""
    data = _probe_video(target)
    if data is None:
        return {"video_analysis": "non disponible (ffprobe absent ou fichier non reconnu)",
                "duration_sec": None, "bitrate_kbps": None,
                "anomaly": False, "anomaly_reason": ""}
    fmt = data.get("format") or {}
    streams = data.get("streams") or []
    duration = fmt.get("duration")
    bitrate = fmt.get("bit_rate")
    if duration is None:
        durations = [x.get("duration") for x in streams if x.get("duration") is not None]
        duration = durations[0] if durations else None
    if bitrate is None:
        rates = [x.get("bit_rate") for x in streams if x.get("bit_rate") is not None]
        bitrate = rates[0] if rates else None
    try:
        duration = round(float(duration), 3) if duration is not None else None
    except (TypeError, ValueError):
        duration = None
    try:
        bitrate = round(float(bitrate) / 1000, 1) if bitrate is not None else None
    except (TypeError, ValueError):
        bitrate = None
    recognized = bool(streams)
    return {
        "video_analysis": "métadonnées lues" if recognized else "aucun flux reconnu",
        "duration_sec": duration,
        "bitrate_kbps": bitrate,
        "anomaly": not recognized,
        "anomaly_reason": "ffprobe ne reconnaît aucun flux" if not recognized else "",
    }


def _correct_video(target: Path, output_dir: Path) -> Path | None:
    """Tente un remux sans ré-encodage ; ne remplace jamais le fichier original."""
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        return None
    fixed = output_dir / f"{target.stem}_remux{target.suffix}"
    temp = fixed.with_name(fixed.stem + ".part" + fixed.suffix)
    try:
        result = subprocess.run(
            [ffmpeg, "-nostdin", "-v", "error", "-y", "-i", str(target),
             "-map", "0", "-c", "copy", "-movflags", "+faststart", str(temp)],
            capture_output=True, text=True, timeout=1800, check=False,
            **_hidden(),
        )
        if result.returncode != 0 or not temp.is_file() or temp.stat().st_size == 0:
            temp.unlink(missing_ok=True)
            return None
        os.replace(temp, fixed)
        return fixed
    except (OSError, subprocess.SubprocessError):
        temp.unlink(missing_ok=True)
        return None

def _range_overlap(starts, ends, a, b) -> bool:
    i = bisect.bisect_right(starts, a)
    if i and ends[starts[i - 1]] > a:
        return True
    return i < len(starts) and starts[i] < b


def _range_add(starts, ends, a, b) -> None:
    if a in ends:
        return
    bisect.insort(starts, a)
    ends[a] = b


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(8 * MIB), b""):
            h.update(block)
    return h.hexdigest()


def _copy_region(src_f, off, length, target: Path) -> str:
    """Copie une plage vers un fichier temporaire, puis publie atomiquement et calcule SHA-256."""
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    temp = target.with_name(target.name + ".part")
    try:
        with open(temp, "wb", buffering=1024 * 1024) as of:
            src_f.seek(off)
            remaining = length
            while remaining:
                block = src_f.read(min(8 * MIB, remaining))
                if not block:
                    raise CarvingError("Fin de lecture inattendue sur la source.")
                of.write(block)
                digest.update(block)
                remaining -= len(block)
            of.flush()
        os.replace(temp, target)
        return digest.hexdigest()
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- #
# Moteur de carving
# --------------------------------------------------------------------------- #

def run_carving(image, out_dir, opts: dict, log, progress, cancel: threading.Event) -> dict:
    image = Path(image)
    out_dir = Path(out_dir)
    if not image.is_file():
        raise CarvingError(f"Image introuvable : {image}")
    exts = {e for e in (opts.get("exts") or ALL_EXTS) if e in ALL_EXTS}
    if not exts:
        raise CarvingError("Aucun type de fichier sélectionné.")
    dry = bool(opts.get("dry_run"))
    analyze = bool(opts.get("analyze_only"))
    if dry and analyze:
        raise CarvingError("La simulation et l'analyse seule sont deux modes différents.")
    profile = hardware_profile()
    if opts.get("auto_optimize", True):
        workers = profile["workers"]
        chunk = profile["chunk_mib"] * MIB
    else:
        requested_workers = int(opts.get("workers", 0))
        workers = max(1, min(64, requested_workers or profile["workers"]))
        chunk = max(4, int(opts.get("chunk_mib", 64))) * MIB
    min_size = max(0, int(opts.get("min_size", 1024)))
    max_files = max(0, int(opts.get("max_files", 0)))
    eng = {"salvage": bool(opts.get("repair", True)),
           "salvage_min": max(1, int(opts.get("salvage_min_kib", 4))) * 1024,
           "salvage_max": max(1, int(opts.get("salvage_max_mib", 64))) * MIB}

    persist = not (dry or analyze)
    manifest = out_dir / "manifest.jsonl"
    meta_path = out_dir / "run_metadata.json"
    resume = False
    if persist:
        out_dir.mkdir(parents=True, exist_ok=True)
        if meta_path.exists():
            try:
                previous = json.loads(meta_path.read_text(encoding="utf-8")).get("source")
            except (OSError, ValueError):
                previous = None
            if previous and previous != str(image):
                raise CarvingError("Ce dossier contient une récupération d'une autre image. "
                                   "Choisissez un autre dossier de sortie.")
            resume = manifest.exists()
            if resume:
                log("Reprise automatique : une récupération précédente existe dans ce dossier.")
    tmp_dir = Path(tempfile.mkdtemp(prefix="pumpkin_")) if analyze else None
    repair_on = bool(opts.get("repair", True)) and not analyze
    eng_opts = dict(opts, repair=repair_on)

    try:
        size_before = image.stat().st_size
        started = time.time()
        log(f"Matériel détecté : {profile['physical_cpus']} cœurs physiques, {profile['logical_cpus']} processeurs logiques, "
            f"{profile['available_gib']:.1f} Gio de RAM disponible.")
        backend = "Hyperscan natif" if _hyperscan is not None else "recherche intégrée (repli sans dépendance)"
        log(f"Analyse des signatures : {backend}, {workers} processus CPU, blocs de {chunk // MIB} Mio.")
        progress(0.0, "Analyse des signatures…")
        cands, size = scan_image(image, workers, chunk, lambda f, l: progress(0.4 * f, l), cancel,
                                 log=log, exts=exts)
        if cancel.is_set():
            return {"status": "cancelled", "message": "Analyse annulée."}
        if image.stat().st_size != size_before:
            raise CarvingError("La taille de l'image a changé pendant l'analyse. Relancez sur une copie figée.")
        cands = [c for c in cands if c[1] in exts]
        log(f"{len(cands)} signatures retenues pour les types choisis.")

        by_ext: dict[str, list[int]] = {}
        for off, e in cands:
            by_ext.setdefault(e, []).append(off)

        starts: list[int] = []
        ends: dict[int, int] = {}
        hashes: set[str] = set()
        records: list[dict] = []
        seq: dict[str, int] = {}
        if resume:
            with open(manifest, encoding="utf-8") as mf:
                for line in mf:
                    if not line.strip():
                        continue
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    records.append(r)
                    a = int(r["offset_decimal"])
                    _range_add(starts, ends, a, a + int(r["size_bytes"]))
                    if r.get("sha256"):
                        hashes.add(r["sha256"])
                    seq[r["type"]] = seq.get(r["type"], 0) + 1
            log(f"Reprise : {len(records)} entrée(s) déjà traitée(s).")

        if persist:
            meta_path.write_text(json.dumps({"source": str(image), "source_size_bytes": size,
                                             "started_at": started, "formats": sorted(exts),
                                             "options": opts}, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
        mf = open(manifest, "a" if resume else "w", encoding="utf-8") if persist else None
        counts: dict[str, int] = {}
        dup = rej = anom = corr = 0
        total = len(cands)
        src_f = open(image, "rb", buffering=8 * MIB)
        try:
            for idx, (off, ext) in enumerate(cands, 1):
                if cancel.is_set():
                    log("Arrêt demandé par l'utilisateur.")
                    break
                if idx % 50 == 0 or idx == total:
                    progress(0.4 + 0.6 * idx / max(total, 1), f"Extraction {idx}/{total}")
                if _range_overlap(starts, ends, off, off + 1):
                    continue
                offs = by_ext[ext]
                j = bisect.bisect_right(offs, off)
                nxt = offs[j] if j < len(offs) else None
                m = _measure(src_f, off, ext, size, nxt, eng)
                if m is None:
                    rej += 1
                    continue
                length, note = m
                end = off + length
                if length < min_size or end > size:
                    rej += 1
                    continue
                if _range_overlap(starts, ends, off, end):
                    continue
                if dry:
                    counts[ext] = counts.get(ext, 0) + 1
                    _range_add(starts, ends, off, end)
                    continue

                folder = FOLDER_FOR[ext]
                seq[ext] = seq.get(ext, 0) + 1
                name = f"recup_{ext}_{seq[ext]:06d}_offset_{off:012x}.{ext}"
                if analyze:
                    if tmp_dir is None:
                        raise CarvingError("Le dossier temporaire d'analyse n'a pas été créé.")
                    target = tmp_dir / name
                else:
                    target = out_dir / folder / name
                try:
                    digest = _copy_region(src_f, off, length, target)
                except (OSError, CarvingError) as e:
                    log(f"Écriture impossible à {hex(off)} : {e}")
                    target.unlink(missing_ok=True)
                    continue
                if opts.get("dedup", True) and digest in hashes:
                    target.unlink(missing_ok=True)
                    dup += 1
                    _range_add(starts, ends, off, end)
                    continue
                hashes.add(digest)
                counts[ext] = counts.get(ext, 0) + 1
                rec = _base_record(folder, name, ext, off, length, digest, note)
                if ext in IMAGE_EXTS:
                    _image_checks(rec, target, out_dir, eng_opts)
                if ext in VIDEO_EXTS and length > VIDEO_BIG:
                    rec.update(_analyze_video(target, length))
                    if rec["anomaly"]:
                        anom += 1
                        log(f"ANOMALIE : {name} — {rec['anomaly_reason']}")
                        if not analyze:
                            fixed = _correct_video(target, target.parent)
                            if fixed:
                                rec["corrected_file"] = f"{folder}/{fixed.name}"
                                rec["corrected_sha256"] = _sha256(fixed)
                                corr += 1
                                log(f"Version corrigée enregistrée : {fixed.name}")
                if analyze:
                    target.unlink(missing_ok=True)
                    rec["saved"] = False
                _range_add(starts, ends, off, end)
                records.append(rec)
                if mf:
                    mf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    # Réduit les flush synchrones, tout en gardant un point de reprise fréquent.
                    if len(records) % 32 == 0:
                        mf.flush()
                if max_files and len(records) >= max_files:
                    log(f"Limite de {max_files} entrée(s) atteinte.")
                    break
        finally:
            src_f.close()
            if mf:
                mf.flush()
                mf.close()

        if image.stat().st_size != size_before:
            raise CarvingError("L'image source a été modifiée pendant le traitement : résultat non fiable.")

        saved = sum(1 for r in records if r.get("saved"))
        stats = {"candidates": total, "rejected": rej, "duplicates": dup, "anomalies": anom,
                 "corrected": corr, "saved": saved,
                 "valid": sum(1 for r in records if r.get("validation") == "valid"),
                 "invalid": sum(1 for r in records if r.get("validation") == "invalid"),
                 "repaired": sum(1 for r in records if r.get("repair_file")),
                 "counts": counts, "duration": round(time.time() - started, 1)}
        if dry:
            return {"status": "done", "stats": stats,
                    "message": f"Simulation : {total} candidat(s), par type {counts}. Aucun fichier écrit."}
        if analyze:
            return {"status": "done", "stats": stats,
                    "message": f"Analyse seule : {total} candidat(s), {stats['valid']} photo(s) valide(s), "
                               f"{anom} anomalie(s) vidéo. Aucun fichier conservé."}
        csv_path, html_path = _write_reports(records, out_dir, image, size, stats, eng_opts)
        log(f"Rapport CSV : {csv_path}")
        log(f"Rapport HTML : {html_path}")
        progress(1.0, "Terminé")
        return {"status": "done", "csv": str(csv_path), "out_dir": str(out_dir), "stats": stats,
                "message": f"Terminé : {saved} fichier(s) rangés dans {out_dir}"}
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _contact_sheet(records, out_dir: Path) -> list[str]:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return []
    paths = [out_dir / r["folder"] / r["file"] for r in records
             if r.get("saved") and r.get("type") in IMAGE_EXTS and r.get("validation") == "valid"]
    outputs, per, cols, cw, ch = [], 120, 6, 200, 170
    for n, start in enumerate(range(0, len(paths), per), 1):
        batch = paths[start:start + per]
        rows = (len(batch) + cols - 1) // cols
        sheet = Image.new("RGB", (cols * cw, rows * ch), (245, 245, 245))
        draw = ImageDraw.Draw(sheet)
        for k, p in enumerate(batch):
            try:
                with Image.open(p) as im:
                    im.thumbnail((180, 135))
                    x = (k % cols) * cw + (cw - im.width) // 2
                    y = (k // cols) * ch + 4
                    sheet.paste(im.convert("RGB"), (x, y))
                draw.text(((k % cols) * cw + 5, (k // cols) * ch + 143), p.name[:28], fill=(20, 20, 20))
            except Exception:
                continue
        name = f"planche_contact_{n:03d}.jpg"
        sheet.save(out_dir / "Photos" / name, quality=85)
        outputs.append(f"Photos/{name}")
    return outputs


def _write_reports(records, out_dir: Path, image: Path, size: int, stats: dict, opts: dict):
    csv_path = out_dir / "rapport_recuperation.csv"
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=REPORT_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)

    sheets = _contact_sheet(records, out_dir) if opts.get("contact_sheet", True) else []

    def esc(v):
        return html.escape("" if v is None else str(v))

    cols = ("folder", "file", "type", "offset_hex", "size_bytes", "validation", "width", "height",
            "saved", "excluded_reason", "corrected_file", "anomaly_reason")
    html_path = out_dir / "rapport_recuperation.html"
    # Écriture progressive : évite de dupliquer tout le rapport en mémoire pour des millions de candidats.
    with open(html_path, "w", encoding="utf-8", buffering=1024 * 1024) as report:
        report.write(
            "<!doctype html><html lang='fr'><meta charset='utf-8'><title>Rapport de récupération</title>"
            "<style>body{font:14px sans-serif;margin:24px}table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #ccc;padding:6px;text-align:left}th{background:#eee}</style>"
            "<h1>Rapport de récupération</h1>"
            f"<p>Source : {esc(image)}</p>"
            f"<p>Candidats : {stats['candidates']} ; enregistrés : {stats['saved']} ; valides : {stats['valid']} ; "
            f"invalides : {stats['invalid']} ; réparations : {stats['repaired']} ; doublons : {stats['duplicates']} ; "
            f"rejetés : {stats['rejected']} ; anomalies vidéo : {stats['anomalies']}</p>"
        )
        if sheets:
            for sheet in sheets:
                report.write(f'<p><a href="{esc(sheet)}">{esc(sheet)}</a></p>')
        else:
            report.write("<p>Aucune planche-contact.</p>")
        report.write("<table><thead><tr>" + "".join(f"<th>{esc(c)}</th>" for c in cols) + "</tr></thead><tbody>")
        for record in records:
            report.write("<tr>" + "".join(f"<td>{esc(record.get(c))}</td>" for c in cols) + "</tr>")
        report.write("</tbody></table><p style='color:#555'>Les classements sont indicatifs. "
                     "Le carving ne reconstruit pas les fichiers fragmentés.</p></html>")
    (out_dir / "run_metadata.json").write_text(json.dumps(
        {"source": str(image), "source_size_bytes": size, "stats": stats, "finished_at": time.time()},
        ensure_ascii=False, indent=2), encoding="utf-8")
    return csv_path, html_path


# --------------------------------------------------------------------------- #
# Workflows
# --------------------------------------------------------------------------- #

def run_workflow(cfg: dict, log, progress, cancel: threading.Event) -> dict:
    preset = cfg["preset"]
    out_dir = Path(cfg["output_dir"])
    opts = {**cfg["options"], "exts": cfg.get("exts") or sorted(ALL_EXTS)}
    profile = hardware_profile()
    if opts.get("auto_optimize", True):
        opts["workers"] = profile["workers"]
        opts["chunk_mib"] = profile["chunk_mib"]
        opts["acq_chunk_mib"] = profile["acq_chunk_mib"]
        log(f"Optimisation automatique : {profile['physical_cpus']} cœurs physiques, "
            f"{profile['available_gib']:.1f} Gio de RAM disponible ; "
            f"{profile['workers']} processus, blocs scan {profile['chunk_mib']} Mio, "
            f"blocs acquisition {profile['acq_chunk_mib']} Mio.")
    else:
        opts["acq_chunk_mib"] = max(8, min(64, int(opts.get("chunk_mib", 64) // 2 or 8)))

    if preset == "image_only":
        return run_carving(cfg["image"], out_dir, opts, log, progress, cancel)

    device = cfg["device"]
    image_path = out_dir / f"image_{safe_name(device)}.img"
    log(f"Acquisition de {device} vers {image_path.name}…")
    acq_progress = (lambda f, l: progress(0.5 * f, l)) if preset == "full" else progress
    res = acquire_image(device, image_path, log, acq_progress, cancel,
                        chunk_size=int(opts.get("acq_chunk_mib", 8)) * MIB)
    if res["status"] == "cancelled":
        return {"status": "cancelled", "message": res["message"]}
    if preset == "setup":
        return {"status": "done", "message": f"Image créée : {image_path}"}
    log("Acquisition terminée. Lancement du carving…")
    return run_carving(image_path, out_dir / "recuperation", opts, log,
                       lambda f, l: progress(0.5 + 0.5 * f, l), cancel)


# --------------------------------------------------------------------------- #
# Sélecteurs natifs (sous-processus, sûr avec les threads de l'interface)
# --------------------------------------------------------------------------- #

def native_pick(kind: str, title: str, initial: str):
    try:
        proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--pick", kind, title, str(initial)],
                              capture_output=True, text=True, encoding="utf-8", timeout=900, **_hidden())
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PumpkinError(f"Sélecteur indisponible : {e}")
    if proc.returncode != 0:
        raise PumpkinError("Sélecteur indisponible (tkinter absent ?).")
    return proc.stdout.strip() or None


def _native_picker(argv) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("kind", choices=["file", "dir"])
    p.add_argument("title")
    p.add_argument("initial")
    a = p.parse_args(argv)
    import tkinter as tk
    from tkinter import filedialog
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        if a.kind == "file":
            res = filedialog.askopenfilename(parent=root, title=a.title, initialdir=a.initial,
                                             filetypes=[("Images disque", "*.img *.dd *.raw *.iso *.dmg *.bin *.001"),
                                                        ("Tous les fichiers", "*.*")])
        else:
            res = filedialog.askdirectory(parent=root, title=a.title, initialdir=a.initial, mustexist=True)
    finally:
        root.destroy()
    reconfigure_stdout = getattr(sys.stdout, "reconfigure", None)
    if callable(reconfigure_stdout):
        reconfigure_stdout(encoding="utf-8")
    print(res or "")


# --------------------------------------------------------------------------- #
# Interface Flet
# --------------------------------------------------------------------------- #

def main(page: ft.Page):
    config = load_config()
    page.title = f"{APP_NAME} - Accueil"
    page.padding = 24
    page.scroll = ft.ScrollMode.AUTO
    page.theme_mode = ft.ThemeMode.DARK if config.get("theme", "dark") == "dark" else ft.ThemeMode.LIGHT
    # API Flet récente : les dimensions sont portées par page.window.
    page.window.min_width = 760
    page.window.min_height = 650

    state = {"preset": None, "step": 0, "media_type": None, "volume": None, "image_path": None,
             "output_dir": str(BASE_DIR), "extensions": set(), "options": default_options()}

    def set_title(view):
        page.title = f"{APP_NAME} - {view}"

    def notify(message):
        sb = ft.SnackBar(content=ft.Text(message))
        # Éviter l'accès statique à page.open, absent des anciennes stubs Flet.
        open_control = getattr(page, "open", None)
        if callable(open_control):
            open_control(sb)
            return
        # Repli pour les versions anciennes de Flet.
        overlay = getattr(page, "overlay", None)
        if overlay is not None:
            overlay.append(sb)
            sb.open = True
            page.update()
        else:
            print(str(message), file=sys.stderr)

    def outlined_card(content, selected=False, on_click=None, width=None):
        color = ft.Colors.ORANGE if selected else ft.Colors.OUTLINE_VARIANT
        side = ft.BorderSide(2, color)
        return ft.Container(
            content=content, width=width, padding=18,
            border=ft.Border(top=side, right=side, bottom=side, left=side), border_radius=16,
            bgcolor=ft.Colors.with_opacity(0.08, ft.Colors.ORANGE) if selected else None,
            animate=ft.Animation(220, ft.AnimationCurve.EASE_OUT), on_click=on_click)

    def app_header(subtitle):
        return ft.Row([
            ft.Container(content=ft.Text(APP_ICON, size=30), padding=12, border_radius=14,
                         bgcolor=ft.Colors.with_opacity(0.12, ft.Colors.ORANGE)),
            ft.Column([ft.Text(APP_NAME, size=25, weight=ft.FontWeight.BOLD),
                       ft.Text(subtitle, size=13, color=ft.Colors.OUTLINE)], spacing=2, expand=True),
            ft.IconButton(icon=ft.Icons.SETTINGS_OUTLINED, tooltip="Paramètres",
                          on_click=lambda e: show_settings()),
        ], vertical_alignment=ft.CrossAxisAlignment.CENTER)

    def show_view(view, controls):
        set_title(view)
        page.controls.clear()
        page.add(ft.Column(controls, spacing=20, horizontal_alignment=ft.CrossAxisAlignment.STRETCH))
        page.update()

    # ----- Accueil, tutoriel, tableau de bord, paramètres -------------------

    def show_welcome():
        welcome = ft.Column([
            ft.Text(APP_ICON, size=76),
            ft.Text(f"Bienvenue dans {APP_NAME}", size=30, weight=ft.FontWeight.BOLD, text_align=ft.TextAlign.CENTER),
            ft.Text("Un parcours guidé pour préparer et exécuter vos récupérations.", size=16,
                    text_align=ft.TextAlign.CENTER, color=ft.Colors.OUTLINE),
            ft.Row([ft.Button("Découvrir l'application", icon=ft.Icons.SCHOOL_OUTLINED,
                              on_click=lambda e: show_tutorial()),
                    ft.OutlinedButton("Passer le tutoriel", on_click=lambda e: finish_welcome())],
                   alignment=ft.MainAxisAlignment.CENTER, wrap=True),
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=22)
        show_view("Bienvenue", [app_header("Récupération de fichiers, étape par étape"), welcome])

    def finish_welcome():
        config["first_time"] = False
        save_config(config)
        show_dashboard()

    def show_tutorial():
        steps = [
            ("Bienvenue", "Pumpkin Carver prépare puis exécute une récupération de fichiers."),
            ("Choisir un mode", "Full Carving acquiert le support puis récupère les fichiers. Setup Carving crée seulement "
                                "une image. Extraction depuis une image travaille sur un fichier image existant."),
            ("Choisir le support", "Choisissez le volume détecté. Sous Windows, lancez l'application en administrateur."),
            ("Choisir les types", "Les fichiers sont rangés par catégorie : Photos, Vidéos, Audio, Documents, Archives."),
            ("Paramètres avancés", "L'avant-dernière étape règle les threads d'analyse, les blocs, les filtres et les modes "
                                   "simulation ou analyse seule. Les valeurs par défaut conviennent en général."),
            ("Interruptions", "Si le support se déconnecte, l'application attend sa réinsertion puis reprend là où elle "
                              "s'était arrêtée. Une récupération interrompue reprend automatiquement dans son dossier."),
        ]
        index = {"value": 0}
        title = ft.Text(steps[0][0], size=24, weight=ft.FontWeight.BOLD)
        body = ft.Text(steps[0][1], size=16)
        bar = ft.ProgressBar(value=1 / len(steps), color=ft.Colors.ORANGE)
        counter = ft.Text(f"Étape 1 sur {len(steps)}", color=ft.Colors.OUTLINE)
        next_button = ft.Button("Étape suivante", icon=ft.Icons.ARROW_FORWARD, on_click=lambda e: next_step())

        def next_step():
            if index["value"] < len(steps) - 1:
                index["value"] += 1
                i = index["value"]
                title.value, body.value = steps[i]
                bar.value = (i + 1) / len(steps)
                counter.value = f"Étape {i + 1} sur {len(steps)}"
                next_button.content = "Terminer" if i == len(steps) - 1 else "Étape suivante"
                page.update()
            else:
                finish_welcome()

        show_view("Tutoriel", [
            app_header("Tutoriel"),
            outlined_card(ft.Column([counter, bar, title, body], spacing=18)),
            ft.Row([ft.TextButton("Retour au tableau de bord", on_click=lambda e: show_dashboard()), next_button],
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ])

    def choose_preset(preset):
        state.update({"preset": preset, "step": 0, "media_type": None, "volume": None,
                      "image_path": None, "extensions": set(), "output_dir": str(BASE_DIR),
                      "options": default_options()})
        show_wizard()

    def show_dashboard():
        state["preset"] = None
        presets = [
            ("full", ft.Icons.DYNAMIC_FORM, "Full Carving", "Acquisition puis récupération depuis un support physique",
             "Support • Disque • Types • Options • Sortie"),
            ("setup", ft.Icons.SAVE_ALT, "Setup Carving", "Créer une image du support sélectionné",
             "Support • Disque • Options • Sortie"),
            ("image_only", ft.Icons.PERM_MEDIA, "Extraction depuis une image", "Extraire des fichiers depuis une image existante",
             "Image source • Types • Options • Sortie"),
        ]
        cards = [outlined_card(ft.Row([
            ft.Container(ft.Icon(icon, size=30, color=ft.Colors.ORANGE), padding=10,
                         bgcolor=ft.Colors.with_opacity(0.10, ft.Colors.ORANGE), border_radius=12),
            ft.Column([ft.Text(title, size=18, weight=ft.FontWeight.BOLD), ft.Text(description, size=14),
                       ft.Text(summary, size=12, color=ft.Colors.OUTLINE)], spacing=6, expand=True),
            ft.Icon(ft.Icons.CHEVRON_RIGHT),
        ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
            on_click=lambda e, p=preset: choose_preset(p)) for preset, icon, title, description, summary in presets]

        show_view("Dashboard", [
            app_header(f"Bonjour, {config.get('username', 'Utilisateur')}"),
            ft.Text("Que souhaitez-vous faire ?", size=26, weight=ft.FontWeight.BOLD),
            ft.Text("Sélectionnez une carte pour commencer le parcours guidé.", color=ft.Colors.OUTLINE),
            *cards,
            ft.Row([ft.TextButton("Tutoriel", icon=ft.Icons.SCHOOL_OUTLINED, on_click=lambda e: show_tutorial()),
                    ft.TextButton("Paramètres", icon=ft.Icons.SETTINGS_OUTLINED, on_click=lambda e: show_settings())],
                   alignment=ft.MainAxisAlignment.END),
        ])

    def show_settings():
        username = ft.TextField(label="Nom d'utilisateur", value=config.get("username", "Utilisateur"))
        theme = ft.Dropdown(label="Thème", value=config.get("theme", "dark"), options=[
            ft.dropdown.Option("dark", "Sombre"), ft.dropdown.Option("light", "Clair")])
        language = ft.Dropdown(label="Langue", value=config.get("langue", "fr"),
                               options=[ft.dropdown.Option("fr", "Français")])

        def save_settings(e):
            config["username"] = (username.value or "").strip() or "Utilisateur"
            config["theme"] = theme.value or "dark"
            config["langue"] = language.value or "fr"
            save_config(config)
            page.theme_mode = ft.ThemeMode.DARK if config["theme"] == "dark" else ft.ThemeMode.LIGHT
            notify("Paramètres enregistrés.")
            show_dashboard()

        show_view("Paramètres", [
            app_header("Préférences de l'application"),
            outlined_card(ft.Column([
                ft.Row([ft.Icon(ft.Icons.SETTINGS, color=ft.Colors.ORANGE, size=28),
                        ft.Text("Paramètres", size=24, weight=ft.FontWeight.BOLD)]),
                username, theme, language,
            ], spacing=16)),
            ft.Row([ft.TextButton("Retour", on_click=lambda e: show_dashboard()),
                    ft.Button("Enregistrer", icon=ft.Icons.CHECK, on_click=save_settings)],
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ])

    # ----- Assistant ---------------------------------------------------------

    LABELS = {"full": "Full Carving", "setup": "Setup Carving", "image_only": "Extraction depuis une image"}

    def get_steps(preset):
        if preset == "full":
            return ["media", "disk", "extensions", "options", "output"]
        if preset == "setup":
            return ["media", "disk", "options", "output"]
        return ["image", "extensions", "options", "output"]

    def show_wizard():
        preset = state["preset"]
        title = LABELS.get(preset, "Configuration")
        steps = get_steps(preset)
        state["step"] = max(0, min(state["step"], len(steps) - 1))
        step = state["step"]

        def previous(e):
            if state["step"] > 0:
                state["step"] -= 1
                show_wizard()
            else:
                show_dashboard()

        def next_step(e):
            if not validate_step(steps[state["step"]]):
                return
            if state["step"] < len(steps) - 1:
                state["step"] += 1
                show_wizard()
            else:
                show_summary(preset)

        show_view(title, [
            app_header(title),
            ft.Row([ft.Text(title, size=25, weight=ft.FontWeight.BOLD), ft.Container(expand=True),
                    ft.Text(f"Étape {step + 1} sur {len(steps)}", color=ft.Colors.OUTLINE)]),
            ft.ProgressBar(value=(step + 1) / len(steps), color=ft.Colors.ORANGE),
            outlined_card(build_step(steps[step])),
            ft.Row([ft.OutlinedButton("Précédent", icon=ft.Icons.ARROW_BACK, on_click=previous),
                    ft.Button("Étape suivante" if step < len(steps) - 1 else "Vérifier la configuration",
                              icon=ft.Icons.ARROW_FORWARD, on_click=next_step)],
                   alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ])

    def media_label():
        return {"sd": "Carte SD", "usb": "Clé USB"}.get(state["media_type"], "Aucun support sélectionné")

    def volume_summary():
        v = state["volume"]
        if not v:
            return "Aucun volume sélectionné."
        return (f"Périphérique : {v['device']}\nPoint de montage : {v['mountpoint']}\n"
                f"Capacité détectée : {format_bytes(v['total'])}")

    def build_step(step_name):
        if step_name == "media":
            def pick(kind):
                state["media_type"] = kind
                state["volume"] = None
                show_wizard()
            return ft.Column([
                ft.Text("Quel type de support voulez-vous cibler ?", size=20, weight=ft.FontWeight.BOLD),
                ft.Row([
                    outlined_card(ft.Column([ft.Icon(ft.Icons.SD_STORAGE, size=36, color=ft.Colors.ORANGE),
                                             ft.Text("Carte SD", weight=ft.FontWeight.BOLD),
                                             ft.Text("Carte mémoire SD / microSD", size=12)],
                                            horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                                  selected=state["media_type"] == "sd", width=220, on_click=lambda e: pick("sd")),
                    outlined_card(ft.Column([ft.Icon(ft.Icons.USB, size=36, color=ft.Colors.ORANGE),
                                             ft.Text("Clé USB", weight=ft.FontWeight.BOLD),
                                             ft.Text("Support de stockage USB", size=12)],
                                            horizontal_alignment=ft.CrossAxisAlignment.CENTER),
                                  selected=state["media_type"] == "usb", width=220, on_click=lambda e: pick("usb")),
                ], wrap=True, alignment=ft.MainAxisAlignment.CENTER),
                ft.Text(f"Sélection actuelle : {media_label()}", color=ft.Colors.OUTLINE),
            ], spacing=16)

        if step_name == "disk":
            volumes = discover_volumes()
            if not volumes:
                return ft.Column([
                    ft.Text("Aucun volume détecté.", size=20, weight=ft.FontWeight.BOLD),
                    ft.Text("Installez psutil (pip install psutil) pour lister les volumes.", color=ft.Colors.OUTLINE)])
            current = state["volume"]
            current_key = next((str(i) for i, v in enumerate(volumes)
                                if current and v["device"] == current["device"]), None)
            summary = ft.Text(volume_summary(), selectable=True)

            def on_pick(e):
                idx = e.control.value
                state["volume"] = volumes[int(idx)] if idx not in (None, "") else None
                summary.value = volume_summary()
                page.update()

            return ft.Column([
                ft.Text("Sélectionnez le volume à traiter", size=20, weight=ft.FontWeight.BOLD),
                ft.Text("Un volume sans taille lisible reste utilisable : la taille sera lue sur le support.",
                        color=ft.Colors.OUTLINE),
                ft.Dropdown(label="Volume disponible", expand=True, value=current_key, on_select=on_pick,
                            options=[ft.dropdown.Option(str(i), f'{v["label"]} — {format_bytes(v["total"])}')
                                     for i, v in enumerate(volumes)]),
                summary,
                ft.OutlinedButton("Actualiser la liste", icon=ft.Icons.REFRESH, on_click=lambda e: show_wizard()),
                ft.Text("Vérifiez soigneusement le périphérique avant de lancer.", color=ft.Colors.ORANGE),
            ], spacing=14)

        if step_name == "extensions":
            return build_extensions()

        if step_name == "options":
            return build_options_step()

        if step_name == "image":
            controls = [
                ft.Text("Choisissez l'image disque source", size=20, weight=ft.FontWeight.BOLD),
                ft.Text(state["image_path"] or "Aucun fichier sélectionné", selectable=True),
                ft.Button("Parcourir les fichiers", icon=ft.Icons.FOLDER_OPEN, on_click=pick_image),
            ]
            existing = find_existing_images()
            if existing:
                controls.append(ft.Text("Images trouvées dans le dossier de Pumpkin Carver", weight=ft.FontWeight.BOLD))
                for path in existing:
                    controls.append(outlined_card(ft.Row([
                        ft.Icon(ft.Icons.INSERT_DRIVE_FILE, color=ft.Colors.ORANGE),
                        ft.Column([ft.Text(path.name, weight=ft.FontWeight.BOLD),
                                   ft.Text(f"{format_bytes(path.stat().st_size)} • {path}", size=12,
                                           color=ft.Colors.OUTLINE, selectable=True)], expand=True, spacing=3),
                        ft.Icon(ft.Icons.CHEVRON_RIGHT),
                    ]), selected=state["image_path"] == str(path), on_click=lambda e, p=str(path): select_image(p)))
            controls.append(ft.Text("Formats courants : .img, .dd, .raw, .iso, .dmg, .bin, .001", color=ft.Colors.OUTLINE))
            return ft.Column(controls, spacing=14)

        if step_name == "output":
            return ft.Column([
                ft.Text("Où enregistrer le résultat ?", size=20, weight=ft.FontWeight.BOLD),
                ft.Text("Les fichiers seront rangés dans des sous-dossiers Photos, Vidéos, Audio, Documents, Archives.",
                        color=ft.Colors.OUTLINE),
                ft.Text(state["output_dir"], selectable=True),
                ft.Button("Choisir le dossier de sortie", icon=ft.Icons.FOLDER_OPEN, on_click=pick_output),
                ft.OutlinedButton("Réinitialiser au dossier du script", icon=ft.Icons.RESTART_ALT,
                                  on_click=lambda e: reset_output()),
            ], spacing=14)
        return ft.Text("Étape inconnue")

    def build_options_step():
        o = state["options"]
        profile_value = float(o.get("recovery_profile", 0.0))
        pending_profile = {"value": profile_value}

        def describe_profile(value):
            if value < 34:
                return ("Récupération maximale", "Recherche prudente : conserve les petits fichiers et les doublons, tente le sauvetage JPEG. Plus lent, sans garantie absolue de tout retrouver.")
            if value < 67:
                return ("Équilibré", "Bon compromis entre vitesse, validation et récupération.")
            return ("Rapide", "Traitement accéléré : certains petits fichiers, miniatures ou fichiers tronqués peuvent être ignorés.")

        initial_name, initial_desc = describe_profile(profile_value)
        profile_status = ft.Text(f"Profil sélectionné : {initial_name} — {initial_desc}", color=ft.Colors.ORANGE, size=12)

        def on_profile_change(e):
            pending_profile["value"] = float(e.control.value)
            name, desc = describe_profile(pending_profile["value"])
            profile_status.value = f"Profil sélectionné : {name} — {desc}"
            page.update()

        def apply_profile(e):
            state["options"] = apply_recovery_profile(state["options"], pending_profile["value"])
            show_wizard()

        profile_slider = ft.Slider(min=0, max=100, divisions=100, value=profile_value,
                                   label="{value}%", on_change=on_profile_change)

        def num(key, label, width):
            return ft.TextField(label=label, value=str(o[key]), width=width, keyboard_type=ft.KeyboardType.NUMBER,
                                on_change=lambda e, k=key: o.__setitem__(k, e.control.value))

        def flag(key, label):
            return ft.Checkbox(label=label, value=bool(o[key]),
                               on_change=lambda e, k=key: o.__setitem__(k, e.control.value))

        return ft.Column([
            ft.Text("Paramètres avancés", size=20, weight=ft.FontWeight.BOLD),
            ft.Text("Choisissez un compromis : le curseur préremplit les paramètres ci-dessous. Vous pouvez ensuite les modifier manuellement.", color=ft.Colors.OUTLINE),
            ft.Text("Niveau de récupération", weight=ft.FontWeight.BOLD),
            ft.Row([ft.Text("Récupération maximale\nPlus lent", size=12), ft.Container(content=profile_slider, expand=True), ft.Text("Rapide\nPlus de risques", size=12)], vertical_alignment=ft.CrossAxisAlignment.CENTER),
            profile_status,
            ft.OutlinedButton("Appliquer ce profil aux paramètres", icon=ft.Icons.TUNE, on_click=apply_profile),
            ft.Text("Analyse et performances", weight=ft.FontWeight.BOLD),
            ft.Row([flag("auto_optimize", "Adapter automatiquement aux ressources du PC")], wrap=True),
            ft.Text("Le moteur CPU multi-processus ajuste le parallélisme aux ressources disponibles. Le scan évite les transferts GPU et limite les lectures et copies inutiles.", size=12, color=ft.Colors.OUTLINE),
            ft.Row([num("workers", "Processus (0 = auto)", 230),
                    num("chunk_mib", "Taille des blocs (Mio, mode manuel)", 240),
                    num("min_size", "Taille minimale (octets)", 220),
                    num("max_files", "Maximum de fichiers (0 = illimité)", 240)], wrap=True),
            ft.Text("Traitement des fichiers", weight=ft.FontWeight.BOLD),
            ft.Row([flag("dedup", "Dédupliquer (SHA-256)"),
                    flag("repair", "Réparer les JPEG tronqués"),
                    flag("contact_sheet", "Créer une planche-contact"),
                    flag("exclude_thumbs", "Exclure les miniatures probables")], wrap=True),
            ft.Row([num("salvage_min_kib", "JPEG tronqué : min (Kio)", 200),
                    num("salvage_max_mib", "JPEG tronqué : max (Mio)", 200)], wrap=True),
            ft.Text("Mode", weight=ft.FontWeight.BOLD),
            ft.Row([flag("dry_run", "Simulation (aucun fichier écrit)"),
                    flag("analyze_only", "Analyse seule (aucune photo conservée)")], wrap=True),
        ], spacing=12)

    def build_extensions():
        selected = state["extensions"]
        tiles = []
        for category, exts in CATEGORIES_EXTENSIONS.items():
            checks = [ft.Checkbox(label=f".{e}", value=e in selected,
                                  on_change=lambda ev, x=e: toggle_extensions([x], ev.control.value)) for e in exts]
            tiles.append(ft.ExpansionTile(
                title=ft.Text(category, weight=ft.FontWeight.BOLD),
                subtitle=ft.Text(f"{len(exts)} types"),
                leading=ft.Icon(ft.Icons.FOLDER_OUTLINED, color=ft.Colors.ORANGE),
                controls=cast(list[ft.Control], [
                    ft.Row(cast(list[ft.Control], [
                        ft.TextButton("Tout sélectionner", on_click=lambda e, xs=exts: toggle_extensions(xs, True)),
                        ft.TextButton("Tout désélectionner", on_click=lambda e, xs=exts: toggle_extensions(xs, False)),
                    ])),
                    ft.Row(cast(list[ft.Control], checks), wrap=True),
                ])))
        return ft.Column([
            ft.Text("Quels types de fichiers récupérer ?", size=20, weight=ft.FontWeight.BOLD),
            ft.Text(f"{len(selected)} type(s) sélectionné(s)", color=ft.Colors.ORANGE),
            *tiles,
        ], spacing=8)

    def toggle_extensions(exts, checked):
        if checked:
            state["extensions"].update(exts)
        else:
            state["extensions"].difference_update(exts)
        show_wizard()

    def pick_image(e):
        try:
            path = native_pick("file", "Pumpkin Carver - Sélectionner une image disque", str(BASE_DIR))
        except PumpkinError as ex:
            notify(str(ex))
            return
        if path:
            select_image(path)

    def select_image(path):
        state["image_path"] = path
        show_wizard()

    def pick_output(e):
        try:
            path = native_pick("dir", "Pumpkin Carver - Choisir le dossier de sortie",
                               state["output_dir"] if os.path.isdir(state["output_dir"]) else str(BASE_DIR))
        except PumpkinError as ex:
            notify(str(ex))
            return
        if path:
            state["output_dir"] = path
            show_wizard()

    def reset_output():
        state["output_dir"] = str(BASE_DIR)
        show_wizard()

    def find_existing_images():
        exts = {".img", ".dd", ".raw", ".iso", ".dmg", ".bin", ".001"}
        try:
            return sorted((p for p in BASE_DIR.iterdir() if p.is_file() and p.suffix.lower() in exts),
                          key=lambda p: p.stat().st_mtime, reverse=True)
        except OSError:
            return []

    def validate_step(step_name):
        if step_name == "media" and not state["media_type"]:
            notify("Sélectionnez Carte SD ou Clé USB.")
            return False
        if step_name == "disk" and not state["volume"]:
            notify("Sélectionnez un volume dans la liste.")
            return False
        if step_name == "image" and not (state["image_path"] and Path(state["image_path"]).is_file()):
            notify("Sélectionnez un fichier image existant.")
            return False
        if step_name == "extensions" and not state["extensions"]:
            notify("Sélectionnez au moins un type de fichier.")
            return False
        if step_name == "options":
            try:
                parse_options(state["options"])
            except PumpkinError as ex:
                notify(str(ex))
                return False
        if step_name == "output" and not os.path.isdir(state["output_dir"]):
            notify("Le dossier de sortie n'existe pas.")
            return False
        return True

    def build_cfg(preset):
        v = state["volume"]
        return {"preset": preset, "device": v["device"] if v else None,
                "image": state["image_path"], "output_dir": state["output_dir"],
                "exts": sorted(state["extensions"]), "options": parse_options(state["options"])}

    def show_summary(preset):
        rows = [ft.Text("Vérifiez votre configuration", size=24, weight=ft.FontWeight.BOLD),
                ft.Text(f"Mode : {LABELS[preset]}")]
        if preset in ("full", "setup"):
            rows += [ft.Text(f"Support : {media_label()}"),
                     ft.Text(f"Volume : {state['volume']['label'] if state['volume'] else '—'}", selectable=True),
                     ft.Text(f"Taille : {format_bytes(state['volume']['total']) if state['volume'] else 'inconnue'}")]
        else:
            rows.append(ft.Text(f"Image source : {state['image_path']}", selectable=True))
        if preset != "setup":
            rows.append(ft.Text("Types : " + (", ".join("." + x for x in sorted(state["extensions"])) or "aucun")))
        perf_label = ("Automatique" if state["options"].get("auto_optimize", True)
                      else f"{state['options']['workers']} processus / blocs {state['options']['chunk_mib']} Mio")
        gpu_label = "CPU multi-processus optimisé"
        rows.append(ft.Text(f"Performances : {perf_label} • {gpu_label} • Dossier : {state['output_dir']}",
                            selectable=True))
        confirm = ft.Checkbox(label="Je confirme que le volume et le dossier de sortie sont corrects", value=False)

        def launch(e):
            if preset != "image_only" and not confirm.value:
                notify("Cochez la confirmation avant de lancer.")
                return
            try:
                cfg = build_cfg(preset)
            except PumpkinError as ex:
                notify(str(ex))
                return
            show_run(LABELS[preset], lambda log, prog, cancel: run_workflow(cfg, log, prog, cancel))

        show_view(LABELS[preset], [
            app_header("Résumé"),
            outlined_card(ft.Column(cast(list[ft.Control], [*rows, ft.Divider(), confirm]), spacing=12)),
            ft.Row([
                ft.OutlinedButton("Modifier", icon=ft.Icons.ARROW_BACK, on_click=lambda e: _edit_last(preset)),
                ft.Button("Lancer", icon=ft.Icons.PLAY_ARROW, on_click=launch)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ])

    def _edit_last(preset):
        state["step"] = len(get_steps(preset)) - 1
        show_wizard()

    # ----- Exécution et résultats -------------------------------------------

    def show_run(title, runner):
        cancel_event = threading.Event()
        events: queue.Queue[tuple[str, object]] = queue.Queue()
        # La progression est une valeur d'état, pas un événement à conserver à chaque
        # bloc lu : le worker remplace la dernière valeur et l'UI ne peint qu'à cadence fixe.
        progress_lock = threading.Lock()
        latest_progress: list[tuple[float | None, str] | None] = [None]
        status = ft.Text("Préparation…", selectable=True)
        bar = ft.ProgressBar(value=None, color=ft.Colors.ORANGE)
        log_view = ft.ListView(expand=True, spacing=2, auto_scroll=True, height=220)
        results_holder = ft.Column(spacing=8)

        def request_cancel(e):
            cancel_event.set()
            status.value = "Annulation demandée…"
            page.update()

        cancel_btn = ft.OutlinedButton("Annuler", icon=ft.Icons.STOP, on_click=request_cancel)
        back_btn = ft.OutlinedButton("Retour au tableau de bord", icon=ft.Icons.ARROW_BACK,
                                     on_click=lambda e: show_dashboard(), disabled=True)

        # Les callbacks du moteur ne touchent plus directement aux contrôles Flet.
        # Ils déposent des événements, appliqués ensuite par la tâche UI asynchrone.
        def log(message):
            events.put(("log", str(message)))

        def progress(frac, label):
            with progress_lock:
                latest_progress[0] = (frac, str(label))

        def worker():
            try:
                summary = runner(log, progress, cancel_event) or {}
                events.put(("finish", summary))
            except PumpkinError as ex:
                events.put(("error", f"Erreur : {ex}"))
                log(f"ERREUR : {ex}")
            except Exception as ex:
                events.put(("error", f"Erreur inattendue : {ex}"))
                log(f"ERREUR INATTENDUE : {ex}")
                log(traceback.format_exc()[-800:])
            finally:
                events.put(("worker_done", None))

        async def pump_ui():
            worker_finished = False
            while True:
                changed = False
                while True:
                    try:
                        kind, payload = events.get_nowait()
                    except queue.Empty:
                        break

                    if kind == "log":
                        log_view.controls.append(ft.Text(str(payload), size=12, selectable=True))
                        if len(log_view.controls) > 600:
                            del log_view.controls[:150]
                        changed = True
                    elif kind == "finish":
                        summary = payload if isinstance(payload, dict) else {}
                        status.value = summary.get("message", "Terminé.")
                        if summary.get("status") == "done":
                            bar.value = 1
                        if summary.get("csv"):
                            results_holder.controls.extend(results_block(summary["csv"]))
                        changed = True
                    elif kind == "error":
                        status.value = str(payload)
                        changed = True
                    elif kind == "worker_done":
                        worker_finished = True
                        cancel_btn.disabled = True
                        back_btn.disabled = False
                        changed = True

                # Ne prendre que la dernière progression publiée : les calculs ne
                # sont jamais ralentis par une file de milliers d'actualisations.
                with progress_lock:
                    progress_update = latest_progress[0]
                    latest_progress[0] = None
                if progress_update is not None:
                    frac, label = progress_update
                    status.value = label
                    if frac is not None:
                        bar.value = max(0.0, min(1.0, frac))
                    changed = True

                if changed:
                    try:
                        page.update()
                    except Exception as ex:
                        print(f"[interface] mise à jour impossible : {ex}", file=sys.stderr)

                if worker_finished and events.empty():
                    break
                # Cadence d'affichage indépendante du calcul : ~10 rafraîchissements/s.
                # Les événements de progression intermédiaires sont volontairement fusionnés.
                await asyncio.sleep(0.1)

        show_view(title, [
            app_header("Exécution"),
            ft.Row([ft.ProgressRing(width=18, height=18, stroke_width=2), status], spacing=12),
            bar,
            ft.Row([cancel_btn, back_btn]),
            ft.Text("Journal", weight=ft.FontWeight.BOLD),
            log_view,
            results_holder,
        ])
        threading.Thread(target=worker, daemon=True).start()
        page.run_task(pump_ui)

    def results_block(csv_path):
        csv_path = Path(csv_path)
        if not csv_path.exists():
            return [ft.Text("Aucun rapport disponible.", color=ft.Colors.OUTLINE)]
        with open(csv_path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        sort = {"key": "file", "reverse": False}
        listing = ft.Column(spacing=4)

        def render():
            listing.controls.clear()
            ordered = sorted(rows, key=lambda r: _sort_value(r, sort["key"]), reverse=sort["reverse"])
            for r in ordered[:500]:
                detail = " • ".join(x for x in (r.get("validation"), r.get("excluded_reason"),
                                                r.get("anomaly_reason")) if x)
                listing.controls.append(ft.Container(ft.Row([
                    ft.Container(ft.Text(f"{r.get('folder', '')}/{r.get('file', '')}", selectable=True,
                                         max_lines=2, overflow=ft.TextOverflow.ELLIPSIS), expand=3),
                    ft.Container(ft.Text(r.get("type", "")), width=60),
                    ft.Container(ft.Text(_size_label(r.get("size_bytes"))), width=100),
                    ft.Container(ft.Text(detail or "—"), expand=2),
                ]), padding=8, border=ft.Border(bottom=ft.BorderSide(1, ft.Colors.OUTLINE_VARIANT))))
            if len(rows) > 500:
                listing.controls.append(ft.Text("Affichage limité aux 500 premières lignes ; le CSV est complet."))

        def on_sort(e):
            sort["key"] = e.control.value
            render()
            listing.update()

        def on_reverse(e):
            sort["reverse"] = not sort["reverse"]
            render()
            listing.update()

        render()
        return [
            ft.Text("Résultats", size=20, weight=ft.FontWeight.BOLD),
            ft.Row([
                ft.Text(f"{len(rows)} entrée(s) dans le rapport", weight=ft.FontWeight.BOLD),
                ft.Dropdown(label="Trier par", value="file", width=190, on_select=on_sort, options=[
                    ft.dropdown.Option("file", "Nom"), ft.dropdown.Option("type", "Format"),
                    ft.dropdown.Option("size_bytes", "Taille"), ft.dropdown.Option("offset_decimal", "Offset"),
                    ft.dropdown.Option("validation", "Validation"), ft.dropdown.Option("duration_sec", "Durée")]),
                ft.IconButton(ft.Icons.SWAP_VERT, tooltip="Inverser le tri", on_click=on_reverse),
            ], wrap=True),
            listing,
        ]

    def _sort_value(r, key):
        v = r.get(key) or ""
        if key in ("size_bytes", "offset_decimal", "duration_sec"):
            try:
                return float(v)
            except ValueError:
                return -1.0
        return str(v).lower()

    if config.get("first_time", True):
        show_welcome()
    else:
        show_dashboard()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--pick":
        _native_picker(sys.argv[2:])
        sys.exit(0)
    try:
        ft.run(main)
    except KeyboardInterrupt:
        sys.exit(130)