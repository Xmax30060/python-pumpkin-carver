#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Récupération/carving prudent depuis une image disque existante (.img/.dd/.raw).

- Source ouverte STRICTEMENT en lecture seule ; la taille de l'image est
  revérifiée après le scan comme garde-fou.
- Scan parallèle des signatures par blocs, avec recouvrement pour ne pas
  manquer une signature à cheval sur deux blocs.
- Contrôle structurel par format (JPEG, PNG, GIF, BMP, PDF), validation Pillow
  si disponible (jamais obligatoire).
- Réparation séparée des JPEG tronqués ; l'extraction brute n'est jamais écrasée.
- SHA-256 de chaque fichier extrait pour la déduplication.
- Reprise sur interruption via --resume (le manifeste JSONL sert de point de contrôle).
- Manifeste JSONL, rapport HTML, CSV et planches-contact si Pillow est disponible.

Limite : ne reconstruit pas les fichiers fragmentés. Ce script ne remplace pas
un outil de forensique certifié pour un usage judiciaire.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import html
import json
import logging
import os
import re
import shutil
import struct
import sys
import tempfile
import time
import traceback
from concurrent.futures import ProcessPoolExecutor, as_completed
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    from PIL import Image, ImageDraw, ImageFile
except ImportError:  # Pillow est optionnel
    Image = None
    ImageDraw = None
    ImageFile = None

# --------------------------------------------------------------------------- #
# Constantes
# --------------------------------------------------------------------------- #

MIB = 1024 * 1024
GIB = 1024 * MIB

SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("jpg", b"\xff\xd8\xff"),
    ("png", b"\x89PNG\r\n\x1a\n"),
    ("pdf", b"%PDF-"),
    ("gif", b"GIF87a"),
    ("gif", b"GIF89a"),
    ("bmp", b"BM"),
)
MAX_SIZES = {
    "jpg": 256 * MIB,
    "png": 512 * MIB,
    "pdf": 512 * MIB,
    "gif": 128 * MIB,
    "bmp": 256 * MIB,
}
OVERLAP = max(len(sig) for _, sig in SIGNATURES) - 1
JPEG_SOF = frozenset(
    {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
)
JPEG_STANDALONE = frozenset({0x00, 0x01, 0xD8} | set(range(0xD0, 0xD8)))
ENTROPY_MARKER = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")
PHOTO_FORMATS = frozenset({"jpg", "png", "gif", "bmp"})
HASH_CHUNK = 8 * MIB
WRITE_CHUNK = 8 * MIB
MANIFEST_SCHEMA_VERSION = 2

EXIF_TAG_DATETIME_ORIGINAL = 36867
EXIF_TAG_DATETIME_DIGITIZED = 36868
EXIF_TAG_DATETIME = 306
EXIF_TAG_SUBSEC_ORIGINAL = 37521
EXIF_TAG_MAKE = 271
EXIF_TAG_MODEL = 272
EXIF_TAG_SERIAL = 42033
EXIF_TAG_SOFTWARE = 305
EXIF_TAG_ORIG_FILENAME = 42016
EXIF_TAG_THUMB_OFFSET = 513
EXIF_TAG_THUMB_LENGTH = 514
EXIF_TAG_IMAGE_WIDTH = 256
EXIF_TAG_IMAGE_HEIGHT = 257
EXIF_TAG_PIXEL_X = 40962
EXIF_TAG_PIXEL_Y = 40963
EXIF_IFD_PRIVATE = 0x8769
EXIF_IFD_1 = 0x0001

EXIF_FIELDS = (
    "exif_datetime_original",
    "exif_datetime_digitized",
    "exif_subsec_original",
    "exif_camera_make",
    "exif_camera_model",
    "exif_camera_serial",
    "exif_software",
    "exif_image_unique_id",
    "exif_full_width",
    "exif_full_height",
    "has_embedded_thumbnail",
    "embedded_thumbnail_offset_in_file",
    "embedded_thumbnail_length",
)

# Exceptions attendues lors de l'ouverture/décodage Pillow.
_BOMB_ERROR = getattr(Image, "DecompressionBombError", OSError)
PIL_ERRORS = (
    OSError,
    ValueError,
    SyntaxError,
    TypeError,
    AttributeError,
    KeyError,
    IndexError,
    _BOMB_ERROR,
)

log = logging.getLogger("recup_after")


# --------------------------------------------------------------------------- #
# Erreurs dédiées
# --------------------------------------------------------------------------- #


class RecupError(Exception):
    """Erreur attendue, destinée à être affichée proprement à l'utilisateur."""


class SourceIntegrityError(RecupError):
    """L'image source semble avoir changé pendant l'exécution (garde-fou)."""


# --------------------------------------------------------------------------- #
# Lecture bas niveau
# --------------------------------------------------------------------------- #


def _read_at(f, pos: int, size: int) -> bytes:
    """Lit `size` octets à la position `pos`."""
    f.seek(pos)
    return f.read(size)


# --------------------------------------------------------------------------- #
# Scan des signatures (multi-processus)
# --------------------------------------------------------------------------- #


def scan_range(job: tuple[str, int, int, int]) -> list[tuple[int, str]]:
    """Cherche toutes les signatures connues dans [start, stop) d'un fichier."""
    path, start, stop, chunk_size = job
    found: list[tuple[int, str]] = []
    try:
        with open(path, "rb", buffering=0) as f:
            f.seek(start)
            carry = b""
            pos = start
            while pos < stop:
                block = f.read(min(chunk_size, stop - pos))
                if not block:
                    break
                data = carry + block
                base = pos - len(carry)
                for ext, sig in SIGNATURES:
                    i = data.find(sig)
                    while i >= 0:
                        absolute = base + i
                        if start <= absolute < stop:
                            found.append((absolute, ext))
                        i = data.find(sig, i + 1)
                carry = data[-OVERLAP:] if OVERLAP else b""
                pos += len(block)
    except OSError as e:
        raise RecupError(
            f"Échec de lecture du bloc [{start}:{stop}] : {e}"
        ) from e
    return found


def scan_signatures(
    path: Path, workers: int, chunk_size: int, progress_cb=None
) -> tuple[list[tuple[int, str]], int]:
    """Scanne l'image en parallèle et retourne (candidats triés, taille)."""
    size = path.stat().st_size
    if size == 0:
        return [], 0
    jobs = [
        (str(path), s, min(size, s + chunk_size), chunk_size)
        for s in range(0, size, chunk_size)
    ]
    found: list[tuple[int, str]] = []
    done = 0
    total = len(jobs)
    log.info("Image : %s (%.2f Gio)", path, size / GIB)
    log.info(
        "Scan : %d processus, blocs de %.0f Mio, %d tâches",
        workers,
        chunk_size / MIB,
        total,
    )
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_range, j) for j in jobs]
        try:
            for fut in as_completed(futures):
                found.extend(fut.result())
                done += 1
                if progress_cb and (
                    done == total or done % max(1, total // 100) == 0
                ):
                    progress_cb(done, total)
        except RecupError:
            for fut in futures:
                fut.cancel()
            raise
    return sorted(set(found)), size


# --------------------------------------------------------------------------- #
# Parsers de longueur par format
# --------------------------------------------------------------------------- #


def find_marker(
    f, offset: int, limit: int, marker: bytes, start_after: int = 0
) -> Optional[int]:
    """Retourne la position relative (à offset) juste après `marker`, ou None."""
    cursor = offset + start_after
    carry = b""
    while cursor < limit:
        block = _read_at(f, cursor, min(4 * MIB, limit - cursor))
        if not block:
            return None
        data = carry + block
        idx = data.find(marker)
        if idx >= 0:
            return cursor - len(carry) + idx + len(marker) - offset
        carry = data[-max(1, len(marker) - 1) :]
        cursor += len(block)
    return None


def _dims_plausible(width: int, height: int) -> bool:
    """Vérifie qu'une paire de dimensions d'image est raisonnable."""
    return (
        1 <= width <= 100_000
        and 1 <= height <= 100_000
        and width * height <= 500_000_000
    )


def _find_next_marker(f, pos: int, limit: int) -> tuple[Optional[int], int]:
    """Retourne (code du marqueur, position juste après le code) ou (None, pos)."""
    while pos < limit:
        window = _read_at(f, pos, 64)
        if not window:
            return None, pos
        idx = window.find(b"\xff")
        if idx < 0:
            pos += len(window)
            continue
        p = pos + idx + 1
        while True:
            code = _read_at(f, p, 1)
            if not code:
                return None, p
            if code != b"\xff":
                return code[0], p + 1
            p += 1
    return None, pos


def _parse_sof_payload(payload: bytes) -> Optional[tuple[int, int]]:
    """Extrait (largeur, hauteur) d'un segment SOF."""
    if len(payload) < 5:
        return None
    height, width = struct.unpack(">HH", payload[1:5])
    if not _dims_plausible(width, height):
        return None
    return width, height


def jpeg_dimensions(
    f, offset: int, max_end: int, header_scan_limit: int = 8 * MIB
) -> Optional[tuple[int, int]]:
    """Parse les marqueurs JPEG jusqu'au SOF et retourne (largeur, hauteur)."""
    if _read_at(f, offset, 2) != b"\xff\xd8":
        return None
    pos = offset + 2
    limit = min(max_end, offset + header_scan_limit)
    while pos + 4 <= limit:
        marker, pos = _find_next_marker(f, pos, limit)
        if marker is None or marker == 0xDA:  # SOS : pas de SOF avant les données
            return None
        if marker in JPEG_STANDALONE or marker == 0xD9:
            continue
        raw = f.read(2)
        if len(raw) != 2:
            return None
        seglen = struct.unpack(">H", raw)[0]
        if seglen < 2 or pos + seglen > limit:
            return None
        if marker in JPEG_SOF:
            return _parse_sof_payload(f.read(min(seglen - 2, 8)))
        pos += seglen
    return None


def _find_entropy_end(f, start: int, limit: int) -> Optional[int]:
    """Retourne la position du prochain marqueur réel après des données compressées."""
    pos = start
    carry = b""
    while pos < limit:
        block = _read_at(f, pos, min(MIB, limit - pos))
        if not block:
            return None
        data = carry + block
        match = ENTROPY_MARKER.search(data)
        if match:
            return pos - len(carry) + match.start()
        carry = data[-1:] if data[-1:] == b"\xff" else b""
        pos += len(block)
    return None


def _find_jpeg_eoi(f, offset: int, limit: int) -> Optional[int]:
    """Retourne la longueur jusqu'au vrai marqueur EOI en respectant les segments."""
    if _read_at(f, offset, 2) != b"\xff\xd8":
        return None
    pos = offset + 2
    while pos < limit:
        marker = _find_next_marker(f, pos, limit)
        code, after = marker
        if code is None:
            return None
        if code == 0xD9:
            return after - offset
        if code in JPEG_STANDALONE:
            pos = after
            continue
        raw = _read_at(f, after, 2)
        if len(raw) != 2:
            return None
        seg_len = struct.unpack(">H", raw)[0]
        if seg_len < 2:
            return None
        seg_end = after + seg_len
        if seg_end > limit:
            return None
        if code != 0xDA:
            pos = seg_end
            continue
        entropy_end = _find_entropy_end(f, seg_end, limit)
        if entropy_end is None:
            return None
        pos = entropy_end
    return None


@dataclass
class SalvageConfig:
    """Paramètres de sauvetage des JPEG tronqués sans marqueur de fin."""

    enabled: bool = True
    min_size: int = 4096
    max_size: int = 64 * MIB


def jpeg_length(
    f,
    offset: int,
    image_size: int,
    next_jpeg: Optional[int],
    salvage: SalvageConfig,
) -> tuple[Optional[int], Optional[str]]:
    """Retourne (longueur, 'end_marker' | 'truncated') ou (None, None)."""
    limit = min(image_size, offset + MAX_SIZES["jpg"])
    end = _find_jpeg_eoi(f, offset, limit)
    if end is not None:
        return end, "end_marker"
    if not salvage.enabled:
        return None, None
    if next_jpeg is not None:
        length = next_jpeg - offset
        if (
            salvage.min_size <= length <= salvage.max_size
            and offset + length <= image_size
        ):
            return length, "truncated"
        return None, None
    remaining = min(image_size - offset, salvage.max_size, MAX_SIZES["jpg"])
    if salvage.min_size <= remaining <= image_size - offset:
        return remaining, "truncated"
    return None, None


def png_length(f, offset: int, image_size: int) -> Optional[int]:
    """Calcule la longueur d'un PNG en parcourant ses chunks jusqu'à IEND."""
    if _read_at(f, offset, 8) != b"\x89PNG\r\n\x1a\n":
        return None
    cur = offset + 8
    limit = min(image_size, offset + MAX_SIZES["png"])
    while cur + 12 <= limit:
        h = _read_at(f, cur, 8)
        if len(h) != 8:
            return None
        n = struct.unpack(">I", h[:4])[0]
        typ = h[4:]
        if n > MAX_SIZES["png"] or cur + 12 + n > limit:
            return None
        cur += 12 + n
        if typ == b"IEND":
            return cur - offset if n == 0 else None
    return None


def gif_length(f, offset: int, image_size: int) -> Optional[int]:
    """Calcule la longueur d'un GIF jusqu'à son terminateur 0x3B."""
    if _read_at(f, offset, 6) not in (b"GIF87a", b"GIF89a"):
        return None
    n = find_marker(
        f, offset, min(image_size, offset + MAX_SIZES["gif"]), b"\x3b", 6
    )
    return n if n is not None and n >= 14 else None


_BMP_DIB_SIZES = frozenset({12, 40, 52, 56, 64, 108, 124})
_BMP_BPP = frozenset({1, 2, 4, 8, 16, 24, 32})
_BMP_COMP = frozenset({0, 1, 2, 3, 6})


def _bmp_header_ok(size: int, pix: int, dib: int, offset: int, image_size: int) -> bool:
    """Contrôle les champs d'en-tête BMP de base."""
    return (
        dib in _BMP_DIB_SIZES
        and size >= 26
        and size <= MAX_SIZES["bmp"]
        and pix >= 14 + dib
        and pix < size
        and size <= image_size - offset
    )


def _bmp_pixel_info(h: bytes, dib: int) -> tuple[int, int, int, int, int]:
    """Retourne (largeur, hauteur, planes, bpp, compression) selon le type DIB."""
    if dib == 12:
        width, height = struct.unpack_from("<HH", h, 18)
        planes, bpp = struct.unpack_from("<HH", h, 22)
        return width, height, planes, bpp, 0
    width, height = struct.unpack_from("<ii", h, 18)
    planes, bpp = struct.unpack_from("<HH", h, 26)
    comp = struct.unpack_from("<I", h, 30)[0]
    return width, height, planes, bpp, comp


def _bmp_pixels_ok(
    width: int,
    height: int,
    planes: int,
    bpp: int,
    comp: int,
    pix: int,
    size: int,
) -> bool:
    """Contrôle la cohérence des champs de pixels."""
    if (
        width == 0
        or height == 0
        or abs(width) > 100_000
        or abs(height) > 100_000
        or planes != 1
        or bpp not in _BMP_BPP
        or comp not in _BMP_COMP
    ):
        return False
    row = ((abs(width) * bpp + 31) // 32) * 4
    return not (comp == 0 and pix + row * abs(height) > size)


def bmp_length(f, offset: int, image_size: int) -> Optional[int]:
    """Valide l'en-tête BMP et retourne la taille déclarée."""
    h = _read_at(f, offset, 54)
    if len(h) < 34 or h[:2] != b"BM":
        return None
    size = struct.unpack_from("<I", h, 2)[0]
    pix = struct.unpack_from("<I", h, 10)[0]
    dib = struct.unpack_from("<I", h, 14)[0]
    if not _bmp_header_ok(size, pix, dib, offset, image_size):
        return None
    if not _bmp_pixels_ok(*_bmp_pixel_info(h, dib), pix, size):
        return None
    return size


def pdf_length(f, offset: int, image_size: int) -> Optional[int]:
    """Retourne la position après le dernier %%EOF du PDF."""
    limit = min(image_size, offset + MAX_SIZES["pdf"])
    if _read_at(f, offset, 5) != b"%PDF-":
        return None
    cur = offset + 5
    tail = b""
    last = None
    while cur < limit:
        block = _read_at(f, cur, min(4 * MIB, limit - cur))
        if not block:
            break
        data = tail + block
        p = 0
        while True:
            i = data.find(b"%%EOF", p)
            if i < 0:
                break
            candidate = cur - len(tail) + i + 5 - offset
            if candidate >= 16:
                last = candidate
            p = i + 5
        tail = data[-4:]
        cur += len(block)
    return last


# --------------------------------------------------------------------------- #
# EXIF et classification des miniatures
# --------------------------------------------------------------------------- #


def empty_exif() -> dict:
    """Dictionnaire EXIF vide (valeurs par défaut)."""
    out = dict.fromkeys(EXIF_FIELDS)
    out["has_embedded_thumbnail"] = False
    return out


def _clean_exif_str(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = str(value).replace("\x00", "").strip()
    return value or None


def _safe_ifd(exif, tag: int) -> dict:
    """Retourne l'IFD demandé ou un dict vide si indisponible."""
    try:
        return exif.get_ifd(tag) or {}
    except PIL_ERRORS:
        return {}


def _fill_exif_basic(out: dict, exif) -> None:
    out["exif_datetime_original"] = exif.get(EXIF_TAG_DATETIME_ORIGINAL) or exif.get(
        EXIF_TAG_DATETIME
    )
    out["exif_datetime_digitized"] = exif.get(EXIF_TAG_DATETIME_DIGITIZED)
    out["exif_subsec_original"] = _clean_exif_str(exif.get(EXIF_TAG_SUBSEC_ORIGINAL))
    out["exif_camera_make"] = _clean_exif_str(exif.get(EXIF_TAG_MAKE))
    out["exif_camera_model"] = _clean_exif_str(exif.get(EXIF_TAG_MODEL))
    out["exif_camera_serial"] = _clean_exif_str(exif.get(EXIF_TAG_SERIAL))
    out["exif_software"] = _clean_exif_str(exif.get(EXIF_TAG_SOFTWARE))
    out["exif_image_unique_id"] = _clean_exif_str(exif.get(EXIF_TAG_ORIG_FILENAME))


def _fill_exif_dimensions(out: dict, exif) -> None:
    exif_ifd = _safe_ifd(exif, EXIF_IFD_PRIVATE)
    if exif_ifd:
        out["exif_full_width"] = exif_ifd.get(EXIF_TAG_PIXEL_X) or exif_ifd.get(
            EXIF_TAG_IMAGE_WIDTH
        )
        out["exif_full_height"] = exif_ifd.get(EXIF_TAG_PIXEL_Y) or exif_ifd.get(
            EXIF_TAG_IMAGE_HEIGHT
        )


def _fill_exif_thumbnail(out: dict, exif) -> None:
    ifd1 = _safe_ifd(exif, EXIF_IFD_1)
    thumb_off = ifd1.get(EXIF_TAG_THUMB_OFFSET)
    thumb_len = ifd1.get(EXIF_TAG_THUMB_LENGTH)
    if thumb_off and thumb_len:
        out["has_embedded_thumbnail"] = True
        out["embedded_thumbnail_offset_in_file"] = thumb_off
        out["embedded_thumbnail_length"] = thumb_len


def extract_exif_metadata(path: Path) -> dict:
    """Extrait les métadonnées EXIF sans exiger le décodage complet des pixels."""
    out = empty_exif()
    if Image is None:
        return out
    try:
        with Image.open(path) as im:
            exif = im.getexif()
            if exif:
                _fill_exif_basic(out, exif)
                _fill_exif_dimensions(out, exif)
                _fill_exif_thumbnail(out, exif)
    except PIL_ERRORS as e:
        log.debug("Lecture EXIF échouée pour %s : %s", path.name, e)
    return out


def _positive_int(value) -> Optional[int]:
    """Convertit en entier strictement positif, sinon None."""
    try:
        n = int(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return n if n > 0 else None


def _role_from_exif(w: int, h: int, full_w: int, full_h: int) -> Optional[str]:
    """Classe à partir des dimensions EXIF pleines comparées aux dimensions du flux."""
    ratio_w = full_w / max(w, 1)
    ratio_h = full_h / max(h, 1)
    same_aspect = abs((full_w / full_h) - (w / h)) <= 0.08
    if same_aspect and ratio_w >= 1.5 and ratio_h >= 1.5 and max(w, h) <= 1600:
        return "likely_thumbnail"
    if abs(full_w - w) / full_w <= 0.12 and abs(full_h - h) / full_h <= 0.12:
        return "likely_original"
    return None


def _role_from_header(
    max_dim: int,
    pixels: int,
    size: int,
    thumbnail_max_dim: int,
    thumbnail_max_bytes: int,
) -> Optional[str]:
    """Classe à partir des seules dimensions et de la taille du flux."""
    very_small = max_dim <= 320 and size <= 128 * 1024 and pixels <= 100_000
    small_thumbnail = (
        max_dim <= thumbnail_max_dim
        and size <= thumbnail_max_bytes
        and pixels <= 300_000
    )
    compact_thumbnail = max_dim <= 800 and size <= 48 * 1024 and pixels <= 250_000
    if very_small or small_thumbnail or compact_thumbnail:
        return "likely_thumbnail"
    if (
        max_dim >= 1200
        or pixels >= 1_000_000
        or (max_dim >= 900 and size >= 96 * 1024)
        or (max_dim >= 700 and size >= 256 * 1024)
    ):
        return "likely_original"
    return None


def classify_jpeg_role(
    carved_size: int,
    dims_header: Optional[tuple],
    exif: dict,
    thumbnail_max_dim: int = 640,
    thumbnail_max_bytes: int = 64 * 1024,
) -> str:
    """Classe le JPEG avec une priorité forte au rappel des originaux."""
    full_w = _positive_int(exif.get("exif_full_width"))
    full_h = _positive_int(exif.get("exif_full_height"))
    w, h = dims_header if dims_header else (None, None)
    w, h = _positive_int(w), _positive_int(h)

    if w is not None and h is not None:
        if full_w is not None and full_h is not None:
            role = _role_from_exif(w, h, full_w, full_h)
            if role:
                return role
        role = _role_from_header(
            max(w, h),
            w * h,
            carved_size,
            thumbnail_max_dim,
            thumbnail_max_bytes,
        )
        if role:
            return role

    if carved_size >= 512 * 1024:
        return "likely_original"
    return "unknown"


def _dims_match(full_w, full_h, cand_w, cand_h) -> bool:
    """Compare deux paires de dimensions avec une tolérance de 3 %."""
    if not (full_w and full_h and cand_w and cand_h):
        return False
    try:
        return abs(int(full_w) - int(cand_w)) <= max(16, int(cand_w) * 0.03) and abs(
            int(full_h) - int(cand_h)
        ) <= max(16, int(cand_h) * 0.03)
    except (TypeError, ValueError, OverflowError):
        return False


def _has_matching_evidence(thumb: dict, candidate: dict, distance: int) -> bool:
    """Un lien éloigné n'est retenu que si les métadonnées concordent."""
    if distance <= 2 * MIB:
        return True
    for key in ("exif_datetime_original", "exif_camera_serial"):
        a, b = thumb.get(key), candidate.get(key)
        if a and b and str(a) == str(b):
            return True
    return _dims_match(
        thumb.get("exif_full_width"),
        thumb.get("exif_full_height"),
        candidate.get("width"),
        candidate.get("height"),
    )


def _link_one_thumbnail(
    rec: dict,
    jpgs: list[dict],
    offsets: list[int],
    valid_originals: list[dict],
    valid_offsets: list[int],
    max_distance: int,
) -> None:
    """Relie une vignette à ses candidats voisins et à ses originaux validés."""
    center = rec.get("offset_decimal", 0)
    lo = bisect.bisect_left(offsets, center - max_distance)
    hi = bisect.bisect_right(offsets, center + max_distance)
    nearby = [
        jpgs[j]
        for j in range(lo, hi)
        if jpgs[j] is not rec
        and jpgs[j].get("jpeg_role") in ("likely_original", "unknown")
    ]
    nearby.sort(key=lambda c: abs(c.get("offset_decimal", 0) - center))
    rec["linked_candidate_offsets_hex"] = [c.get("offset_hex") for c in nearby[:20]]
    rec["linked_candidate_count"] = len(nearby)

    vlo = bisect.bisect_left(valid_offsets, center - max_distance)
    vhi = bisect.bisect_right(valid_offsets, center + max_distance)
    linked_valid = [
        c
        for c in valid_originals[vlo:vhi]
        if _has_matching_evidence(
            rec, c, abs(c.get("offset_decimal", 0) - center)
        )
    ]
    linked_valid.sort(key=lambda c: abs(c.get("offset_decimal", 0) - center))
    rec["linked_validated_original_offsets_hex"] = [
        c.get("offset_hex") for c in linked_valid[:20]
    ]
    rec["linked_validated_original_count"] = len(linked_valid)
    rec["has_validated_original_association"] = bool(linked_valid)


def link_thumbnails_to_candidates(
    records: list[dict], max_distance: int = 64 * MIB
) -> None:
    """Relie les vignettes aux candidats JPEG voisins (indicatif uniquement)."""
    jpgs = sorted(
        (r for r in records if r.get("type") == "jpg"),
        key=lambda r: r.get("offset_decimal", 0),
    )
    offsets = [r.get("offset_decimal", 0) for r in jpgs]
    valid_originals = [
        r
        for r in jpgs
        if r.get("validation") == "valid" and r.get("jpeg_role") == "likely_original"
    ]
    valid_offsets = [r.get("offset_decimal", 0) for r in valid_originals]

    for rec in jpgs:
        rec.setdefault("linked_candidate_offsets_hex", [])
        rec.setdefault("linked_candidate_count", 0)
        rec["linked_validated_original_offsets_hex"] = []
        rec["linked_validated_original_count"] = 0
        rec["has_validated_original_association"] = False
        if rec.get("jpeg_role") == "likely_thumbnail":
            _link_one_thumbnail(
                rec, jpgs, offsets, valid_originals, valid_offsets, max_distance
            )


# --------------------------------------------------------------------------- #
# Validation / réparation Pillow (optionnelles)
# --------------------------------------------------------------------------- #


def _exif_date(im) -> Optional[str]:
    """Lit la date EXIF d'une image Pillow ouverte, sans lever d'erreur."""
    try:
        ex = im.getexif()
        return ex.get(EXIF_TAG_DATETIME_ORIGINAL) or ex.get(EXIF_TAG_DATETIME)
    except PIL_ERRORS:
        return None


def image_validate(path: Path) -> dict:
    """Valide une image avec Pillow ; retourne un dict de résultats."""
    if Image is None:
        return {
            "validation": "pillow_missing",
            "width": None,
            "height": None,
            "exif_date": None,
            "error": "Pillow absent",
        }
    try:
        with Image.open(path) as im:
            fmt = im.format
            width, height = im.size
            exif_date = _exif_date(im)
            im.verify()
        with Image.open(path) as im:
            im.load()
        return {
            "validation": "valid",
            "width": width,
            "height": height,
            "format": fmt,
            "exif_date": exif_date,
            "error": None,
        }
    except PIL_ERRORS as e:
        return {
            "validation": "invalid",
            "width": None,
            "height": None,
            "exif_date": None,
            "error": str(e)[:300],
        }


def try_repair(source: Path, output: Path) -> tuple[bool, Optional[str]]:
    """Tente de réécrire un JPEG tronqué en le décodant partiellement."""
    if Image is None:
        return False, "Pillow absent"
    old = ImageFile.LOAD_TRUNCATED_IMAGES
    try:
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        with Image.open(source) as im:
            im.load()
            if im.mode not in ("RGB", "L", "RGBA", "CMYK", "P"):
                im = im.convert("RGB")
            output.parent.mkdir(parents=True, exist_ok=True)
            im.save(output, format="JPEG", quality=95)
        return True, None
    except PIL_ERRORS as e:
        _unlink_quietly(output)
        return False, str(e)[:300]
    finally:
        ImageFile.LOAD_TRUNCATED_IMAGES = old


def make_contact_sheet(
    records: list[dict], dest: Path, thumb_size=(180, 135), per_sheet=120
) -> list[str]:
    """Crée des planches-contact JPEG à partir des images validées."""
    if Image is None:
        return []
    paths = [
        dest / r["file"]
        for r in records
        if r.get("saved", True) is not False
        and r.get("type") in PHOTO_FORMATS
        and r.get("validation") in ("valid", "partial_repair_possible")
    ]
    outputs: list[str] = []
    for batchno in range(0, len(paths), per_sheet):
        batch = paths[batchno : batchno + per_sheet]
        cols = 6
        cellw, cellh = 200, 170
        sheet = Image.new(
            "RGB",
            (cols * cellw, ((len(batch) + cols - 1) // cols) * cellh),
            (245, 245, 245),
        )
        draw = ImageDraw.Draw(sheet)
        for i, p in enumerate(batch):
            try:
                with Image.open(p) as im:
                    im.thumbnail(thumb_size)
                    x = (i % cols) * cellw + (cellw - im.width) // 2
                    y = (i // cols) * cellh + 4
                    sheet.paste(im, (x, y))
                    draw.text(
                        ((i % cols) * cellw + 5, (i // cols) * cellh + 143),
                        p.name[:28],
                        fill=(20, 20, 20),
                    )
            except PIL_ERRORS as e:
                log.debug("Vignette ignorée pour %s : %s", p.name, e)
        out = dest / f"planche_contact_{batchno // per_sheet + 1:03d}.jpg"
        sheet.save(out, quality=85)
        outputs.append(out.name)
    return outputs


def _unlink_quietly(path: Optional[Path]) -> None:
    """Supprime un fichier sans lever d'erreur."""
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# État du run
# --------------------------------------------------------------------------- #


@dataclass
class RunStats:
    """Compteurs du run."""

    extracted: int = 0
    rejected: int = 0
    duplicates: int = 0
    counts: dict = field(default_factory=dict)


@dataclass
class RunState:
    """État mutable du run : enregistrements, plages couvertes et hashes vus."""

    stats: RunStats
    records: list
    covered: set
    ranges_strong: list
    ranges_weak: list
    seen_hashes: set


@dataclass
class RunContext:
    """Paramètres constants du run."""

    args: argparse.Namespace
    dest: Path
    src: Path
    image_size: int
    started: float
    jpg_offsets: list
    formats: set


@dataclass
class RunIO:
    """Ressources ouvertes pendant le run."""

    fh: object
    manifest: Optional[object]
    temp_dir: Optional[Path]


def load_existing_manifest(
    manifest_path: Path,
) -> tuple[list[dict], set[int], set[str]]:
    """Relit un manifeste existant pour une reprise."""
    records: list[dict] = []
    seen_hashes: set[str] = set()
    covered_starts: set[int] = set()
    if not manifest_path.exists():
        return records, covered_starts, seen_hashes
    with open(manifest_path, "r", encoding="utf-8") as mf:
        for line in mf:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Ligne de manifeste illisible ignorée (reprise).")
                continue
            records.append(rec)
            covered_starts.add(rec["offset_decimal"])
            if rec.get("sha256"):
                seen_hashes.add(rec["sha256"])
    return records, covered_starts, seen_hashes


def _is_strong(rec: dict) -> bool:
    """Un enregistrement validé (ou non-image) bloque les chevauchements."""
    return rec.get("validation") in ("valid", "not_applicable")


def _span_list(state: RunState, rec: dict) -> list:
    """Retourne la liste de plages (forte ou faible) correspondant à l'enregistrement."""
    return state.ranges_strong if _is_strong(rec) else state.ranges_weak


def _exclude_thumbnail(rec: dict, dest: Path) -> None:
    """Marque une vignette comme exclue et supprime sa réparation éventuelle."""
    if rec.get("repair_file"):
        _unlink_quietly(dest / rec["repair_file"])
    rec["repair_created"] = False
    rec["repair_file"] = None
    rec["saved"] = False
    rec["excluded_reason"] = "likely_thumbnail"


def _is_excludable_thumbnail(rec: dict, args: argparse.Namespace) -> bool:
    """Indique si l'enregistrement est une vignette à exclure."""
    return bool(
        args.exclude_thumbnails
        and rec.get("type") == "jpg"
        and rec.get("jpeg_role") == "likely_thumbnail"
    )


# --------------------------------------------------------------------------- #
# Analyse sommaire FAT/exFAT (lecture seule)
# --------------------------------------------------------------------------- #


# pylint: disable=too-many-instance-attributes
@dataclass
class FatInfo:
    """Paramètres d'un système de fichiers FAT/exFAT détecté."""

    fs_type: str
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size_bytes: int
    reserved_sectors: int
    num_fats: int
    fat_size_sectors: int
    root_cluster: Optional[int]
    data_start_offset: int
    total_sectors: int
    volume_label: Optional[str] = None
    warnings: list = field(default_factory=list)


# pylint: enable=too-many-instance-attributes


def _parse_exfat(boot: bytes) -> Optional[FatInfo]:
    """Analyse un secteur de boot exFAT."""
    bps_shift, spc_shift, num_fats = boot[108], boot[109], boot[110]
    fat_offset = struct.unpack_from("<I", boot, 80)[0]
    fat_length = struct.unpack_from("<I", boot, 84)[0]
    heap_offset = struct.unpack_from("<I", boot, 88)[0]
    root_cluster = struct.unpack_from("<I", boot, 96)[0]
    total_sectors = struct.unpack_from("<Q", boot, 72)[0]
    bps = 1 << bps_shift if 0 < bps_shift <= 16 else 0
    spc = 1 << spc_shift if spc_shift <= 25 else 0
    if not bps or not spc:
        return None
    return FatInfo(
        "exFAT",
        bps,
        spc,
        bps * spc,
        fat_offset,
        num_fats,
        fat_length,
        root_cluster,
        heap_offset * bps,
        total_sectors,
        None,
        [],
    )


def _parse_fat_legacy(boot: bytes) -> Optional[FatInfo]:
    """Analyse un secteur de boot FAT12/16/32."""
    bps = struct.unpack_from("<H", boot, 11)[0]
    spc = boot[13]
    reserved = struct.unpack_from("<H", boot, 14)[0]
    num_fats = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    total16 = struct.unpack_from("<H", boot, 19)[0]
    fatsz16 = struct.unpack_from("<H", boot, 22)[0]
    total32 = struct.unpack_from("<I", boot, 32)[0]
    if not bps or not spc or spc & (spc - 1):
        return None
    warnings: list[str] = []
    if fatsz16:
        root_dir_sectors = (root_entries * 32 + bps - 1) // bps
        fatsz = fatsz16
        data_sector = reserved + num_fats * fatsz + root_dir_sectors
        fs_type = "FAT12_ou_FAT16"
        root_cluster = None
        label = boot[43:54].decode("ascii", errors="replace").strip()
    else:
        fatsz = struct.unpack_from("<I", boot, 36)[0]
        root_cluster = struct.unpack_from("<I", boot, 44)[0]
        data_sector = reserved + num_fats * fatsz
        fs_type = "FAT32"
        label = boot[71:82].decode("ascii", errors="replace").strip()
    if not fatsz or data_sector <= 0:
        warnings.append("Paramètres BPB incohérents.")
    return FatInfo(
        fs_type,
        bps,
        spc,
        bps * spc,
        reserved,
        num_fats,
        fatsz,
        root_cluster,
        data_sector * bps,
        total16 or total32,
        label or None,
        warnings,
    )


def parse_fat_boot_sector(f) -> Optional[FatInfo]:
    """Lit le secteur de boot et délègue à l'analyseur adapté."""
    boot = _read_at(f, 0, 512)
    if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
        return None
    if boot[3:11] == b"EXFAT   ":
        return _parse_exfat(boot)
    return _parse_fat_legacy(boot)


def analyze_filesystem(src: Path) -> Optional[FatInfo]:
    """Analyse le système de fichiers en tête d'image (lecture seule)."""
    with open(src, "rb", buffering=0) as f:
        return parse_fat_boot_sector(f)


def cross_reference_candidates_with_clusters(
    records: list[dict], info: FatInfo
) -> None:
    """Annote chaque enregistrement avec son cluster FAT estimé."""
    if not info.cluster_size_bytes:
        return
    for rec in records:
        offset = rec.get("offset_decimal")
        rec["fat_cluster"] = (
            None
            if offset is None or offset < info.data_start_offset
            else 2 + (offset - info.data_start_offset) // info.cluster_size_bytes
        )


# --------------------------------------------------------------------------- #
# Extraction d'un candidat
# --------------------------------------------------------------------------- #


def _measure_candidate(
    ctx: RunContext, io: RunIO, offset: int, ext: str
) -> Optional[tuple[int, bool, Optional[tuple]]]:
    """Retourne (longueur, tronqué, dimensions) ou None si non reconnu."""
    args = ctx.args
    if ext == "jpg":
        header_limit = args.header_scan_mib * MIB
        dims = jpeg_dimensions(
            io.fh,
            offset,
            min(ctx.image_size, offset + header_limit),
            header_limit,
        )
        j = bisect.bisect_right(ctx.jpg_offsets, offset)
        next_jpg = ctx.jpg_offsets[j] if j < len(ctx.jpg_offsets) else None
        salvage = SalvageConfig(
            enabled=not args.no_repair,
            min_size=args.salvage_min_kib * 1024,
            max_size=args.salvage_max_mib * MIB,
        )
        length, kind = jpeg_length(
            io.fh, offset, ctx.image_size, next_jpg, salvage
        )
        if length is None:
            return None
        return length, kind == "truncated", dims
    parsers = {
        "png": png_length,
        "gif": gif_length,
        "bmp": bmp_length,
        "pdf": pdf_length,
    }
    length = parsers[ext](io.fh, offset, ctx.image_size)
    return None if length is None else (length, False, None)


def _carve_to_file(io: RunIO, offset: int, length: int, out: Path) -> bool:
    """Copie `length` octets depuis la source vers `out`. Retourne False si erreur."""
    try:
        with open(out, "xb", buffering=0) as of:
            io.fh.seek(offset)
            remaining = length
            while remaining:
                block = io.fh.read(min(WRITE_CHUNK, remaining))
                if not block:
                    raise OSError("Fin de lecture inattendue sur la source")
                of.write(block)
                remaining -= len(block)
        return True
    except (OSError, FileExistsError) as e:
        log.warning("Erreur d'écriture à l'offset %#x: %s", offset, e)
        _unlink_quietly(out)
        return False


def hash_file(path: Path) -> str:
    """Calcule le SHA-256 d'un fichier."""
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            block = f.read(HASH_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _repair_fields(out: Path, dest: Path) -> dict:
    """Tente la réparation d'un JPEG invalide et retourne les champs associés."""
    repair_path = dest / "reparations" / (out.stem + "_repare.jpg")
    ok, err = try_repair(out, repair_path)
    return {
        "repair_created": ok,
        "repair_file": str(Path("reparations") / repair_path.name) if ok else None,
        "repair_error": err,
    }


def _image_fields(
    ctx: RunContext,
    out: Path,
    ext: str,
    truncated: bool,
    length: int,
    dims: Optional[tuple],
) -> dict:
    """Champs de validation, réparation et EXIF propres au format."""
    if ext not in PHOTO_FORMATS:
        fields = {
            "validation": "not_applicable",
            "width": None,
            "height": None,
            "exif_date": None,
            "error": None,
        }
        fields.update(empty_exif())
        fields["jpeg_role"] = "not_applicable"
        return fields

    fields = image_validate(out)
    if truncated and fields.get("validation") != "valid":
        fields["validation"] = "partial_repair_possible"
    if (
        ext == "jpg"
        and fields.get("validation") != "valid"
        and not ctx.args.no_repair
        and not ctx.args.analyze_only
    ):
        fields.update(_repair_fields(out, ctx.dest))
    if ext == "jpg":
        exif_meta = extract_exif_metadata(out)
        fields.update(exif_meta)
        fields["jpeg_role"] = classify_jpeg_role(length, dims, exif_meta)
    else:
        fields.update(empty_exif())
        fields["jpeg_role"] = "not_applicable"
    return fields


def _build_record(
    ctx: RunContext,
    state: RunState,
    out: Path,
    name: str,
    ext: str,
    offset: int,
    length: int,
    truncated: bool,
    dims: Optional[tuple],
) -> Optional[dict]:
    """Construit l'enregistrement ; retourne None si c'est un doublon."""
    digest = hash_file(out)
    if not ctx.args.no_dedup and digest in state.seen_hashes:
        _unlink_quietly(out)
        state.stats.duplicates += 1
        state.stats.counts[ext] -= 1
        return None
    state.seen_hashes.add(digest)
    state.stats.extracted += 1
    rec = {
        "file": name,
        "type": ext,
        "offset_hex": hex(offset),
        "offset_decimal": offset,
        "size_bytes": length,
        "sha256": digest,
        "truncated_candidate": truncated,
        "jpeg_dimensions_header": list(dims) if dims else None,
    }
    rec.update(_image_fields(ctx, out, ext, truncated, length, dims))
    return rec


def _apply_thumbnail_policy(
    ctx: RunContext, state: RunState, rec: dict, out: Path
) -> bool:
    """Exclut la vignette si demandé. Retourne True si elle est exclue."""
    if not _is_excludable_thumbnail(rec, ctx.args):
        rec["saved"] = not ctx.args.analyze_only
        rec["excluded_reason"] = None
        return False
    _exclude_thumbnail(rec, ctx.dest)
    _unlink_quietly(out)
    state.stats.extracted = max(0, state.stats.extracted - 1)
    state.seen_hashes.discard(rec["sha256"])
    return True


def _register_record(
    ctx: RunContext, io: RunIO, state: RunState, rec: dict, out: Path
) -> None:
    """Applique la politique de vignettes, enregistre les plages et le manifeste."""
    excluded = _apply_thumbnail_policy(ctx, state, rec, out)
    start = rec["offset_decimal"]
    if not excluded:
        _span_list(state, rec).append((start, start + rec["size_bytes"]))
    state.records.append(rec)
    if io.manifest is not None:
        io.manifest.write(json.dumps(rec, ensure_ascii=False) + "\n")
        io.manifest.flush()
    if ctx.args.analyze_only:
        _unlink_quietly(out)


def _process_candidate(
    ctx: RunContext, io: RunIO, state: RunState, offset: int, ext: str
) -> None:
    """Traite un candidat : mesure, carve, valide, enregistre."""
    if any(a <= offset < b for a, b in state.ranges_strong):
        return
    measured = _measure_candidate(ctx, io, offset, ext)
    if measured is None:
        state.stats.rejected += 1
        return
    length, truncated, dims = measured
    if (
        length < ctx.args.min_size
        or offset + length > ctx.image_size
    ):
        state.stats.rejected += 1
        return
    end = offset + length
    if any(offset < b and end > a for a, b in state.ranges_strong):
        return

    state.stats.counts[ext] = state.stats.counts.get(ext, 0) + 1
    if ctx.args.dry_run:
        state.stats.extracted += 1
        state.ranges_weak.append((offset, end))
        return

    name = f"recup_{ext}_{state.stats.counts[ext]:06d}_offset_{offset:012x}.{ext}"
    out = (io.temp_dir / name) if ctx.args.analyze_only and io.temp_dir else ctx.dest / name
    if not _carve_to_file(io, offset, length, out):
        return
    rec = _build_record(ctx, state, out, name, ext, offset, length, truncated, dims)
    if rec is None:
        return
    _register_record(ctx, io, state, rec, out)


def _run_extraction(
    ctx: RunContext, io: RunIO, state: RunState, candidates: list
) -> None:
    """Parcourt tous les candidats et les traite un par un."""
    total = len(candidates)
    for idx, (offset, ext) in enumerate(candidates, 1):
        if ctx.args.resume and offset in state.covered:
            continue
        if not ctx.args.quiet and (idx % 5000 == 0 or idx == total):
            sys.stdout.write(
                f"\rExtraction/validation : {idx}/{total} "
                f"({100 * idx / max(1, total):.1f}%)"
            )
            sys.stdout.flush()
        _process_candidate(ctx, io, state, offset, ext)
        if ctx.args.max_files and state.stats.extracted >= ctx.args.max_files:
            print()
            log.info("Limite --max-files=%d atteinte.", ctx.args.max_files)
            break
    print()


# --------------------------------------------------------------------------- #
# Rapports
# --------------------------------------------------------------------------- #


def _html_row(r: dict) -> str:
    """Construit une ligne HTML du rapport."""
    fn = html.escape(str(r.get("file", "")))
    validation = html.escape(str(r.get("validation", "")))
    size = f"{r.get('size_bytes', 0) / MIB:.2f} Mio"
    dims = f"{r.get('width')}×{r.get('height')}" if r.get("width") else "—"
    rep = html.escape(str(r.get("repair_file") or "—"))
    sha = html.escape(str(r.get("sha256", ""))[:12])
    role = str(r.get("jpeg_role") or "—")
    role_html = (
        f'<span style="background:#fde68a;padding:1px 6px;border-radius:3px">'
        f"{html.escape(role)}</span>"
        if role == "likely_thumbnail"
        else html.escape(role)
    )
    exif_dt = html.escape(str(r.get("exif_datetime_original") or "—"))
    serial = html.escape(str(r.get("exif_camera_serial") or "—"))
    cluster = r.get("fat_cluster")
    cluster_s = f"#{cluster}" if cluster is not None else "—"
    linked = r.get("linked_candidate_offsets_hex") or []
    linked_s = (
        html.escape(
            ", ".join(linked[:5])
            + (f" (+{len(linked) - 5})" if len(linked) > 5 else "")
        )
        if linked
        else "—"
    )
    saved_s = "oui" if r.get("saved", True) else "non (miniature exclue)"
    assoc = "oui" if r.get("has_validated_original_association") else "—"
    return (
        f"<tr><td>{fn}</td><td>{html.escape(str(r.get('type', '')))}</td>"
        f"<td>{size}</td><td>{dims}</td><td>{validation}</td><td>{role_html}</td>"
        f"<td>{exif_dt}</td><td>{serial}</td><td>{cluster_s}</td><td>{linked_s}</td>"
        f"<td>{assoc}</td><td>{saved_s}</td><td>{rep}</td><td>{sha}</td></tr>"
    )


def _sort_key(r: dict) -> tuple:
    """Trie par date EXIF connue puis par offset."""
    dt = r.get("exif_datetime_original") or ""
    return ((0, str(dt)) if dt else (1, "")), r.get("offset_decimal", 0)


def write_html_report(
    ctx: RunContext, records: list[dict], stats: RunStats, sheets: list[str]
) -> Path:
    """Écrit le rapport HTML autonome."""
    valid = sum(r.get("validation") == "valid" for r in records)
    invalid = sum(r.get("validation") == "invalid" for r in records)
    repaired = sum(bool(r.get("repair_created")) for r in records)
    sheet_html = (
        "".join(
            f'<p><a href="{html.escape(s)}">Planche-contact {html.escape(s)}</a></p>'
            for s in sheets
        )
        or "<p>Aucune planche-contact générée (Pillow absent ou option désactivée).</p>"
    )
    rows = [_html_row(r) for r in sorted(records, key=_sort_key)]
    html_path = ctx.dest / "rapport_recuperation.html"
    html_path.write_text(
        "<!doctype html><html lang='fr'><meta charset='utf-8'>"
        "<title>Rapport de récupération</title>"
        "<style>body{font:14px sans-serif;margin:24px}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:left}"
        "th{position:sticky;top:0;background:#eee}"
        "tr:nth-child(even){background:#f7f7f7}</style>"
        "<h1>Rapport de récupération</h1>"
        f"<p>Source : {html.escape(str(ctx.src))}</p>"
        f"<p>Candidats recensés : {len(records)} ; validés : {valid} ; "
        f"invalides : {invalid} ; réparations créées : {repaired} ; "
        f"doublons écartés : {stats.duplicates} ; rejetés : {stats.rejected}</p>"
        + sheet_html
        + "<table><thead><tr><th>Fichier</th><th>Type</th><th>Taille</th>"
        "<th>Dimensions</th><th>Validation</th><th>Rôle JPEG</th>"
        "<th>Date EXIF prise de vue</th><th>N° série appareil</th>"
        "<th>Cluster FAT</th><th>Candidats liés (offsets)</th>"
        "<th>Original validé associé</th><th>Sauvegardé</th>"
        "<th>Réparation</th><th>SHA-256</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        "<p style='margin-top:16px;color:#555'>Une ligne <b>likely_thumbnail</b> "
        "indique un JPEG probablement extrait comme vignette. Les offsets liés "
        "signalent les JPEG voisins à examiner ; ils ne prouvent pas qu'ils "
        "appartiennent à la même photo. L'analyse FAT est indicative et ne "
        "reconstruit pas les fichiers.</p></html>",
        encoding="utf-8",
    )
    return html_path


CSV_FIELDS = [
    "file",
    "type",
    "offset_hex",
    "offset_decimal",
    "size_bytes",
    "sha256",
    "validation",
    "width",
    "height",
    "exif_date",
    "truncated_candidate",
    "repair_created",
    "repair_file",
    "error",
    "jpeg_role",
    *EXIF_FIELDS,
    "linked_candidate_count",
    "linked_candidate_offsets_hex",
    "linked_validated_original_count",
    "linked_validated_original_offsets_hex",
    "has_validated_original_association",
    "saved",
    "excluded_reason",
    "fat_cluster",
]


def write_csv_report(dest: Path, records: list[dict]) -> Path:
    """Écrit le rapport CSV."""
    csv_path = dest / "rapport_recuperation.csv"
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as cf:
        w = csv.DictWriter(cf, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)
    return csv_path


def write_run_metadata(ctx: RunContext, mtime_ns: int) -> None:
    """Écrit les métadonnées de run pour audit et reprise."""
    meta = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "source_path": str(ctx.src),
        "source_size_bytes": ctx.image_size,
        "source_mtime_ns": mtime_ns,
        "started_at": ctx.started,
        "finished_at": time.time(),
        "formats": sorted(ctx.formats),
        "args": {
            k: (str(v) if isinstance(v, Path) else v)
            for k, v in vars(ctx.args).items()
        },
    }
    (ctx.dest / "run_metadata.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_manifest(manifest_path: Path, records: list[dict]) -> None:
    """Réécrit le manifeste complet, avec les liens calculés après le scan."""
    with open(manifest_path, "w", encoding="utf-8") as mf_out:
        for rec in records:
            mf_out.write(json.dumps(rec, ensure_ascii=False) + "\n")


def log_analyze_summary(records: list[dict], found: int, started: float) -> None:
    """Affiche le résumé du mode --analyze-only."""
    photo = [r for r in records if r.get("type") in PHOTO_FORMATS]
    jpg = [r for r in photo if r.get("type") == "jpg"]

    def count(pred, items=jpg) -> int:
        return sum(1 for r in items if pred(r))

    log.warning("=" * 68)
    log.warning("RÉSUMÉ ANALYSE — AUCUNE PHOTO SAUVEGARDÉE")
    log.warning("Signatures de fichiers photo trouvées (JPEG/PNG/GIF/BMP) : %d", found)
    log.warning(
        "Photos validées par Pillow : %d",
        sum(r.get("validation") == "valid" for r in photo),
    )
    log.warning(
        "Originaux JPEG probables détectés : %d",
        count(lambda r: r.get("jpeg_role") == "likely_original"),
    )
    log.warning(
        "Originaux JPEG probables validés : %d",
        count(
            lambda r: r.get("validation") == "valid"
            and r.get("jpeg_role") == "likely_original"
        ),
    )
    log.warning(
        "Miniatures JPEG probables détectées : %d",
        count(lambda r: r.get("jpeg_role") == "likely_thumbnail"),
    )
    log.warning(
        "JPEG au rôle incertain (conservés par prudence) : %d",
        count(lambda r: r.get("jpeg_role") == "unknown"),
    )
    log.warning(
        "Originaux JPEG probables invalides ou non validés : %d",
        count(
            lambda r: r.get("jpeg_role") == "likely_original"
            and r.get("validation") != "valid"
        ),
    )
    log.warning(
        "Miniatures associées à au moins un original JPEG probable validé : %d",
        count(
            lambda r: r.get("jpeg_role") == "likely_thumbnail"
            and bool(r.get("has_validated_original_association"))
        ),
    )
    log.warning(
        "Candidats photo non retenus au carving : %d",
        max(0, found - len(photo)),
    )
    log.warning("Les classements et associations sont heuristiques, pas des certitudes.")
    log.warning(
        "Fichiers temporaires supprimés ; aucun rapport ni photo écrit dans le dossier de sortie."
    )
    log.warning("Durée totale : %.1f s", time.time() - started)


# --------------------------------------------------------------------------- #
# Arguments et configuration
# --------------------------------------------------------------------------- #


def build_arg_parser() -> argparse.ArgumentParser:
    """Construit le parseur d'arguments de la ligne de commande."""
    p = argparse.ArgumentParser(
        description="Carving prudent depuis un .img existant (source en lecture seule)."
    )
    p.add_argument("image", type=Path, help="Fichier .img/.dd/.raw existant")
    p.add_argument("-o", "--output", type=Path, default=None)
    p.add_argument(
        "-j", "--workers", type=int, default=max(1, min(12, os.cpu_count() or 1))
    )
    p.add_argument("--chunk-mib", type=int, default=64)
    p.add_argument(
        "--min-size",
        type=int,
        default=1024,
        help="Taille minimale d'un fichier extrait (octets; défaut 1024)",
    )
    p.add_argument(
        "--max-files", type=int, default=0, help="Limite d'extractions (0=illimité)"
    )
    p.add_argument(
        "--no-repair",
        action="store_true",
        help="Ne pas tenter de réparer les JPEG invalides/tronqués",
    )
    p.add_argument(
        "--analyze-fat",
        action="store_true",
        help="Analyse préliminaire du secteur de boot FAT/exFAT (lecture seule)",
    )
    p.add_argument(
        "--no-contact-sheet",
        action="store_true",
        help="Ne pas créer de planches-contact",
    )
    p.add_argument(
        "--no-dedup",
        action="store_true",
        help="Ne pas dédupliquer par hash SHA-256",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Reprendre un run existant à partir du manifeste JSONL",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Estimation rapide des candidats, sans extraction ni validation complète",
    )
    p.add_argument(
        "--analyze-only",
        "--analyse-seule",
        dest="analyze_only",
        action="store_true",
        help="Analyse complète sans conserver les photos",
    )
    p.add_argument(
        "--exclude-thumbnails",
        "--sans-miniatures",
        dest="exclude_thumbnails",
        action="store_true",
        help="Ne pas sauvegarder les JPEG classés comme miniatures probables",
    )
    p.add_argument(
        "--formats",
        type=str,
        default="jpg,png,gif,bmp,pdf",
        help="Sous-ensemble de formats à rechercher, séparés par des virgules",
    )
    p.add_argument(
        "--header-scan-mib",
        type=int,
        default=8,
        help="Fenêtre de recherche du SOF dans l'en-tête JPEG, en Mio (défaut 8)",
    )
    p.add_argument(
        "--salvage-min-kib",
        type=int,
        default=4,
        help="Taille minimale, en Kio, d'un JPEG tronqué sauvé (défaut 4)",
    )
    p.add_argument(
        "--salvage-max-mib",
        type=int,
        default=64,
        help="Taille maximale, en Mio, d'un JPEG tronqué sauvé (défaut 64)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true", help="Journalisation détaillée (DEBUG)"
    )
    p.add_argument(
        "-q", "--quiet", action="store_true", help="Réduit la sortie au strict résumé"
    )
    return p


def _check_numeric_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Valide les arguments numériques et les combinaisons de modes."""
    if not 1 <= args.workers <= 64:
        parser.error("--workers doit être entre 1 et 64")
    if args.chunk_mib < 4:
        parser.error("--chunk-mib doit être au moins égal à 4")
    if args.min_size < 0 or args.max_files < 0:
        parser.error("--min-size et --max-files doivent être positifs")
    if args.dry_run and args.analyze_only:
        parser.error("--dry-run et --analyze-only sont deux modes différents.")
    if args.analyze_only and args.resume:
        parser.error("--resume ne s'applique pas à --analyze-only.")


def _parse_formats(raw: str, parser: argparse.ArgumentParser) -> set[str]:
    """Valide la liste des formats demandés."""
    formats = {s.strip().lower() for s in raw.split(",") if s.strip()}
    valid_formats = {ext for ext, _ in SIGNATURES}
    unknown = formats - valid_formats
    if unknown:
        parser.error(
            f"Formats inconnus : {', '.join(sorted(unknown))} "
            f"(valides : {', '.join(sorted(valid_formats))})"
        )
    if not formats:
        parser.error("--formats ne peut pas être vide")
    return formats


def _resolve_dest(
    args: argparse.Namespace, src: Path, parser: argparse.ArgumentParser
) -> Path:
    """Détermine et valide le dossier de sortie."""
    dest = (args.output or src.with_name(src.stem + "_recuperation")).expanduser().resolve()
    if src in (dest, *dest.parents):
        parser.error("Le dossier de sortie ne peut pas être l'image elle-même.")
    if dest in src.parents:
        parser.error("Le dossier de sortie ne peut pas être un dossier parent de l'image.")
    if dest.exists() and dest.is_file():
        parser.error("Le chemin de sortie existe et n'est pas un dossier.")
    needs_empty = not (args.resume or args.dry_run or args.analyze_only)
    if dest.exists() and any(dest.iterdir()) and needs_empty:
        parser.error(
            f"Le dossier de sortie {dest} existe déjà et n'est pas vide. Utilisez "
            "--resume pour reprendre, ou choisissez un autre --output."
        )
    return dest


def validate_args(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> tuple[Path, Path, set[str]]:
    """Valide les arguments et retourne (source, dossier de sortie, formats)."""
    src = args.image.expanduser().resolve()
    if not src.is_file():
        parser.error(f"Image introuvable : {src}")
    _check_numeric_args(args, parser)
    formats = _parse_formats(args.formats, parser)
    dest = _resolve_dest(args, src, parser)
    return src, dest, formats


def configure_logging(dest: Optional[Path], verbose: bool, quiet: bool) -> None:
    """Configure la journalisation console et fichier."""
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    log.setLevel(logging.DEBUG)
    log.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(console)

    if dest is not None:
        dest.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(dest / "recup_after.log", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        log.addHandler(file_handler)


def _pillow_available() -> bool:
    """Indique si Pillow est disponible."""
    return Image is not None


# --------------------------------------------------------------------------- #
# Initialisation et reprise
# --------------------------------------------------------------------------- #


def _restore_resume_state(
    args: argparse.Namespace, dest: Path, manifest_path: Path, state: RunState
) -> None:
    """Recharge l'état d'un run précédent depuis le manifeste."""
    records, covered, seen = load_existing_manifest(manifest_path)
    state.records = records
    state.covered = covered
    state.seen_hashes = seen
    for r in records:
        if _is_excludable_thumbnail(r, args):
            if r.get("saved", True) is not False:
                _unlink_quietly(dest / r["file"])
            _exclude_thumbnail(r, dest)
            continue
        start = r["offset_decimal"]
        _span_list(state, r).append((start, start + r["size_bytes"]))
    if args.exclude_thumbnails:
        state.seen_hashes = {
            r["sha256"]
            for r in records
            if r.get("saved", True) is not False and isinstance(r.get("sha256"), str)
        }
    for r in records:
        state.stats.counts[r["type"]] = state.stats.counts.get(r["type"], 0) + 1
    state.stats.extracted = sum(r.get("saved", True) is not False for r in records)
    log.info(
        "Reprise : %d fichiers déjà sauvegardés dans un run précédent, conservés tels quels.",
        state.stats.extracted,
    )


def _init_state(args: argparse.Namespace, dest: Path, manifest_path: Path) -> tuple[RunState, str]:
    """Crée l'état du run, en le restaurant si --resume est demandé."""
    state = RunState(
        stats=RunStats(),
        records=[],
        covered=set(),
        ranges_strong=[],
        ranges_weak=[],
        seen_hashes=set(),
    )
    if args.resume and not args.dry_run and not args.analyze_only:
        _restore_resume_state(args, dest, manifest_path, state)
        return state, "a"
    return state, "w"


def _maybe_analyze_fat(src: Path, args: argparse.Namespace) -> Optional[FatInfo]:
    """Lance l'analyse FAT si demandée et journalise le résultat."""
    if not args.analyze_fat:
        return None
    fat_info = analyze_filesystem(src)
    if fat_info is None:
        log.warning(
            "--analyze-fat : aucun secteur de boot FAT/exFAT valide en tête d'image "
            "(possible si l'image commence par une table MBR/GPT)."
        )
        return None
    log.info(
        "Système de fichiers détecté : %s | cluster : %d octets | zone de données : %#x",
        fat_info.fs_type,
        fat_info.cluster_size_bytes,
        fat_info.data_start_offset,
    )
    for warning in fat_info.warnings:
        log.warning("FAT : %s", warning)
    return fat_info


def _filter_candidates(
    candidates: list[tuple[int, str]], formats: set[str], analyze_only: bool
) -> list[tuple[int, str]]:
    """Filtre les candidats selon les formats demandés et le mode d'analyse."""
    candidates = [c for c in candidates if c[1] in formats]
    if analyze_only:
        candidates = [c for c in candidates if c[1] in PHOTO_FORMATS]
        log.info(
            "Mode analyse : les fichiers non-images (ex. PDF) ne seront pas extraits ni analysés."
        )
    return candidates


def _log_banner(args: argparse.Namespace, formats: set[str]) -> None:
    """Affiche l'en-tête du run."""
    log.info("=" * 68)
    log.info("CARVING PRUDENT — SOURCE EN LECTURE SEULE")
    log.info("=" * 68)
    log.info(
        "Formats recherchés : %s. Validation Pillow facultative.",
        ", ".join(sorted(formats)),
    )
    if args.analyze_only:
        log.info("Mode analyse seul : les photos ne seront pas sauvegardées.")
    else:
        log.info("Les originaux extraits sont conservés ; les réparations sont séparées.")
    log.info("Note : les fichiers fragmentés ne peuvent pas toujours être reconstruits.")


def _progress_printer(quiet: bool):
    """Retourne le callback de progression du scan."""

    def progress(done: int, total: int) -> None:
        if quiet:
            return
        pct = 100 * done / max(1, total)
        sys.stdout.write(f"\rAnalyse : {pct:5.1f}%")
        sys.stdout.flush()

    return progress


def _finish_reports(
    ctx: RunContext,
    state: RunState,
    manifest_path: Path,
    source_mtime_ns: int,
    fat_info: Optional[FatInfo],
    no_contact_sheet: bool,
) -> None:
    """Écrit tous les rapports pour un run normal."""
    if fat_info is not None:
        cross_reference_candidates_with_clusters(state.records, fat_info)
    write_manifest(manifest_path, state.records)
    csv_path = write_csv_report(ctx.dest, state.records)
    sheets = [] if no_contact_sheet else make_contact_sheet(state.records, ctx.dest)
    write_run_metadata(ctx, source_mtime_ns)
    html_path = write_html_report(ctx, state.records, state.stats, sheets)

    log.info("Terminé.")
    log.info("Dossier : %s", ctx.dest)
    log.info("Manifeste : %s", manifest_path)
    log.info("Métadonnées de run : %s", ctx.dest / "run_metadata.json")
    log.info("Rapport HTML : %s", html_path)
    log.info("Rapport CSV : %s", csv_path)
    saved_count = sum(r.get("saved", True) is not False for r in state.records)
    excluded_count = sum(
        r.get("excluded_reason") == "likely_thumbnail" for r in state.records
    )
    valid = sum(r.get("validation") == "valid" for r in state.records)
    invalid = sum(r.get("validation") == "invalid" for r in state.records)
    repaired = sum(bool(r.get("repair_created")) for r in state.records)
    log.info(
        "Fichiers réellement sauvegardés : %d | miniatures exclues : %d | "
        "formats candidats : %s",
        saved_count,
        excluded_count,
        state.stats.counts,
    )
    log.info(
        "Images validées : %d | invalides : %d | réparations créées : %d",
        valid,
        invalid,
        repaired,
    )
    log.info(
        "Doublons écartés : %d | candidats rejetés : %d",
        state.stats.duplicates,
        state.stats.rejected,
    )
    log.info("Durée totale : %.1f s", time.time() - ctx.started)
    if not _pillow_available():
        log.info(
            "Conseil : installe Pillow pour activer validation, réparation et "
            "planches-contact : python -m pip install Pillow"
        )


def main() -> int:
    """Point d'entrée du programme."""
    parser = build_arg_parser()
    args = parser.parse_args()
    src, dest, formats = validate_args(args, parser)

    configure_logging(
        None if (args.dry_run or args.analyze_only) else dest,
        args.verbose,
        args.quiet,
    )
    _log_banner(args, formats)
    if not args.dry_run and not args.analyze_only:
        dest.mkdir(parents=True, exist_ok=True)

    src_stat_before = src.stat()
    started = time.time()

    try:
        candidates, image_size = scan_signatures(
            src,
            args.workers,
            args.chunk_mib * MIB,
            progress_cb=_progress_printer(args.quiet),
        )
    except RecupError as e:
        print()
        log.error("Échec du scan : %s", e)
        return 1
    print()

    if src.stat().st_size != src_stat_before.st_size:
        raise SourceIntegrityError(
            "La taille de l'image source a changé pendant le scan "
            f"({src_stat_before.st_size} -> {src.stat().st_size} octets). "
            "Le résultat n'est pas fiable ; relancez sur une copie figée."
        )

    fat_info = _maybe_analyze_fat(src, args)
    candidates = _filter_candidates(candidates, formats, args.analyze_only)
    log.info(
        "Signatures candidates : %d (après filtre --formats%s)",
        len(candidates),
        " et formats photo" if args.analyze_only else "",
    )

    manifest_path = dest / "manifest.jsonl"
    state, manifest_mode = _init_state(args, dest, manifest_path)
    ctx = RunContext(
        args=args,
        dest=dest,
        src=src,
        image_size=image_size,
        started=started,
        jpg_offsets=[o for o, e in candidates if e == "jpg"],
        formats=formats,
    )

    with ExitStack() as stack:
        manifest = None
        if not args.dry_run and not args.analyze_only:
            manifest = stack.enter_context(
                open(manifest_path, manifest_mode, encoding="utf-8")
            )
        temp_dir = None
        if args.analyze_only:
            temp_dir = Path(tempfile.mkdtemp(prefix="recup_after_analyse_"))
            stack.callback(shutil.rmtree, temp_dir, True)
        fh = stack.enter_context(open(src, "rb", buffering=0))
        io = RunIO(fh=fh, manifest=manifest, temp_dir=temp_dir)
        _run_extraction(ctx, io, state, candidates)

    if args.dry_run:
        log.info("--dry-run : aucun fichier écrit.")
        log.info(
            "Estimation : %d fichiers extractibles, %d rejetés, par type : %s",
            state.stats.extracted,
            state.stats.rejected,
            state.stats.counts,
        )
        log.info("Durée : %.1f s", time.time() - started)
        return 0

    link_thumbnails_to_candidates(state.records)
    if args.analyze_only:
        found = sum(1 for _, ext in candidates if ext in PHOTO_FORMATS)
        log_analyze_summary(state.records, found, started)
        return 0

    _finish_reports(
        ctx,
        state,
        manifest_path,
        src_stat_before.st_mtime_ns,
        fat_info,
        args.no_contact_sheet,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(
            "\nInterrompu. Relancez avec --resume pour reprendre là où le scan s'est arrêté."
        )
        sys.exit(130)
    except RecupError as exc:
        print(f"\nERREUR : {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception:  # pylint: disable=broad-exception-caught
        # Filet de sécurité volontaire au niveau le plus haut du programme.
        print("\nERREUR INATTENDUE :", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)