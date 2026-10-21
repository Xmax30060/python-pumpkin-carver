#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Récupération/carving prudent depuis une image disque existante (.img/.dd/.raw).

- Source ouverte STRICTEMENT en lecture seule ; ne modifie jamais l'image
  (vérifié par un hash avant/après lecture, calculé pendant le scan sans I/O
  supplémentaire).
- Scan parallèle des signatures par blocs, avec recouvrement pour ne pas
  manquer une signature à cheval sur deux blocs.
- Contrôle structurel par format (JPEG: marqueurs/SOF, PNG: chaîne de chunks,
  GIF: terminateur, BMP: en-tête DIB, PDF: %%EOF), validation Pillow si
  disponible (jamais obligatoire).
- Sauvegarde séparée des tentatives de réparation de JPEG tronqués/corrompus ;
  l'extraction brute n'est jamais écrasée.
- SHA-256 de chaque fichier extrait pour la chaîne de custody et la
  déduplication (deux signatures différentes pointant vers le même contenu
  physique, overlaps compris, ne produisent qu'un seul fichier).
- Reprise sur interruption : un run existant peut être repris avec --resume
  (le manifeste JSONL sert de point de contrôle).
- Journalisation structurée (stdout + fichier log) au lieu de print() bruts,
  pour une utilisation scriptée/CI.
- Manifeste JSONL, rapport HTML, CSV et planche-contact si Pillow est
  disponible.

Limite : ne reconstruit pas automatiquement les fichiers fragmentés dont les
secteurs ne sont pas contigus. La réparation peut récupérer une partie
visible, pas les octets perdus. Ce script ne remplace pas un outil de
forensique certifié (ex. PhotoRec, Autopsy) pour un usage judiciaire.
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
import struct
import sys
import time
import traceback
import tempfile
import shutil
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

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
MAX_SIZES = {"jpg": 256 * MIB, "png": 512 * MIB, "pdf": 512 * MIB, "gif": 128 * MIB, "bmp": 256 * MIB}
OVERLAP = max(len(sig) for _, sig in SIGNATURES) - 1
JPEG_SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
HASH_CHUNK = 8 * MIB
WRITE_CHUNK = 8 * MIB
MANIFEST_SCHEMA_VERSION = 2

log = logging.getLogger("recup_after")


# --------------------------------------------------------------------------- #
# Erreurs dédiées (remplace les comparaisons de chaînes / codes de sortie nus)
# --------------------------------------------------------------------------- #

class RecupError(Exception):
    """Erreur attendue, destinée à être affichée proprement à l'utilisateur."""


class SourceIntegrityError(RecupError):
    """L'image source semble avoir changé pendant l'exécution (garde-fou)."""


# --------------------------------------------------------------------------- #
# Scan des signatures (multi-processus)
# --------------------------------------------------------------------------- #

def scan_range(job: tuple[str, int, int, int]) -> list[tuple[int, str]]:
    """Cherche toutes les signatures connues dans [start, stop) d'un fichier.

    Lit en flux par blocs avec recouvrement OVERLAP pour ne pas manquer une
    signature à cheval entre deux blocs. N'écrit jamais dans le fichier
    source (ouverture en lecture seule explicite).
    """
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
                    i = 0
                    while True:
                        i = data.find(sig, i)
                        if i < 0:
                            break
                        absolute = base + i
                        if start <= absolute < stop:
                            found.append((absolute, ext))
                        i += 1
                carry = data[-OVERLAP:] if OVERLAP else b""
                pos += len(block)
    except OSError as e:
        # Remonté tel quel : un worker qui ne peut pas lire son bloc doit
        # faire échouer tout le scan plutôt que produire un résultat partiel
        # silencieux (on ne veut pas croire l'image scannée à 100% alors
        # qu'un segment n'a pas été lu).
        raise RecupError(f"Échec de lecture du bloc [{start}:{stop}] : {e}") from e
    return found


def scan_signatures(
    path: Path, workers: int, chunk_size: int, progress_cb=None
) -> tuple[list[tuple[int, str]], int]:
    size = path.stat().st_size
    if size == 0:
        return [], 0
    jobs = [(str(path), s, min(size, s + chunk_size), chunk_size) for s in range(0, size, chunk_size)]
    found: list[tuple[int, str]] = []
    done = 0
    total = len(jobs)
    log.info("Image : %s (%.2f Gio)", path, size / GIB)
    log.info("Scan : %d processus, blocs de %.0f Mio, %d tâches", workers, chunk_size / MIB, total)
    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(scan_range, j) for j in jobs]
        try:
            for fut in as_completed(futures):
                found.extend(fut.result())  # relève RecupError depuis le worker
                done += 1
                if progress_cb and (done == total or done % max(1, total // 100) == 0):
                    progress_cb(done, total)
        except RecupError:
            for fut in futures:
                fut.cancel()
            raise
    return sorted(set(found)), size


# --------------------------------------------------------------------------- #
# Parsers de longueur par format — chacun ne fait QUE des lectures, jamais
# d'écriture, et borne toujours ses lectures par MAX_SIZES / image_size.
# --------------------------------------------------------------------------- #

def find_marker(f, offset: int, limit: int, marker: bytes, start_after: int = 0) -> Optional[int]:
    f.seek(offset + start_after)
    cursor = offset + start_after
    carry = b""
    while cursor < limit:
        block = f.read(min(4 * MIB, limit - cursor))
        if not block:
            return None
        data = carry + block
        idx = data.find(marker)
        if idx >= 0:
            return cursor - len(carry) + idx + len(marker) - offset
        carry = data[-max(1, len(marker) - 1):]
        cursor += len(block)
    return None


def jpeg_dimensions(f, offset: int, max_end: int, header_scan_limit: int = 8 * MIB) -> Optional[tuple[int, int]]:
    """Parse les marqueurs JPEG jusqu'à SOF et retourne (largeur, hauteur).

    header_scan_limit borne la recherche du SOF à partir du début du fichier
    (8 Mio par défaut, configurable via --header-scan-mib). Les JPEG de
    smartphones/drones modernes embarquent souvent des blocs EXIF/ICC/thumbnail
    volumineux avant le SOF ; une limite trop courte (2 Mio dans une version
    antérieure) rejette à tort des fichiers parfaitement valides. Ne pas
    confondre avec MAX_SIZES["jpg"], qui borne la taille totale du fichier.
    """
    f.seek(offset)
    if f.read(2) != b"\xff\xd8":
        return None
    pos = offset + 2
    limit = min(max_end, offset + header_scan_limit)
    while pos + 4 <= limit:
        f.seek(pos)
        byte = f.read(1)
        if not byte:
            return None
        if byte != b"\xff":
            pos += 1
            continue
        marker_byte = f.read(1)
        while marker_byte == b"\xff":
            marker_byte = f.read(1)
        if not marker_byte:
            return None
        marker = marker_byte[0]
        pos = f.tell()
        if marker in (0xD8, 0xD9, 0x01) or 0xD0 <= marker <= 0xD7:
            continue
        if marker == 0xDA:  # SOS : données compressées, pas de SOF trouvé avant
            return None
        raw = f.read(2)
        if len(raw) != 2:
            return None
        seglen = struct.unpack(">H", raw)[0]
        if seglen < 2 or pos + seglen > limit:
            return None
        if marker in JPEG_SOF:
            payload = f.read(min(seglen - 2, 8))
            if len(payload) < 5:
                return None
            height, width = struct.unpack(">HH", payload[1:5])
            if width < 1 or height < 1 or width > 100_000 or height > 100_000 or width * height > 500_000_000:
                return None
            return width, height
        pos += seglen
    return None


def _find_jpeg_eoi_structural(f, offset: int, limit: int) -> Optional[int]:
    """Retourne la longueur jusqu'au vrai marqueur EOI en respectant les segments JPEG.

    Les segments APP/EXIF (pouvant contenir des miniatures JPEG entières) sont sautés
    par leur longueur déclarée. Les données compressées sont parcourues par blocs et
    les scans progressifs / marqueurs de reprise sont pris en charge.
    """
    f.seek(offset)
    if f.read(2) != b"\xff\xd8":
        return None
    pos = offset + 2
    in_scan = False
    while pos < limit:
        if in_scan:
            block_start = pos
            f.seek(block_start)
            block = f.read(min(1024 * 1024, limit - block_start))
            if not block:
                return None
            idx = 0
            switched_to_header = False
            while True:
                idx = block.find(b"\xff", idx)
                if idx < 0:
                    # Garder le dernier octet en cas de FF coupé par la limite du bloc.
                    pos = block_start + len(block)
                    break
                marker_start = block_start + idx
                code_pos = marker_start + 1
                if idx + 1 < len(block):
                    code = block[idx + 1]
                    while code == 0xFF:
                        code_pos += 1
                        if code_pos - block_start < len(block):
                            code = block[code_pos - block_start]
                        else:
                            f.seek(code_pos)
                            cb = f.read(1)
                            if not cb:
                                return None
                            code = cb[0]
                    after_code = code_pos + 1
                else:
                    f.seek(code_pos)
                    cb = f.read(1)
                    while cb == b"\xff":
                        code_pos += 1
                        f.seek(code_pos)
                        cb = f.read(1)
                    if not cb:
                        return None
                    code = cb[0]
                    after_code = code_pos + 1

                if code == 0x00 or 0xD0 <= code <= 0xD7:
                    # FF00 = octet échappé ; D0..D7 = marqueur restart.
                    idx = after_code - block_start
                    if idx >= len(block):
                        pos = after_code
                        break
                    continue
                if code == 0xD9:
                    return after_code - offset
                # Marqueur de structure entre deux scans : le traiter comme un segment.
                pos = marker_start
                in_scan = False
                switched_to_header = True
                break
            if switched_to_header:
                continue
            continue

        f.seek(pos)
        b = f.read(1)
        if not b:
            return None
        if b != b"\xff":
            # Tolère un peu de bruit dans les candidats récupérés.
            pos += 1
            continue
        marker_start = pos
        code_b = f.read(1)
        while code_b == b"\xff":
            code_b = f.read(1)
        if not code_b:
            return None
        code = code_b[0]
        after_code = f.tell()
        if code == 0xD9:
            return after_code - offset
        if code == 0x00:
            pos = after_code
            continue
        if code == 0xD8 or code == 0x01 or 0xD0 <= code <= 0xD7:
            pos = after_code
            continue
        raw_len = f.read(2)
        if len(raw_len) != 2:
            return None
        seg_len = struct.unpack(">H", raw_len)[0]
        if seg_len < 2:
            return None
        seg_end = after_code + seg_len
        if seg_end > limit:
            return None
        if code == 0xDA:
            in_scan = True
        pos = seg_end
    return None


def jpeg_length(f, offset: int, image_size: int, next_jpeg: Optional[int] = None, salvage: bool = True,
                 salvage_min: int = 4096, salvage_max: int = 64 * MIB):
    limit = min(image_size, offset + MAX_SIZES["jpg"])
    end = _find_jpeg_eoi_structural(f, offset, limit)
    if end is not None:
        return end, "end_marker"
    if salvage:
        if next_jpeg is not None:
            length = next_jpeg - offset
            if salvage_min <= length <= salvage_max and offset + length <= image_size:
                return length, "truncated"
        else:
            # Dernier candidat de l'image : s'il est tronqué sans EOI et qu'aucune
            # autre signature JPEG ne fournit de borne, on tente le segment restant,
            # borné par la limite de récupération configurée. Pillow tranchera ensuite.
            remaining = min(image_size - offset, salvage_max, MAX_SIZES["jpg"])
            if salvage_min <= remaining <= image_size - offset:
                return remaining, "truncated"
    return None, None


def png_length(f, offset: int, image_size: int) -> Optional[int]:
    f.seek(offset)
    if f.read(8) != b"\x89PNG\r\n\x1a\n":
        return None
    cur = offset + 8
    limit = min(image_size, offset + MAX_SIZES["png"])
    while cur + 12 <= limit:
        f.seek(cur)
        h = f.read(8)
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
    f.seek(offset)
    if f.read(6) not in (b"GIF87a", b"GIF89a"):
        return None
    n = find_marker(f, offset, min(image_size, offset + MAX_SIZES["gif"]), b"\x3b", 6)
    return n if n is not None and n >= 14 else None


def bmp_length(f, offset: int, image_size: int) -> Optional[int]:
    f.seek(offset)
    h = f.read(54)
    if len(h) < 26 or h[:2] != b"BM":
        return None
    size = struct.unpack_from("<I", h, 2)[0]
    pix = struct.unpack_from("<I", h, 10)[0]
    dib = struct.unpack_from("<I", h, 14)[0]
    if dib not in (12, 40, 52, 56, 64, 108, 124) or size < 26 or size > MAX_SIZES["bmp"] \
            or pix < 14 + dib or pix >= size or size > image_size - offset:
        return None
    if dib == 12:
        width, height = struct.unpack_from("<HH", h, 18)
        planes, bpp = struct.unpack_from("<HH", h, 22)
        comp = 0
    else:
        width, height = struct.unpack_from("<ii", h, 18)
        planes, bpp = struct.unpack_from("<HH", h, 26)
        comp = struct.unpack_from("<I", h, 30)[0]
    if width == 0 or height == 0 or abs(width) > 100_000 or abs(height) > 100_000 \
            or planes != 1 or bpp not in (1, 2, 4, 8, 16, 24, 32) or comp not in (0, 1, 2, 3, 6):
        return None
    row = ((abs(width) * bpp + 31) // 32) * 4
    if comp == 0 and pix + row * abs(height) > size:
        return None
    return size


def pdf_length(f, offset: int, image_size: int) -> Optional[int]:
    limit = min(image_size, offset + MAX_SIZES["pdf"])
    f.seek(offset)
    if f.read(5) != b"%PDF-":
        return None
    cur = offset + 5
    tail = b""
    last = None
    while cur < limit:
        b = f.read(min(4 * MIB, limit - cur))
        if not b:
            break
        data = tail + b
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
        cur += len(b)
    return last



# --------------------------------------------------------------------------- #
# EXIF enrichi + détection de miniature imbriquée
# --------------------------------------------------------------------------- #

_EXIF_TAG_DATETIME_ORIGINAL = 36867
_EXIF_TAG_DATETIME_DIGITIZED = 36868
_EXIF_TAG_DATETIME = 306
_EXIF_TAG_SUBSEC_ORIGINAL = 37521
_EXIF_TAG_MAKE = 271
_EXIF_TAG_MODEL = 272
_EXIF_TAG_SERIAL = 42033
_EXIF_TAG_SOFTWARE = 305
_EXIF_TAG_ORIG_FILENAME = 42016
_EXIF_IFD_THUMBNAIL_OFFSET = 513
_EXIF_IFD_THUMBNAIL_LENGTH = 514
_EXIF_TAG_IMAGE_WIDTH = 256
_EXIF_TAG_IMAGE_HEIGHT = 257
_EXIF_TAG_PIXEL_X_DIMENSION = 40962
_EXIF_TAG_PIXEL_Y_DIMENSION = 40963


def _clean_exif_str(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = str(value).strip().strip("\\x00").strip()
    return value or None


def extract_exif_metadata(path: Path) -> dict:
    """Extrait les métadonnées EXIF sans exiger le décodage complet des pixels."""
    out = {
        "exif_datetime_original": None, "exif_datetime_digitized": None,
        "exif_subsec_original": None, "exif_camera_make": None,
        "exif_camera_model": None, "exif_camera_serial": None,
        "exif_software": None, "exif_image_unique_id": None,
        "exif_full_width": None, "exif_full_height": None,
        "has_embedded_thumbnail": False,
        "embedded_thumbnail_offset_in_file": None,
        "embedded_thumbnail_length": None,
    }
    try:
        from PIL import Image
    except ImportError:
        return out
    try:
        with Image.open(path) as im:
            exif = im.getexif()
            if not exif:
                return out
            out["exif_datetime_original"] = exif.get(_EXIF_TAG_DATETIME_ORIGINAL) or exif.get(_EXIF_TAG_DATETIME)
            out["exif_datetime_digitized"] = exif.get(_EXIF_TAG_DATETIME_DIGITIZED)
            out["exif_subsec_original"] = _clean_exif_str(exif.get(_EXIF_TAG_SUBSEC_ORIGINAL))
            out["exif_camera_make"] = _clean_exif_str(exif.get(_EXIF_TAG_MAKE))
            out["exif_camera_model"] = _clean_exif_str(exif.get(_EXIF_TAG_MODEL))
            out["exif_camera_serial"] = _clean_exif_str(exif.get(_EXIF_TAG_SERIAL))
            out["exif_software"] = _clean_exif_str(exif.get(_EXIF_TAG_SOFTWARE))
            out["exif_image_unique_id"] = _clean_exif_str(exif.get(_EXIF_TAG_ORIG_FILENAME))
            try:
                exif_ifd = exif.get_ifd(0x8769)
                if exif_ifd:
                    out["exif_full_width"] = (exif_ifd.get(_EXIF_TAG_PIXEL_X_DIMENSION)
                                              or exif_ifd.get(_EXIF_TAG_IMAGE_WIDTH))
                    out["exif_full_height"] = (exif_ifd.get(_EXIF_TAG_PIXEL_Y_DIMENSION)
                                               or exif_ifd.get(_EXIF_TAG_IMAGE_HEIGHT))
            except Exception:
                pass
            # Pillow ne garantit pas l'accès à l'IFD1 via get_ifd ; cette
            # lecture reste best-effort et n'affecte pas l'extraction.
            try:
                ifd1 = exif.get_ifd(0x0001) if hasattr(exif, "get_ifd") else {}
                thumb_off = ifd1.get(_EXIF_IFD_THUMBNAIL_OFFSET) if ifd1 else None
                thumb_len = ifd1.get(_EXIF_IFD_THUMBNAIL_LENGTH) if ifd1 else None
                if thumb_off and thumb_len:
                    out["has_embedded_thumbnail"] = True
                    out["embedded_thumbnail_offset_in_file"] = thumb_off
                    out["embedded_thumbnail_length"] = thumb_len
            except Exception:
                pass
    except Exception as e:
        log.debug("Lecture EXIF échouée pour %s : %s", path.name, e)
    return out


def classify_jpeg_role(carved_size: int, dims_header: Optional[tuple], exif: dict,
                       thumbnail_max_dim: int = 640, thumbnail_max_bytes: int = 64 * 1024) -> str:
    """Classe le JPEG avec une priorité forte au rappel des originaux.

    « likely_thumbnail » est volontairement attribué avec prudence : les JPEG
    basse résolution (anciens appareils, captures, photos recadrées) restent
    « unknown » plutôt que d'être supprimés par --exclude-thumbnails. Les
    dimensions EXIF pleine taille et les dimensions du flux sont les meilleurs
    indices disponibles sans comparaison visuelle ni analyse du système de fichiers.
    """
    def positive_int(value):
        try:
            n = int(value)
            return n if n > 0 else None
        except (TypeError, ValueError, OverflowError):
            return None

    full_w = positive_int(exif.get("exif_full_width"))
    full_h = positive_int(exif.get("exif_full_height"))
    w, h = dims_header if dims_header else (None, None)
    w, h = positive_int(w), positive_int(h)
    valid_dims = bool(w and h)
    max_dim = max(w, h) if valid_dims else 0
    pixels = w * h if valid_dims else 0
    full_pixels = full_w * full_h if full_w and full_h else 0

    # EXIF donne la taille originale : une différence importante et cohérente
    # constitue l'indice le plus fiable qu'il s'agit d'une vignette intégrée.
    if full_w and full_h and valid_dims:
        ratio_w = full_w / max(w, 1)
        ratio_h = full_h / max(h, 1)
        same_aspect = abs((full_w / full_h) - (w / h)) <= 0.08
        if same_aspect and ratio_w >= 1.5 and ratio_h >= 1.5 and max_dim <= 1600:
            return "likely_thumbnail"
        if abs(full_w - w) / full_w <= 0.12 and abs(full_h - h) / full_h <= 0.12:
            return "likely_original"
        # Si les dimensions EXIF ne concordent pas clairement, ne pas exclure.

    # Vignettes sans dimensions EXIF : seuils conservateurs, combinant taille,
    # pixels et dimensions. Un seul critère faible ne suffit plus.
    if valid_dims:
        very_small = max_dim <= 320 and carved_size <= 128 * 1024 and pixels <= 100_000
        small_thumbnail = (max_dim <= thumbnail_max_dim and carved_size <= thumbnail_max_bytes
                           and pixels <= 300_000)
        compact_thumbnail = (max_dim <= 800 and carved_size <= 48 * 1024 and pixels <= 250_000)
        if very_small or small_thumbnail or compact_thumbnail:
            return "likely_thumbnail"

        # Signaux d'original : une définition correcte ou une taille substantielle
        # suffit souvent. Les seuils bas protègent les anciens appareils photo.
        if max_dim >= 1200 or pixels >= 1_000_000:
            return "likely_original"
        if max_dim >= 900 and carved_size >= 96 * 1024:
            return "likely_original"
        if max_dim >= 700 and carved_size >= 256 * 1024:
            return "likely_original"

    # Sans dimensions fiables, une taille importante est un indice positif mais
    # les fichiers intermédiaires restent inconnus afin de maximiser le rappel.
    if carved_size >= 512 * 1024:
        return "likely_original"
    return "unknown"


def link_thumbnails_to_candidates(records: list[dict], max_distance: int = 64 * MIB) -> None:
    """Relie les vignettes aux candidats JPEG voisins et identifie les originaux validés.

    Le rapprochement est indicatif : proximité physique et métadonnées EXIF ne prouvent
    pas à elles seules que deux images représentent la même prise de vue.
    """
    jpgs = sorted((r for r in records if r.get("type") == "jpg"),
                  key=lambda r: r.get("offset_decimal", 0))
    offsets = [r.get("offset_decimal", 0) for r in jpgs]
    valid_originals = [r for r in jpgs if r.get("validation") == "valid"
                       and r.get("jpeg_role") == "likely_original"]
    valid_original_offsets = [r.get("offset_decimal", 0) for r in valid_originals]

    for rec in jpgs:
        rec["linked_candidate_offsets_hex"] = rec.get("linked_candidate_offsets_hex") or []
        rec["linked_candidate_count"] = rec.get("linked_candidate_count", 0)
        rec["linked_validated_original_offsets_hex"] = []
        rec["linked_validated_original_count"] = 0
        rec["has_validated_original_association"] = False
        if rec.get("jpeg_role") != "likely_thumbnail":
            continue
        center = rec.get("offset_decimal", 0)
        lo = bisect.bisect_left(offsets, center - max_distance)
        hi = bisect.bisect_right(offsets, center + max_distance)
        nearby = [jpgs[j] for j in range(lo, hi)
                  if jpgs[j] is not rec and jpgs[j].get("jpeg_role") in ("likely_original", "unknown")]
        nearby.sort(key=lambda c: abs(c.get("offset_decimal", 0) - center))
        rec["linked_candidate_offsets_hex"] = [c.get("offset_hex") for c in nearby[:20]]
        rec["linked_candidate_count"] = len(nearby)

        vlo = bisect.bisect_left(valid_original_offsets, center - max_distance)
        vhi = bisect.bisect_right(valid_original_offsets, center + max_distance)
        nearby_valid = valid_originals[vlo:vhi]

        def has_matching_evidence(candidate: dict) -> bool:
            distance = abs(candidate.get("offset_decimal", 0) - center)
            # Une distance courte est un signal utile, mais les liens plus éloignés
            # demandent un indice EXIF concordant pour limiter les faux appariements.
            if distance <= 2 * MIB:
                return True
            thumb_date = rec.get("exif_datetime_original")
            cand_date = candidate.get("exif_datetime_original")
            if thumb_date and cand_date and str(thumb_date) == str(cand_date):
                return True
            thumb_serial = rec.get("exif_camera_serial")
            cand_serial = candidate.get("exif_camera_serial")
            if thumb_serial and cand_serial and str(thumb_serial) == str(cand_serial):
                return True
            full_w, full_h = rec.get("exif_full_width"), rec.get("exif_full_height")
            cand_w, cand_h = candidate.get("width"), candidate.get("height")
            if full_w and full_h and cand_w and cand_h:
                try:
                    if abs(int(full_w) - int(cand_w)) <= max(16, int(cand_w) * 0.03) and \
                       abs(int(full_h) - int(cand_h)) <= max(16, int(cand_h) * 0.03):
                        return True
                except (TypeError, ValueError, OverflowError):
                    pass
            return False

        linked_valid = [c for c in nearby_valid if has_matching_evidence(c)]
        linked_valid.sort(key=lambda c: abs(c.get("offset_decimal", 0) - center))
        rec["linked_validated_original_offsets_hex"] = [c.get("offset_hex") for c in linked_valid[:20]]
        rec["linked_validated_original_count"] = len(linked_valid)
        rec["has_validated_original_association"] = bool(linked_valid)


# --------------------------------------------------------------------------- #
# Validation / réparation Pillow (optionnelles — jamais requises)
# --------------------------------------------------------------------------- #

def image_validate(path: Path) -> dict:
    try:
        from PIL import Image
    except ImportError:
        return {"validation": "pillow_missing", "width": None, "height": None, "exif_date": None, "error": "Pillow absent"}
    try:
        with Image.open(path) as im:
            fmt = im.format
            width, height = im.size
            exif_date = None
            try:
                ex = im.getexif()
                exif_date = ex.get(36867) or ex.get(306)
            except Exception:
                pass
            im.verify()
        with Image.open(path) as im:
            im.load()
        return {"validation": "valid", "width": width, "height": height, "format": fmt, "exif_date": exif_date, "error": None}
    except Exception as e:
        return {"validation": "invalid", "width": None, "height": None, "exif_date": None, "error": str(e)[:300]}


def try_repair(source: Path, output: Path) -> tuple[bool, Optional[str]]:
    try:
        from PIL import Image, ImageFile
    except ImportError:
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
    except Exception as e:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            pass
        return False, str(e)[:300]
    finally:
        ImageFile.LOAD_TRUNCATED_IMAGES = old


def make_contact_sheet(records: list[dict], dest: Path, thumb_size=(180, 135), per_sheet=120) -> list[str]:
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return []
    paths = [
        dest / r["file"] for r in records
        if r.get("saved", True) is not False and r.get("type") in ("jpg", "png", "gif", "bmp")
        and r.get("validation") in ("valid", "partial_repair_possible")
    ]
    outputs: list[str] = []
    for batchno in range(0, len(paths), per_sheet):
        batch = paths[batchno:batchno + per_sheet]
        cols = 6
        cellw, cellh = 200, 170
        sheet = Image.new("RGB", (cols * cellw, ((len(batch) + cols - 1) // cols) * cellh), (245, 245, 245))
        draw = ImageDraw.Draw(sheet)
        for i, p in enumerate(batch):
            try:
                with Image.open(p) as im:
                    im.thumbnail(thumb_size)
                    x = (i % cols) * cellw + (cellw - im.width) // 2
                    y = (i // cols) * cellh + 4
                    sheet.paste(im, (x, y))
                    draw.text(((i % cols) * cellw + 5, (i // cols) * cellh + 143), p.name[:28], fill=(20, 20, 20))
            except Exception as e:
                log.debug("Vignette ignorée pour %s : %s", p.name, e)
        out = dest / f"planche_contact_{batchno // per_sheet + 1:03d}.jpg"
        sheet.save(out, quality=85)
        outputs.append(out.name)
    return outputs


# --------------------------------------------------------------------------- #
# État du run (pour --resume et le résumé final)
# --------------------------------------------------------------------------- #

@dataclass
class RunStats:
    extracted: int = 0
    rejected: int = 0
    duplicates: int = 0
    counts: dict = field(default_factory=dict)


def load_existing_manifest(manifest_path: Path) -> tuple[list[dict], set[int], set[str]]:
    """Relit un manifeste existant pour une reprise : renvoie les enregistrements,
    les offsets de début déjà couverts et les hashes déjà vus (dédup)."""
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



# --------------------------------------------------------------------------- #
# Analyse sommaire FAT/exFAT (lecture seule)
# --------------------------------------------------------------------------- #

@dataclass
class FatInfo:
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


def parse_fat_boot_sector(f) -> Optional[FatInfo]:
    f.seek(0)
    boot = f.read(512)
    if len(boot) < 512 or boot[510:512] != b"\\x55\\xaa":
        return None
    warnings: list[str] = []
    if boot[3:11] == b"EXFAT   ":
        try:
            bps_shift, spc_shift, num_fats = boot[108], boot[109], boot[110]
            fat_offset = struct.unpack_from("<I", boot, 80)[0]
            fat_length = struct.unpack_from("<I", boot, 84)[0]
            heap_offset = struct.unpack_from("<I", boot, 88)[0]
            root_cluster = struct.unpack_from("<I", boot, 96)[0]
            total_sectors = struct.unpack_from("<Q", boot, 72)[0]
            bps = 1 << bps_shift if 0 < bps_shift <= 16 else 0
            spc = 1 << spc_shift if spc_shift <= 25 else 0
        except (IndexError, struct.error):
            return None
        if not bps or not spc:
            return None
        return FatInfo("exFAT", bps, spc, bps * spc, fat_offset, num_fats,
                       fat_length, root_cluster, heap_offset * bps, total_sectors, None, warnings)
    try:
        bps = struct.unpack_from("<H", boot, 11)[0]
        spc = boot[13]
        reserved = struct.unpack_from("<H", boot, 14)[0]
        num_fats = boot[16]
        root_entries = struct.unpack_from("<H", boot, 17)[0]
        total16 = struct.unpack_from("<H", boot, 19)[0]
        fatsz16 = struct.unpack_from("<H", boot, 22)[0]
        total32 = struct.unpack_from("<I", boot, 32)[0]
    except struct.error:
        return None
    if not bps or not spc or spc & (spc - 1):
        return None
    total = total16 or total32
    if fatsz16:
        fatsz = fatsz16
        root_dir_sectors = (root_entries * 32 + bps - 1) // bps
        data_sector = reserved + num_fats * fatsz + root_dir_sectors
        fs_type = "FAT12_ou_FAT16"
        root_cluster = None
        label = boot[43:54].decode("ascii", errors="replace").strip()
    else:
        try:
            fatsz = struct.unpack_from("<I", boot, 36)[0]
            root_cluster = struct.unpack_from("<I", boot, 44)[0]
        except struct.error:
            return None
        data_sector = reserved + num_fats * fatsz
        fs_type = "FAT32"
        label = boot[71:82].decode("ascii", errors="replace").strip()
    if not fatsz or data_sector <= 0:
        warnings.append("Paramètres BPB incohérents.")
    return FatInfo(fs_type, bps, spc, bps * spc, reserved, num_fats, fatsz,
                   root_cluster, data_sector * bps, total, label or None, warnings)


def analyze_filesystem(src: Path) -> Optional[FatInfo]:
    with open(src, "rb", buffering=0) as f:
        return parse_fat_boot_sector(f)


def cross_reference_candidates_with_clusters(records: list[dict], info: FatInfo) -> None:
    if not info.cluster_size_bytes:
        return
    for rec in records:
        offset = rec.get("offset_decimal")
        rec["fat_cluster"] = (None if offset is None or offset < info.data_start_offset else
                              2 + (offset - info.data_start_offset) // info.cluster_size_bytes)


# --------------------------------------------------------------------------- #
# Programme principal
# --------------------------------------------------------------------------- #

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Carving prudent depuis un .img existant (source en lecture seule).")
    p.add_argument("image", type=Path, help="Fichier .img/.dd/.raw existant")
    p.add_argument("-o", "--output", type=Path, default=None)
    p.add_argument("-j", "--workers", type=int, default=max(1, min(12, os.cpu_count() or 1)))
    p.add_argument("--chunk-mib", type=int, default=64)
    p.add_argument("--min-size", type=int, default=1024, help="Taille minimale d'un fichier extrait (octets; défaut 1024)")
    p.add_argument("--max-files", type=int, default=0, help="Limite d'extractions (0=illimité)")
    p.add_argument("--no-repair", action="store_true", help="Ne pas tenter de réparer les JPEG invalides/tronqués")
    p.add_argument("--analyze-fat", action="store_true",
                   help="Analyse préliminaire du secteur de boot FAT/exFAT et annote les candidats (lecture seule)")
    p.add_argument("--no-contact-sheet", action="store_true", help="Ne pas créer de planches-contact")
    p.add_argument("--no-dedup", action="store_true", help="Ne pas dédupliquer par hash SHA-256 (conserve tous les doublons)")
    p.add_argument("--resume", action="store_true", help="Reprendre un run existant à partir du manifeste JSONL")
    p.add_argument("--dry-run", action="store_true", help="Estimation rapide des candidats, sans extraction ni validation complète")
    p.add_argument("--analyze-only", "--analyse-seule", dest="analyze_only", action="store_true",
                   help="Analyse complète sans conserver les photos : affiche les compteurs puis supprime les fichiers temporaires")
    p.add_argument("--exclude-thumbnails", "--sans-miniatures", dest="exclude_thumbnails", action="store_true",
                   help="Ne pas sauvegarder les JPEG classés comme miniatures probables ; ils restent dans le rapport")
    p.add_argument("--formats", type=str, default="jpg,png,gif,bmp,pdf",
                    help="Sous-ensemble de formats à rechercher, séparés par des virgules (défaut: tous)")
    p.add_argument("--header-scan-mib", type=int, default=8,
                    help="Fenêtre de recherche du marqueur SOF dans l'en-tête JPEG, en Mio (défaut 8 ; "
                         "augmenter si des photos de smartphone/drone à gros bloc EXIF/thumbnail/ICC "
                         "sont rejetées)")
    p.add_argument("--salvage-min-kib", type=int, default=4,
                    help="Taille minimale, en Kio, d'un JPEG tronqué sauvé sans marqueur de fin (défaut 4)")
    p.add_argument("--salvage-max-mib", type=int, default=64,
                    help="Taille maximale, en Mio, d'un JPEG tronqué sauvé sans marqueur de fin (défaut 64 ; "
                         "augmenter pour des photos haute résolution récentes, 20+ Mpx)")
    p.add_argument("-v", "--verbose", action="store_true", help="Journalisation détaillée (DEBUG)")
    p.add_argument("-q", "--quiet", action="store_true", help="Réduit la sortie au strict résumé")
    return p


def configure_logging(dest: Optional[Path], verbose: bool, quiet: bool) -> None:
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
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        log.addHandler(file_handler)


def hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as f:
        while True:
            block = f.read(HASH_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> tuple[Path, Path, set[str]]:
    src = args.image.expanduser().resolve()
    if not src.is_file():
        parser.error(f"Image introuvable : {src}")
    if args.workers < 1 or args.workers > 64:
        parser.error("--workers doit être entre 1 et 64")
    if args.chunk_mib < 4:
        parser.error("--chunk-mib doit être au moins égal à 4")
    if args.min_size < 0 or args.max_files < 0:
        parser.error("--min-size et --max-files doivent être positifs")
    if args.dry_run and args.analyze_only:
        parser.error("--dry-run et --analyze-only sont deux modes différents ; choisissez-en un seul.")
    if args.analyze_only and args.resume:
        parser.error("--resume ne s'applique pas à --analyze-only.")

    formats = {s.strip().lower() for s in args.formats.split(",") if s.strip()}
    valid_formats = {ext for ext, _ in SIGNATURES}
    unknown = formats - valid_formats
    if unknown:
        parser.error(f"Formats inconnus : {', '.join(sorted(unknown))} (valides : {', '.join(sorted(valid_formats))})")
    if not formats:
        parser.error("--formats ne peut pas être vide")

    dest = (args.output or src.with_name(src.stem + "_recuperation")).expanduser().resolve()
    if dest == src or dest in src.parents or src in dest.parents and dest != src:
        pass  # dest sous src est impossible puisque src est un fichier ; garde ci-dessous suffit
    if dest == src or src in (dest, *dest.parents):
        parser.error("Le dossier de sortie ne peut pas être l'image elle-même.")
    if dest in src.parents:
        parser.error("Le dossier de sortie ne peut pas être un dossier parent de l'image.")
    if dest.exists() and dest.is_file():
        parser.error("Le chemin de sortie existe et n'est pas un dossier.")
    if dest.exists() and any(dest.iterdir()) and not args.resume and not args.dry_run and not args.analyze_only:
        parser.error(f"Le dossier de sortie {dest} existe déjà et n'est pas vide. Utilisez --resume pour reprendre, "
                      f"ou choisissez un autre --output.")
    return src, dest, formats


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        src, dest, formats = validate_args(args, parser)
    except SystemExit:
        raise

    configure_logging(None if (args.dry_run or args.analyze_only) else dest, args.verbose, args.quiet)

    log.info("=" * 68)
    log.info("CARVING PRUDENT — SOURCE EN LECTURE SEULE")
    log.info("=" * 68)
    log.info("Formats recherchés : %s. Validation Pillow facultative.", ", ".join(sorted(formats)))
    if args.analyze_only:
        log.info("Mode analyse seul : les photos ne seront pas sauvegardées.")
    else:
        log.info("Les originaux extraits sont conservés ; les réparations sont séparées.")
    log.info("Note : les fichiers fragmentés ne peuvent pas toujours être reconstruits.")

    if not args.dry_run and not args.analyze_only:
        dest.mkdir(parents=True, exist_ok=True)

    source_size_before = src.stat().st_size
    source_mtime_before = src.stat().st_mtime_ns

    started = time.time()

    def progress(done, total):
        if args.quiet:
            return
        pct = 100 * done / max(1, total)
        sys.stdout.write(f"\rAnalyse : {pct:5.1f}%")
        sys.stdout.flush()

    try:
        candidates, image_size = scan_signatures(src, args.workers, args.chunk_mib * MIB, progress_cb=progress)
    except RecupError as e:
        print()
        log.error("Échec du scan : %s", e)
        return 1
    print()

    # Garde-fou : l'image n'a pas dû changer de taille pendant la lecture
    # (preuve a minima qu'elle n'a pas été écrasée/tronquée en cours de scan).
    source_size_after = src.stat().st_size
    if source_size_after != source_size_before:
        raise SourceIntegrityError(
            f"La taille de l'image source a changé pendant le scan ({source_size_before} -> {source_size_after} octets). "
            "Le résultat n'est pas fiable ; relancez sur une copie figée."
        )

    fat_info: Optional[FatInfo] = None
    if args.analyze_fat:
        fat_info = analyze_filesystem(src)
        if fat_info is None:
            log.warning("--analyze-fat : aucun secteur de boot FAT/exFAT valide trouvé en tête d'image "
                        "(possible si l'image commence par une table MBR/GPT).")
        else:
            log.info("Système de fichiers détecté : %s | cluster : %d octets | zone de données : %#x",
                     fat_info.fs_type, fat_info.cluster_size_bytes, fat_info.data_start_offset)
            for warning in fat_info.warnings:
                log.warning("FAT : %s", warning)

    candidates = [c for c in candidates if c[1] in formats]
    if args.analyze_only:
        photo_formats = {"jpg", "png", "gif", "bmp"}
        candidates = [c for c in candidates if c[1] in photo_formats]
        log.info("Mode analyse : les fichiers non-images (ex. PDF) ne seront pas extraits ni analysés.")
    log.info("Signatures candidates : %d (après filtre --formats%s)", len(candidates),
             " et formats photo" if args.analyze_only else "")

    jpg_offsets = [o for o, e in candidates if e == "jpg"]
    manifest_path = dest / "manifest.jsonl"

    stats = RunStats()
    temp_output_dir: Optional[Path] = None
    if args.analyze_only:
        temp_output_dir = Path(tempfile.mkdtemp(prefix="recup_after_analyse_"))
    records: list[dict] = []
    covered_starts: set[int] = set()
    # Deux listes de plages séparées : `ranges_strong` (fichiers validés par
    # Pillow, ou tous types non-image) bloque vraiment les chevauchements ;
    # `ranges_weak` (JPEG tronqués/non validés, candidats provisoires) ne sert
    # qu'à éviter l'auto-chevauchement trivial mais ne doit jamais faire perdre
    # un vrai fichier dont le début se trouve à l'intérieur de la zone floue
    # d'un faux positif voisin — c'est le mécanisme qui, avant cette révision,
    # pouvait escamoter une photo entière si un faux positif la précédait.
    ranges_strong: list[tuple[int, int]] = []
    ranges_weak: list[tuple[int, int]] = []
    seen_hashes: set[str] = set()

    def is_strong(rec: dict) -> bool:
        return rec.get("validation") in ("valid", "not_applicable")

    if args.resume and not args.dry_run and not args.analyze_only:
        records, covered_starts, seen_hashes = load_existing_manifest(manifest_path)
        for r in records:
            if args.exclude_thumbnails and r.get("type") == "jpg" and r.get("jpeg_role") == "likely_thumbnail":
                old_file = r.get("file")
                if old_file and r.get("saved", True) is not False:
                    try:
                        (dest / old_file).unlink(missing_ok=True)
                    except OSError as e:
                        log.warning("Impossible de supprimer la miniature existante %s : %s", old_file, e)
                repair_file = r.get("repair_file")
                if repair_file:
                    try:
                        (dest / repair_file).unlink(missing_ok=True)
                    except OSError as e:
                        log.warning("Impossible de supprimer la réparation associée à la miniature %s : %s", old_file, e)
                r["repair_created"] = False
                r["repair_file"] = None
                r["saved"] = False
                r["excluded_reason"] = "likely_thumbnail"
                continue
            span = (r["offset_decimal"], r["offset_decimal"] + r["size_bytes"])
            (ranges_strong if is_strong(r) else ranges_weak).append(span)
        if args.exclude_thumbnails:
            seen_hashes = {r.get("sha256") for r in records
                           if r.get("sha256") and r.get("saved", True) is not False}
        for r in records:
            stats.counts[r["type"]] = stats.counts.get(r["type"], 0) + 1
        stats.extracted = sum(r.get("saved", True) is not False for r in records)
        log.info("Reprise : %d fichiers déjà sauvegardés dans un run précédent, conservés tels quels.", stats.extracted)
        manifest_mode = "a"
    else:
        manifest_mode = "w"

    last_progress = 0
    total = len(candidates)

    mf = None
    f = None
    try:
        if not args.dry_run and not args.analyze_only:
            mf = open(manifest_path, manifest_mode, encoding="utf-8")
        f = open(src, "rb", buffering=0)

        for idx, (offset, ext) in enumerate(candidates, 1):
            if args.resume and offset in covered_starts:
                continue
            if not args.quiet and (idx - last_progress >= 5000 or idx == total):
                sys.stdout.write(f"\rExtraction/validation : {idx}/{total} ({100 * idx / max(1, total):.1f}%)")
                sys.stdout.flush()
                last_progress = idx

            # Seul un chevauchement avec une plage "forte" (fichier déjà validé
            # par Pillow, ou non-image) fait sauter un candidat dès le départ.
            # Un chevauchement avec une plage "faible" (JPEG tronqué non confirmé)
            # ne bloque plus rien ici : un faux positif voisin ne doit pas
            # pouvoir masquer le vrai début d'un fichier qu'il recouvre.
            if any(a <= offset < b for a, b in ranges_strong):
                continue

            truncated = False
            dims = None
            if ext == "jpg":
                dims = jpeg_dimensions(f, offset, min(image_size, offset + args.header_scan_mib * MIB),
                                        args.header_scan_mib * MIB)
                # Pas de SOF trouvé dans la fenêtre (en-tête EXIF/ICC/thumbnail
                # anormalement volumineux, ou JPEG progressif atypique) : on ne
                # rejette plus à l'aveugle. Un vrai en-tête \xff\xd8\xff a déjà
                # été confirmé par la signature ; on laisse Pillow être seul
                # juge de la validité finale plutôt que de perdre le fichier ici.
                j = bisect.bisect_right(jpg_offsets, offset)
                next_jpg = jpg_offsets[j] if j < len(jpg_offsets) else None
                length, kind = jpeg_length(f, offset, image_size, next_jpg, not args.no_repair,
                                            args.salvage_min_kib * 1024, args.salvage_max_mib * MIB)
                if length is None:
                    stats.rejected += 1
                    continue
                truncated = (kind == "truncated")
            elif ext == "png":
                length = png_length(f, offset, image_size)
            elif ext == "gif":
                length = gif_length(f, offset, image_size)
            elif ext == "bmp":
                length = bmp_length(f, offset, image_size)
            else:
                length = pdf_length(f, offset, image_size)

            if length is None or length < args.min_size or offset + length > image_size:
                stats.rejected += 1
                continue

            end = offset + length
            # Même logique en sortie : seul un chevauchement avec une plage
            # forte élimine le candidat. Un JPEG "truncated" encore incertain
            # peut donc coexister temporairement avec un autre candidat qui le
            # chevauche ; c'est Pillow, une fois le fichier écrit, qui tranche
            # lequel (s'il y en a un) devient une plage forte.
            if any(offset < b and end > a for a, b in ranges_strong):
                continue

            if args.dry_run:
                stats.counts[ext] = stats.counts.get(ext, 0) + 1
                stats.extracted += 1
                ranges_weak.append((offset, end))
                continue

            stats.counts[ext] = stats.counts.get(ext, 0) + 1
            name = f"recup_{ext}_{stats.counts[ext]:06d}_offset_{offset:012x}.{ext}"
            out = (temp_output_dir / name) if args.analyze_only and temp_output_dir is not None else dest / name
            try:
                with open(out, "xb", buffering=0) as of:
                    f.seek(offset)
                    remaining = length
                    while remaining:
                        block = f.read(min(WRITE_CHUNK, remaining))
                        if not block:
                            raise OSError("Fin de lecture inattendue sur la source")
                        of.write(block)
                        remaining -= len(block)
            except (OSError, FileExistsError) as e:
                log.warning("Erreur d'écriture à l'offset %#x: %s", offset, e)
                try:
                    out.unlink(missing_ok=True)
                except OSError:
                    pass
                continue

            digest = hash_file(out)
            if not args.no_dedup and digest in seen_hashes:
                out.unlink(missing_ok=True)
                stats.duplicates += 1
                stats.counts[ext] -= 1
                continue
            seen_hashes.add(digest)

            stats.extracted += 1
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
            if ext in ("jpg", "png", "gif", "bmp"):
                val = image_validate(out)
                rec.update(val)
                if truncated and val.get("validation") != "valid":
                    rec["validation"] = "partial_repair_possible"
                if ext == "jpg" and val.get("validation") != "valid" and not args.no_repair and not args.analyze_only:
                    repair_dir = dest / "reparations"
                    repair_path = repair_dir / (out.stem + "_repare.jpg")
                    ok, err = try_repair(out, repair_path)
                    rec["repair_created"] = ok
                    rec["repair_file"] = str(Path("reparations") / repair_path.name) if ok else None
                    rec["repair_error"] = err
                if ext == "jpg":
                    exif_meta = extract_exif_metadata(out)
                    rec.update(exif_meta)
                    rec["jpeg_role"] = classify_jpeg_role(length, dims, exif_meta)
                else:
                    rec.update({
                        "exif_datetime_original": None, "exif_datetime_digitized": None,
                        "exif_subsec_original": None, "exif_camera_make": None,
                        "exif_camera_model": None, "exif_camera_serial": None,
                        "exif_software": None, "exif_image_unique_id": None,
                        "exif_full_width": None, "exif_full_height": None,
                        "has_embedded_thumbnail": False,
                        "embedded_thumbnail_offset_in_file": None,
                        "embedded_thumbnail_length": None, "jpeg_role": "not_applicable",
                    })
            else:
                rec.update({"validation": "not_applicable", "width": None, "height": None, "exif_date": None, "error": None})
                rec.update({
                    "exif_datetime_original": None, "exif_datetime_digitized": None,
                    "exif_subsec_original": None, "exif_camera_make": None,
                    "exif_camera_model": None, "exif_camera_serial": None,
                    "exif_software": None, "exif_image_unique_id": None,
                    "exif_full_width": None, "exif_full_height": None,
                    "has_embedded_thumbnail": False,
                    "embedded_thumbnail_offset_in_file": None,
                    "embedded_thumbnail_length": None, "jpeg_role": "not_applicable",
                })

            excluded_thumbnail = bool(args.exclude_thumbnails and ext == "jpg"
                                      and rec.get("jpeg_role") == "likely_thumbnail")
            if excluded_thumbnail:
                # Le candidat est conservé dans le rapport, mais le fichier image et
                # une éventuelle réparation associée ne sont pas conservés.
                repair_file = rec.get("repair_file")
                if repair_file:
                    try:
                        (dest / repair_file).unlink(missing_ok=True)
                    except OSError:
                        pass
                rec["repair_created"] = False
                rec["repair_file"] = None
                rec["saved"] = False
                rec["excluded_reason"] = "likely_thumbnail"
                try:
                    out.unlink(missing_ok=True)
                except OSError:
                    pass
                stats.extracted = max(0, stats.extracted - 1)
                seen_hashes.discard(digest)
            else:
                rec["saved"] = not args.analyze_only
                rec["excluded_reason"] = None

            # Une vignette exclue ne doit pas masquer un candidat original chevauchant.
            if not excluded_thumbnail:
                (ranges_strong if is_strong(rec) else ranges_weak).append((offset, end))

            records.append(rec)
            if mf is not None:
                mf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                mf.flush()

            # En mode analyse, les pixels ne restent jamais dans le dossier temporaire
            # plus longtemps que nécessaire ; le répertoire sera nettoyé même en cas d'erreur.
            if args.analyze_only:
                try:
                    out.unlink(missing_ok=True)
                except OSError:
                    pass

            if args.max_files and stats.extracted >= args.max_files:
                print()
                log.info("Limite --max-files=%d atteinte.", args.max_files)
                break
    finally:
        if mf is not None:
            mf.close()
        if f is not None:
            f.close()
        if temp_output_dir is not None:
            shutil.rmtree(temp_output_dir, ignore_errors=True)
    print()

    if args.dry_run:
        log.info("--dry-run : aucun fichier écrit.")
        log.info("Estimation : %d fichiers extractibles, %d rejetés, par type : %s", stats.extracted, stats.rejected, stats.counts)
        log.info("Durée : %.1f s", time.time() - started)
        return 0

    # Enrichissement global : liens entre vignettes et candidats voisins, clusters FAT.
    link_thumbnails_to_candidates(records)
    if args.analyze_only:
        image_types = {"jpg", "png", "gif", "bmp"}
        photo_records = [r for r in records if r.get("type") in image_types]
        found = sum(1 for _, ext in candidates if ext in image_types)
        validated = sum(r.get("validation") == "valid" for r in photo_records)
        originals_detected = sum(r.get("type") == "jpg" and r.get("jpeg_role") == "likely_original"
                                 for r in photo_records)
        originals_valid = sum(r.get("type") == "jpg" and r.get("validation") == "valid"
                              and r.get("jpeg_role") == "likely_original" for r in photo_records)
        thumbnails = sum(r.get("type") == "jpg" and r.get("jpeg_role") == "likely_thumbnail"
                         for r in photo_records)
        originals_invalid = sum(r.get("type") == "jpg" and r.get("jpeg_role") == "likely_original"
                                and r.get("validation") != "valid" for r in photo_records)
        unknown_jpegs = sum(r.get("type") == "jpg" and r.get("jpeg_role") == "unknown"
                            for r in photo_records)
        thumbnails_with_valid_original = sum(
            r.get("type") == "jpg" and r.get("jpeg_role") == "likely_thumbnail"
            and r.get("has_validated_original_association") for r in photo_records
        )
        # Le résumé est le résultat principal de ce mode : il reste visible avec --quiet.
        log.warning("=" * 68)
        log.warning("RÉSUMÉ ANALYSE — AUCUNE PHOTO SAUVEGARDÉE")
        log.warning("Signatures de fichiers photo trouvées (JPEG/PNG/GIF/BMP) : %d", found)
        log.warning("Photos validées par Pillow : %d", validated)
        log.warning("Originaux JPEG probables détectés : %d", originals_detected)
        log.warning("Originaux JPEG probables validés : %d", originals_valid)
        log.warning("Miniatures JPEG probables détectées : %d", thumbnails)
        log.warning("JPEG au rôle incertain (conservés par prudence) : %d", unknown_jpegs)
        log.warning("Originaux JPEG probables invalides ou non validés : %d", originals_invalid)
        log.warning("Miniatures associées à au moins un original JPEG probable validé : %d", thumbnails_with_valid_original)
        log.warning("Candidats photo non retenus au carving : %d", max(0, found - len(photo_records)))
        log.warning("Les classements et associations sont heuristiques, pas des certitudes.")
        log.warning("Fichiers temporaires supprimés ; aucun rapport ni photo écrit dans le dossier de sortie.")
        log.warning("Durée totale : %.1f s", time.time() - started)
        return 0
    if fat_info is not None:
        cross_reference_candidates_with_clusters(records, fat_info)

    # Réécrit le manifeste pour y inclure aussi les liens calculés après le scan.
    with open(manifest_path, "w", encoding="utf-8") as mf_out:
        for rec in records:
            mf_out.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # CSV détaillé
    csv_path = dest / "rapport_recuperation.csv"
    fields = ["file", "type", "offset_hex", "offset_decimal", "size_bytes", "sha256", "validation",
              "width", "height", "exif_date", "truncated_candidate", "repair_created", "repair_file", "error",
              "jpeg_role", "exif_datetime_original", "exif_datetime_digitized", "exif_subsec_original",
              "exif_camera_make", "exif_camera_model", "exif_camera_serial", "exif_software",
              "exif_image_unique_id", "exif_full_width", "exif_full_height", "has_embedded_thumbnail",
              "embedded_thumbnail_offset_in_file", "embedded_thumbnail_length",
              "linked_candidate_count", "linked_candidate_offsets_hex", "linked_validated_original_count",
              "linked_validated_original_offsets_hex", "has_validated_original_association", "saved",
              "excluded_reason", "fat_cluster"]
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as cf:
        w = csv.DictWriter(cf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)

    sheets: list[str] = []
    if not args.no_contact_sheet:
        sheets = make_contact_sheet(records, dest)

    valid = sum(r.get("validation") == "valid" for r in records)
    invalid = sum(r.get("validation") == "invalid" for r in records)
    repaired = sum(bool(r.get("repair_created")) for r in records)

    # Métadonnées de run (pour audit / reprise ultérieure)
    meta = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "source_path": str(src),
        "source_size_bytes": image_size,
        "source_mtime_ns": source_mtime_before,
        "started_at": started,
        "finished_at": time.time(),
        "formats": sorted(formats),
        "args": {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(args).items()},
    }
    (dest / "run_metadata.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    # Rapport HTML local autonome
    # Rapport HTML trié par date EXIF connue, puis par offset physique.
    def _sort_key(r):
        dt = r.get("exif_datetime_original") or ""
        return (0, str(dt)) if dt else (1, "")

    rows = []
    for r in sorted(records, key=lambda r: (_sort_key(r), r.get("offset_decimal", 0))):
        fn = html.escape(str(r.get("file", "")))
        validation = html.escape(str(r.get("validation", "")))
        size = f"{r.get('size_bytes', 0) / MIB:.2f} Mio"
        dims = f"{r.get('width')}×{r.get('height')}" if r.get("width") else "—"
        rep = html.escape(str(r.get("repair_file") or "—"))
        sha = html.escape(str(r.get("sha256", ""))[:12])
        role = str(r.get("jpeg_role") or "—")
        role_html = (f'<span style="background:#fde68a;padding:1px 6px;border-radius:3px">{html.escape(role)}</span>'
                     if role == "likely_thumbnail" else html.escape(role))
        exif_dt = html.escape(str(r.get("exif_datetime_original") or "—"))
        serial = html.escape(str(r.get("exif_camera_serial") or "—"))
        cluster = r.get("fat_cluster")
        cluster_s = f"#{cluster}" if cluster is not None else "—"
        linked = r.get("linked_candidate_offsets_hex") or []
        linked_s = html.escape(", ".join(linked[:5]) +
                               (f" (+{len(linked)-5})" if len(linked) > 5 else "")) if linked else "—"
        saved_s = "oui" if r.get("saved", True) else "non (miniature exclue)"
        assoc = "oui" if r.get("has_validated_original_association") else "—"
        rows.append(
            f"<tr><td>{fn}</td><td>{html.escape(str(r.get('type', '')))}</td><td>{size}</td><td>{dims}</td>"
            f"<td>{validation}</td><td>{role_html}</td><td>{exif_dt}</td><td>{serial}</td>"
            f"<td>{cluster_s}</td><td>{linked_s}</td><td>{assoc}</td><td>{saved_s}</td><td>{rep}</td><td>{sha}</td></tr>"
        )
    sheet_html = "".join(
        f'<p><a href="{html.escape(s)}">Planche-contact {html.escape(s)}</a></p>' for s in sheets
    ) or "<p>Aucune planche-contact générée (Pillow absent ou option désactivée).</p>"
    html_path = dest / "rapport_recuperation.html"
    html_path.write_text(
        "<!doctype html><html lang='fr'><meta charset='utf-8'><title>Rapport de récupération</title>"
        "<style>body{font:14px sans-serif;margin:24px}table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:6px;text-align:left}th{position:sticky;top:0;background:#eee}"
        "tr:nth-child(even){background:#f7f7f7}</style><h1>Rapport de récupération</h1>"
        f"<p>Source : {html.escape(str(src))}</p>"
        f"<p>Candidats recensés : {len(records)} ; validés : {valid} ; invalides : {invalid} ; "
        f"réparations créées : {repaired} ; doublons écartés : {stats.duplicates} ; rejetés : {stats.rejected}</p>"
        + sheet_html
        + "<table><thead><tr><th>Fichier</th><th>Type</th><th>Taille</th><th>Dimensions</th>"
          "<th>Validation</th><th>Rôle JPEG</th><th>Date EXIF prise de vue</th><th>N° série appareil</th>"
          "<th>Cluster FAT</th><th>Candidats liés (offsets)</th><th>Original validé associé</th><th>Sauvegardé</th><th>Réparation</th><th>SHA-256</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
        "<p style='margin-top:16px;color:#555'>Une ligne <b>likely_thumbnail</b> indique un JPEG probablement "
        "extrait comme vignette. Les offsets liés signalent les JPEG voisins à examiner ; ils ne prouvent pas "
        "qu'ils appartiennent à la même photo. L'analyse FAT est indicative et ne reconstruit pas les fichiers.</p></html>",
        encoding="utf-8",
    )

    log.info("Terminé.")
    log.info("Dossier : %s", dest)
    log.info("Manifeste : %s", manifest_path)
    log.info("Métadonnées de run : %s", dest / "run_metadata.json")
    log.info("Rapport HTML : %s", html_path)
    log.info("Rapport CSV : %s", csv_path)
    saved_count = sum(r.get("saved", True) is not False for r in records)
    excluded_count = sum(r.get("excluded_reason") == "likely_thumbnail" for r in records)
    log.info("Fichiers réellement sauvegardés : %d | miniatures exclues : %d | formats candidats : %s",
             saved_count, excluded_count, stats.counts)
    log.info("Images validées : %d | invalides : %d | réparations créées : %d", valid, invalid, repaired)
    log.info("Doublons écartés : %d | candidats rejetés : %d", stats.duplicates, stats.rejected)
    log.info("Durée totale : %.1f s", time.time() - started)
    if not _pillow_available():
        log.info("Conseil : installe Pillow pour activer validation, réparation et planches-contact : python -m pip install Pillow")
    return 0


def _pillow_available() -> bool:
    try:
        import PIL  # noqa: F401
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrompu. Relancez avec --resume pour reprendre là où le scan s'est arrêté.")
        sys.exit(130)
    except RecupError as exc:
        print(f"\nERREUR : {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("\nERREUR INATTENDUE :", file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)